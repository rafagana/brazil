#!/usr/bin/env python3
"""
ebpf_streamer_sc.py

Production-grade eBPF packet streamer for Smart City / ChirpStack.
Captures ChirpStack-relevant packets with Linux TC/eBPF and streams framed
packet telemetry to a local Cloudflare Tunnel TCP forwarder, normally
127.0.0.1:9998.

Transport architecture:
    eBPF sensor -> 127.0.0.1:9998 -> cloudflared -> Cloudflare -> vault_router_sc.py

Default traffic filter:
    UDP 1700          Semtech UDP Packet Forwarder
    TCP 1883 / 8883   MQTT / MQTT over TLS
    TCP 8080          ChirpStack UI/API in common deployments
    TCP 3000          Basics Station / WebSocket style deployments

Notes:
    - Supports 802.1Q / 802.1AD single VLAN tagging.
    - Default CAPTURE_DIRECTION=ingress is intended for a passive mirror interface.
    - Run as root because TC/eBPF attachment requires elevated privileges.
"""

import ctypes
import os
import queue
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone

from bcc import BPF
from pyroute2 import IPRoute

# =============================================================================
# ENVIRONMENT CONFIGURATION
# =============================================================================
VAULT_IP = os.getenv("VAULT_IP", "127.0.0.1")
VAULT_PORT = int(os.getenv("VAULT_PORT", "9998"))
CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "eth0")
CAPTURE_DIRECTION = os.getenv("CAPTURE_DIRECTION", "ingress").lower()  # ingress, egress, both

SNAPLEN_MAX = int(os.getenv("SNAPLEN_MAX", "9000"))
INITIAL_SNAPLEN = int(os.getenv("INITIAL_SNAPLEN", "9000"))
MIN_OVERLOAD_SNAPLEN = int(os.getenv("MIN_OVERLOAD_SNAPLEN", "192"))
NORMAL_SAMPLE_RATE = int(os.getenv("NORMAL_SAMPLE_RATE", "1"))
OVERLOAD_SAMPLE_RATE = int(os.getenv("OVERLOAD_SAMPLE_RATE", "5"))
CRITICAL_SAMPLE_RATE = int(os.getenv("CRITICAL_SAMPLE_RATE", "25"))

SOCKET_SNDBUF = int(os.getenv("SOCKET_SNDBUF", str(16 * 1024 * 1024)))
BATCH_BYTES = int(os.getenv("BATCH_BYTES", "524288"))
BATCH_MAX_PACKETS = int(os.getenv("BATCH_MAX_PACKETS", "1024"))
BATCH_TIMEOUT_MS = int(os.getenv("BATCH_TIMEOUT_MS", "20"))
PERF_PAGE_CNT = int(os.getenv("PERF_PAGE_CNT", "8192"))
CHUNK_QUEUE_MAXSIZE = int(os.getenv("CHUNK_QUEUE_MAXSIZE", "100"))

QUEUE_OVERLOAD_RATIO = float(os.getenv("QUEUE_OVERLOAD_RATIO", "0.85"))
QUEUE_CRITICAL_RATIO = float(os.getenv("QUEUE_CRITICAL_RATIO", "0.95"))
STABLE_INTERVALS_TO_RESTORE = int(os.getenv("STABLE_INTERVALS_TO_RESTORE", "4"))
TELEMETRY_INTERVAL_SEC = int(os.getenv("TELEMETRY_INTERVAL_SEC", "5"))

# Big-endian frame header consumed by vault_router_sc.py.
# seq, cap_len, orig_len, direction, wall_ts_ns, kernel_ts_ns = 36 bytes.
FRAME_HEADER_STRUCT = struct.Struct(">QIIIQQ")

# eBPF metadata emitted before copied skb bytes.
# Native aligned C layout: u32, u32, u32, 4-byte padding, u64 = 24 bytes.
PKT_META_STRUCT = struct.Struct("=III4xQ")
PKT_META_SIZE = PKT_META_STRUCT.size

DIR_LABELS = {0: "ingress", 1: "egress"}

# =============================================================================
# GLOBAL STATE AND THREAD LOCKS
# =============================================================================
if os.geteuid() != 0:
    sys.exit("[-] Run as root: sudo python3 ebpf_streamer_sc.py")

if CAPTURE_DIRECTION not in {"ingress", "egress", "both"}:
    sys.exit("[-] CAPTURE_DIRECTION must be one of: ingress, egress, both")

stop_event = threading.Event()
chunk_queue = queue.Queue(maxsize=CHUNK_QUEUE_MAXSIZE)

capture_seq = 0
current_chunk = bytearray()
current_chunk_packets = 0
last_chunk_flush_ns = time.monotonic_ns()
BOOT_WALL_OFFSET_NS = time.time_ns() - time.monotonic_ns()

stats_lock = threading.Lock()
chunk_lock = threading.Lock()
bpf_lock = threading.Lock()

stats = {
    "events_enqueued": 0,
    "events_sent": 0,
    "bytes_enqueued": 0,
    "bytes_sent": 0,
    "chunk_queue_drops": 0,
    "packet_queue_drops": 0,
    "perf_lost": 0,
    "socket_reconnects": 0,
    "send_errors": 0,
    "send_dropped_packets": 0,
    "send_dropped_bytes": 0,
    "adaptive_mode_changes": 0,
}

runtime_state = {
    "snaplen": INITIAL_SNAPLEN,
    "sample_rate": NORMAL_SAMPLE_RATE,
    "mode": "normal",
    "stable_intervals": 0,
}

# =============================================================================
# SIGNAL HANDLING & LOGGING
# =============================================================================
def log(message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    print(f"[{ts}] {message}", flush=True)


def handle_signal(signum, frame):
    log(f"[*] Caught signal {signum}, initiating graceful shutdown")
    stop_event.set()


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

# =============================================================================
# EBPF C PROGRAM
# =============================================================================
ebpf_source = f"""
#include <linux/bpf.h>
#include <linux/if_vlan.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <bcc/proto.h>

#define SNAPLEN_MAX {SNAPLEN_MAX}
#define DIR_INGRESS 0
#define DIR_EGRESS 1

struct pkt_meta {{
    u32 orig_len;
    u32 cap_len;
    u32 direction;
    u64 ts_ns;
}};

BPF_PERF_OUTPUT(skb_events);
BPF_ARRAY(cfg, u32, 2);            // 0: snaplen, 1: sample_rate
BPF_PERCPU_ARRAY(pkt_counter, u64, 1);

static __always_inline u32 read_cfg_or_default(u32 index, u32 fallback) {{
    u32 *val = cfg.lookup(&index);
    if (!val) return fallback;
    return *val;
}}

static __always_inline int is_chirpstack_traffic(struct __sk_buff *skb) {{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;

    u64 offset = sizeof(*eth);
    u16 h_proto = eth->h_proto;

    // Supports one 802.1Q or 802.1AD VLAN tag.
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {{
        struct vlan_hdr *vlan = data + offset;
        if ((void *)(vlan + 1) > data_end) return 0;
        h_proto = vlan->h_vlan_encapsulated_proto;
        offset += sizeof(*vlan);
    }}

    if (h_proto != bpf_htons(ETH_P_IP)) return 0;

    struct iphdr *iph = data + offset;
    if ((void *)(iph + 1) > data_end) return 0;
    if (iph->ihl < 5) return 0;

    u32 ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end) return 0;
    offset += ip_hdr_len;

    if (iph->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcph = data + offset;
        if ((void *)(tcph + 1) > data_end) return 0;

        u16 sport = bpf_ntohs(tcph->source);
        u16 dport = bpf_ntohs(tcph->dest);

        // MQTT, MQTT-TLS, common ChirpStack UI/API, Basics Station style WebSocket.
        if (sport == 1883 || dport == 1883) return 1;
        if (sport == 8883 || dport == 8883) return 1;
        if (sport == 8080 || dport == 8080) return 1;
        if (sport == 3000 || dport == 3000) return 1;
    }} else if (iph->protocol == IPPROTO_UDP) {{
        struct udphdr *udph = data + offset;
        if ((void *)(udph + 1) > data_end) return 0;

        u16 sport = bpf_ntohs(udph->source);
        u16 dport = bpf_ntohs(udph->dest);

        // Semtech UDP Packet Forwarder.
        if (sport == 1700 || dport == 1700) return 1;
    }}

    return 0;
}}

static __always_inline int submit_packet(struct __sk_buff *skb, u32 direction) {{
    if (!is_chirpstack_traffic(skb)) return TC_ACT_OK;

    u32 sample_rate = read_cfg_or_default(1, {NORMAL_SAMPLE_RATE});
    if (sample_rate > 1) {{
        u32 zero = 0;
        u64 *cnt = pkt_counter.lookup(&zero);
        if (cnt) {{
            (*cnt)++;
            if ((*cnt % sample_rate) != 0) return TC_ACT_OK;
        }}
    }}

    u32 snaplen = read_cfg_or_default(0, {INITIAL_SNAPLEN});
    if (snaplen > SNAPLEN_MAX) snaplen = SNAPLEN_MAX;

    u32 pkt_len = skb->len;
    u32 cap_len = pkt_len;
    if (cap_len > snaplen) cap_len = snaplen;

    struct pkt_meta meta = {{}};
    meta.orig_len = pkt_len;
    meta.cap_len = cap_len;
    meta.direction = direction;
    meta.ts_ns = bpf_ktime_get_ns();

    skb_events.perf_submit_skb(skb, cap_len, &meta, sizeof(meta));
    return TC_ACT_OK;
}}

int physical_tc_ingress_tap(struct __sk_buff *skb) {{
    return submit_packet(skb, DIR_INGRESS);
}}

int physical_tc_egress_tap(struct __sk_buff *skb) {{
    return submit_packet(skb, DIR_EGRESS);
}}
"""

# =============================================================================
# CHUNKING AND PERF CALLBACKS
# =============================================================================
def flush_current_chunk_locked() -> None:
    """Flush current_chunk. Caller must hold chunk_lock."""
    global current_chunk, current_chunk_packets, last_chunk_flush_ns

    if current_chunk_packets == 0:
        return

    packet_count = current_chunk_packets
    byte_count = len(current_chunk)

    try:
        chunk_queue.put_nowait((bytes(current_chunk), packet_count, byte_count))
        with stats_lock:
            stats["events_enqueued"] += packet_count
            stats["bytes_enqueued"] += byte_count
    except queue.Full:
        with stats_lock:
            stats["chunk_queue_drops"] += 1
            stats["packet_queue_drops"] += packet_count

    current_chunk = bytearray()
    current_chunk_packets = 0
    last_chunk_flush_ns = time.monotonic_ns()


def maybe_timeout_flush() -> None:
    with chunk_lock:
        if current_chunk_packets == 0:
            return
        elapsed_ms = (time.monotonic_ns() - last_chunk_flush_ns) / 1_000_000
        if elapsed_ms >= BATCH_TIMEOUT_MS:
            flush_current_chunk_locked()


def on_packet(cpu, data, size) -> None:
    global capture_seq, current_chunk, current_chunk_packets

    if size < PKT_META_SIZE:
        return

    raw = ctypes.string_at(data, size)
    orig_len, cap_len, direction, kernel_ts_ns = PKT_META_STRUCT.unpack_from(raw, 0)

    if cap_len <= 0 or cap_len > SNAPLEN_MAX or size < PKT_META_SIZE + cap_len:
        return

    payload = raw[PKT_META_SIZE:PKT_META_SIZE + cap_len]
    wall_ts_ns = BOOT_WALL_OFFSET_NS + kernel_ts_ns

    with chunk_lock:
        capture_seq += 1
        frame_header = FRAME_HEADER_STRUCT.pack(
            capture_seq,
            cap_len,
            orig_len,
            direction,
            wall_ts_ns,
            kernel_ts_ns,
        )
        current_chunk.extend(frame_header)
        current_chunk.extend(payload)
        current_chunk_packets += 1

        if len(current_chunk) >= BATCH_BYTES or current_chunk_packets >= BATCH_MAX_PACKETS:
            flush_current_chunk_locked()


def on_lost(*args) -> None:
    """Flexible BCC lost callback for either (count) or (cpu, count)."""
    if len(args) == 1:
        lost_cnt = int(args[0])
    elif len(args) >= 2:
        lost_cnt = int(args[1])
    else:
        lost_cnt = 0

    with stats_lock:
        stats["perf_lost"] += lost_cnt

# =============================================================================
# THREAD WORKERS
# =============================================================================
def connect_to_vault() -> socket.socket:
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_SNDBUF)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((VAULT_IP, VAULT_PORT))
            with stats_lock:
                stats["socket_reconnects"] += 1
            log(f"[TCP] Connected to local tunnel at {VAULT_IP}:{VAULT_PORT}")
            return s
        except Exception as exc:
            log(f"[TCP] Connect failed: {exc}; retrying in 2 seconds")
            time.sleep(2)

    raise RuntimeError("Stopped")


def network_sender() -> None:
    client_socket = None

    while not stop_event.is_set():
        if client_socket is None:
            try:
                client_socket = connect_to_vault()
            except RuntimeError:
                break

        try:
            chunk, pkt_cnt, byte_cnt = chunk_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        try:
            client_socket.sendall(chunk)
            with stats_lock:
                stats["events_sent"] += pkt_cnt
                stats["bytes_sent"] += byte_cnt
        except Exception as exc:
            with stats_lock:
                stats["send_errors"] += 1
                stats["send_dropped_packets"] += pkt_cnt
                stats["send_dropped_bytes"] += byte_cnt
            log(f"[TCP] Send failed: {exc}; dropped dequeued chunk and reconnecting")
            if client_socket:
                try:
                    client_socket.close()
                except OSError:
                    pass
            client_socket = None


def monitor_stats(bpf: BPF) -> None:
    """Unified telemetry reporter and adaptive controller from pi_v5."""
    prev_enq = 0
    prev_sent = 0
    prev_bytes = 0
    prev_pktdrops = 0
    prev_perflost = 0
    prev_time = time.monotonic()

    while not stop_event.is_set():
        time.sleep(TELEMETRY_INTERVAL_SEC)

        now = time.monotonic()
        dt = max(now - prev_time, 0.001)
        prev_time = now

        with stats_lock:
            cur_stats = dict(stats)

        with bpf_lock:
            mode = runtime_state["mode"]
            snaplen = runtime_state["snaplen"]
            sample_rate = runtime_state["sample_rate"]

        # Interval Deltas
        enq_delta = cur_stats["events_enqueued"] - prev_enq
        sent_delta = cur_stats["events_sent"] - prev_sent
        bytes_delta = cur_stats["bytes_sent"] - prev_bytes
        pktdrops_delta = cur_stats["packet_queue_drops"] - prev_pktdrops
        perflost_delta = cur_stats["perf_lost"] - prev_perflost

        # Per-second Rates
        enq_rate = enq_delta / dt
        sent_rate = sent_delta / dt
        mbps_sent = (bytes_delta * 8) / dt / 1_000_000

        # Baselines
        prev_enq = cur_stats["events_enqueued"]
        prev_sent = cur_stats["events_sent"]
        prev_bytes = cur_stats["bytes_sent"]
        prev_pktdrops = cur_stats["packet_queue_drops"]
        prev_perflost = cur_stats["perf_lost"]

        qsize = chunk_queue.qsize()
        qratio = qsize / CHUNK_QUEUE_MAXSIZE

        # Standardized Telemetry Line
        log(
            "[TELEMETRY] "
            f"Mode: {mode} | "
            f"Snaplen: {snaplen} | "
            f"Sample: 1:{sample_rate} | "
            f"ChunksQ: {qsize}/{CHUNK_QUEUE_MAXSIZE} | "
            f"Enq: {cur_stats['events_enqueued']} | "
            f"Sent: {cur_stats['events_sent']} | "
            f"Enq/s: {enq_rate:.0f} | "
            f"Sent/s: {sent_rate:.0f} | "
            f"Mb/s: {mbps_sent:.1f} | "
            f"PktDrops: {cur_stats['packet_queue_drops']} (+{pktdrops_delta}) | "
            f"PerfLost: {cur_stats['perf_lost']} (+{perflost_delta}) | "
            f"Reconnects: {cur_stats['socket_reconnects']} | "
            f"SendErr: {cur_stats['send_errors']} | "
            f"ModeChanges: {cur_stats['adaptive_mode_changes']}"
        )

        # Adaptive Runtime Control Logic
        mode_before = mode
        if qratio >= QUEUE_CRITICAL_RATIO or perflost_delta > 100_000:
            new_mode = "critical"
            new_snap = MIN_OVERLOAD_SNAPLEN
            new_sample = CRITICAL_SAMPLE_RATE
            stable = 0
        elif qratio >= QUEUE_OVERLOAD_RATIO or perflost_delta > 0:
            new_mode = "overload"
            new_snap = MIN_OVERLOAD_SNAPLEN
            new_sample = OVERLOAD_SAMPLE_RATE
            stable = 0
        else:
            stable = runtime_state["stable_intervals"] + 1
            if stable >= STABLE_INTERVALS_TO_RESTORE:
                new_mode = "normal"
                new_snap = INITIAL_SNAPLEN
                new_sample = NORMAL_SAMPLE_RATE
            else:
                new_mode, new_snap, new_sample = mode, snaplen, sample_rate

        with bpf_lock:
            runtime_state["mode"] = new_mode
            runtime_state["snaplen"] = new_snap
            runtime_state["sample_rate"] = new_sample
            runtime_state["stable_intervals"] = stable

            bpf["cfg"][ctypes.c_uint32(0)] = ctypes.c_uint32(new_snap)
            bpf["cfg"][ctypes.c_uint32(1)] = ctypes.c_uint32(new_sample)

        if mode_before != new_mode:
            with stats_lock:
                stats["adaptive_mode_changes"] += 1
            log(f"[ADAPT] mode={new_mode} snaplen={new_snap} sample_rate=1:{new_sample}")

# =============================================================================
# TC ATTACHMENT AND MAIN
# =============================================================================
def main() -> None:
    log(f"[*] Starting eBPF streamer on {CAPTURE_INTERFACE} -> {VAULT_IP}:{VAULT_PORT}")
    log(f"[*] Capture direction: {CAPTURE_DIRECTION}")

    bpf = BPF(text=ebpf_source)
    ipr = IPRoute()
    ifindexes = ipr.link_lookup(ifname=CAPTURE_INTERFACE)
    if not ifindexes:
        sys.exit(f"[-] Interface not found: {CAPTURE_INTERFACE}")
    ifindex = ifindexes[0]

    try:
        try:
            ipr.tc("del", "clsact", ifindex)
        except Exception:
            pass
        ipr.tc("add", "clsact", ifindex)

        if CAPTURE_DIRECTION in {"ingress", "both"}:
            fn_in = bpf.load_func("physical_tc_ingress_tap", BPF.SCHED_CLS)
            ipr.tc(
                "add-filter", "bpf", ifindex, ":1",
                fd=fn_in.fd, name=fn_in.name,
                parent="ffff:fff2", classid=1, direct_action=True,
            )
            log("[*] Attached ingress TC/eBPF filter")

        if CAPTURE_DIRECTION in {"egress", "both"}:
            fn_eg = bpf.load_func("physical_tc_egress_tap", BPF.SCHED_CLS)
            ipr.tc(
                "add-filter", "bpf", ifindex, ":2",
                fd=fn_eg.fd, name=fn_eg.name,
                parent="ffff:fff3", classid=1, direct_action=True,
            )
            log("[*] Attached egress TC/eBPF filter")

        bpf["cfg"][ctypes.c_uint32(0)] = ctypes.c_uint32(INITIAL_SNAPLEN)
        bpf["cfg"][ctypes.c_uint32(1)] = ctypes.c_uint32(NORMAL_SAMPLE_RATE)
        bpf["skb_events"].open_perf_buffer(on_packet, lost_cb=on_lost, page_cnt=PERF_PAGE_CNT)

        threading.Thread(target=network_sender, daemon=True).start()
        threading.Thread(target=monitor_stats, args=(bpf,), daemon=True).start()

        while not stop_event.is_set():
            bpf.perf_buffer_poll(timeout=10)
            maybe_timeout_flush()

        with chunk_lock:
            flush_current_chunk_locked()

    finally:
        try:
            ipr.tc("del", "clsact", ifindex)
        except Exception:
            pass
        ipr.close()
        log("[*] Cleaned up TC hooks. Exiting.")


if __name__ == "__main__":
    main()