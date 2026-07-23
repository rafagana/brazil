#!/usr/bin/env python3
"""
vault_router_sc.py

Production-grade Vault receiver/router behind Cloudflare Tunnel.
Receives framed eBPF packet telemetry from a local Cloudflare Tunnel listener,
reconstructs PCAP, archives raw frames, tracks global sequence continuity across
reconnects, and streams packet frames to Kafka.

Expected sensor frame format, big-endian 36-byte header:
    seq:uint64, cap_len:uint32, orig_len:uint32, direction:uint32,
    wall_ts_ns:uint64, kernel_ts_ns:uint64, payload:cap_len bytes
"""

import os
import signal
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

try:
    from confluent_kafka import Producer
except ImportError:
    Producer = None

# =============================================================================
# ENVIRONMENT CONFIGURATION
# =============================================================================
BIND_IP = os.getenv("BIND_IP", "127.0.0.1")
BIND_PORT = int(os.getenv("BIND_PORT", "9998"))

PCAP_DIR = os.getenv("PCAP_DIR", "/home/rafagana/phd/brazil/data/vault/pcap") 
FRAME_DIR = os.getenv("FRAME_DIR", "/home/rafagana/phd/brazil/data/vault/frames")
# By changing "true" to "false" in the ENABLE_FRAME_ARCHIVE os.getenv fallbacks, the script naturally skips all 
# local file operations and acts purely as a real-time socket-to-Kafka streaming gateway—leaving your disk 
# space entirely untouched.
ENABLE_FRAME_ARCHIVE = os.getenv("ENABLE_FRAME_ARCHIVE", "false").lower() == "true"
ENABLE_PCAP = os.getenv("ENABLE_PCAP", "true").lower() == "true"
ENABLE_KAFKA = os.getenv("ENABLE_KAFKA", "true").lower() == "true"

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "127.0.0.1:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "brazil-smartcity-telemetry")

SNAPLEN = int(os.getenv("SNAPLEN", "1522"))
MAX_CAP_LEN = int(os.getenv("MAX_CAP_LEN", str(SNAPLEN)))
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", str(100 * 1024 * 1024)))
SOCKET_RCVBUF = int(os.getenv("SOCKET_RCVBUF", str(16 * 1024 * 1024)))
LISTEN_BACKLOG = int(os.getenv("LISTEN_BACKLOG", "16"))
STATS_INTERVAL_SECONDS = int(os.getenv("STATS_INTERVAL_SECONDS", "10"))

FRAME_HEADER_STRUCT = struct.Struct(">QIIIQQ")
FRAME_HEADER_SIZE = FRAME_HEADER_STRUCT.size
if FRAME_HEADER_SIZE != 36:
    raise RuntimeError(f"Unexpected frame header size: {FRAME_HEADER_SIZE}")

# Little-endian libpcap global header, Ethernet DLT.
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1)

# =============================================================================
# GLOBAL STATE AND LOCKS
# =============================================================================
stop_event = threading.Event()
producer: Optional[Producer] = None

seq_lock = threading.Lock()
stats_lock = threading.Lock()
expected_seq_global = None

vault_stats = {
    "connections": 0,
    "active_connections": 0,
    "frames_received": 0,
    "payload_bytes": 0,
    "wire_bytes": 0,
    "malformed_frames": 0,
    "sequence_gaps": 0,
    "duplicates_or_reordered": 0,
    "pcap_rotations": 0,
    "frame_file_rotations": 0,
    "pcap_write_errors": 0,
    "frame_write_errors": 0,
    "kafka_enqueued": 0,
    "kafka_errors": 0,
    "kafka_delivered": 0,
}

# =============================================================================
# LOGGING AND SIGNAL HANDLING
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
# SEQUENCE, IO, AND KAFKA HELPERS
# =============================================================================
def update_sequence_state(seq: int) -> None:
    """Track sequence continuity globally across Cloudflare Tunnel reconnects."""
    global expected_seq_global

    with seq_lock:
        if expected_seq_global is None:
            expected_seq_global = seq + 1
            return

        if seq == expected_seq_global:
            expected_seq_global += 1
        elif seq > expected_seq_global:
            gap = seq - expected_seq_global
            with stats_lock:
                vault_stats["sequence_gaps"] += gap
            expected_seq_global = seq + 1
        else:
            with stats_lock:
                vault_stats["duplicates_or_reordered"] += 1


def kafka_delivery_report(err, msg) -> None:
    with stats_lock:
        if err is not None:
            vault_stats["kafka_errors"] += 1
        else:
            vault_stats["kafka_delivered"] += 1


def recv_exact(conn: socket.socket, nbytes: int) -> Optional[bytes]:
    buf = bytearray(nbytes)
    view = memoryview(buf)
    offset = 0

    while offset < nbytes and not stop_event.is_set():
        try:
            received = conn.recv_into(view[offset:], nbytes - offset)
            if received == 0:
                return None
            offset += received
        except (InterruptedError, socket.timeout):
            continue
        except OSError:
            return None

    return bytes(buf) if offset == nbytes else None


def timestamp_name(prefix: str, suffix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}_{stamp}_{time.time_ns()}{suffix}"


def open_pcap_file():
    path = os.path.join(PCAP_DIR, timestamp_name("sensor", ".pcap"))
    f = open(path, "wb")
    f.write(PCAP_GLOBAL_HEADER)
    return f, path, len(PCAP_GLOBAL_HEADER)


def open_frame_file():
    path = os.path.join(FRAME_DIR, timestamp_name("frames", ".bin"))
    f = open(path, "wb")
    return f, path, 0


# =============================================================================
# GLOBAL FILE WRITERS (Persist across socket reconnects)
# =============================================================================
pcap_lock = threading.Lock()
global_pcap_file = None
global_pcap_bytes = 0

frame_lock = threading.Lock()
global_frame_file = None
global_frame_bytes = 0

def write_pcap_globally(pkt_hdr: bytes, payload: bytes):
    global global_pcap_file, global_pcap_bytes
    with pcap_lock:
        data_len = len(pkt_hdr) + len(payload)
        if global_pcap_file is None or (global_pcap_bytes + data_len) >= MAX_FILE_SIZE_BYTES:
            if global_pcap_file:
                global_pcap_file.close()
                with stats_lock:
                    vault_stats["pcap_rotations"] += 1
            global_pcap_file, pcap_path, global_pcap_bytes = open_pcap_file()
            log(f"[PCAP] Opened {pcap_path}")
        
        global_pcap_file.write(pkt_hdr)
        global_pcap_file.write(payload)
        global_pcap_bytes += data_len

def write_frame_globally(header: bytes, payload: bytes):
    global global_frame_file, global_frame_bytes
    with frame_lock:
        data_len = len(header) + len(payload)
        if global_frame_file is None or (global_frame_bytes + data_len) >= MAX_FILE_SIZE_BYTES:
            if global_frame_file:
                global_frame_file.close()
                with stats_lock:
                    vault_stats["frame_file_rotations"] += 1
            global_frame_file, frame_path, global_frame_bytes = open_frame_file()
            log(f"[FRAME] Opened {frame_path}")
        
        global_frame_file.write(header)
        global_frame_file.write(payload)
        global_frame_bytes += data_len

# =============================================================================
# CLIENT HANDLER
# =============================================================================
def handle_client(conn: socket.socket, addr) -> None:
    log(f"[+] Tunnel client connected: {addr}")
    with stats_lock:
        vault_stats["connections"] += 1
        vault_stats["active_connections"] += 1

    conn.settimeout(1.0)

    try:
        while not stop_event.is_set():
            header = recv_exact(conn, FRAME_HEADER_SIZE)
            if not header:
                break

            try:
                seq, cap_len, orig_len, direction, wall_ts_ns, kernel_mono_ns = FRAME_HEADER_STRUCT.unpack(header)
            except struct.error:
                with stats_lock:
                    vault_stats["malformed_frames"] += 1
                break

            if cap_len == 0 or cap_len > MAX_CAP_LEN or orig_len < cap_len:
                with stats_lock:
                    vault_stats["malformed_frames"] += 1
                log(f"[WARN] Malformed frame seq={seq} cap_len={cap_len} orig_len={orig_len}")
                break

            payload = recv_exact(conn, cap_len)
            if not payload:
                break

            update_sequence_state(seq)

            with stats_lock:
                vault_stats["frames_received"] += 1
                vault_stats["payload_bytes"] += cap_len
                vault_stats["wire_bytes"] += FRAME_HEADER_SIZE + cap_len

            if ENABLE_PCAP:
                try:
                    sec = wall_ts_ns // 1_000_000_000
                    usec = (wall_ts_ns % 1_000_000_000) // 1_000
                    pkt_hdr = struct.pack("<IIII", sec, usec, cap_len, orig_len)
                    write_pcap_globally(pkt_hdr, payload)
                except OSError as exc:
                    with stats_lock:
                        vault_stats["pcap_write_errors"] += 1
                    log(f"[PCAP] Write error: {exc}")

            if ENABLE_FRAME_ARCHIVE:
                try:
                    write_frame_globally(header, payload)
                except OSError as exc:
                    with stats_lock:
                        vault_stats["frame_write_errors"] += 1
                    log(f"[FRAME] Write error: {exc}")

            if producer and ENABLE_KAFKA:
                frame_value = header + payload
                try:
                    producer.produce(
                        KAFKA_TOPIC,
                        key=str(seq).encode("ascii"),
                        value=frame_value,
                        headers=[
                            ("seq", str(seq).encode("ascii")),
                            ("direction", str(direction).encode("ascii")),
                            ("cap_len", str(cap_len).encode("ascii")),
                            ("orig_len", str(orig_len).encode("ascii")),
                        ],
                        on_delivery=kafka_delivery_report,
                    )
                    producer.poll(0)
                    with stats_lock:
                        vault_stats["kafka_enqueued"] += 1
                except BufferError:
                    producer.poll(0.1)
                    with stats_lock:
                        vault_stats["kafka_errors"] += 1
                except Exception as exc:
                    with stats_lock:
                        vault_stats["kafka_errors"] += 1
                    log(f"[KAFKA] Produce error: {exc}")

    finally:
        try:
            conn.close()
        finally:
            with stats_lock:
                vault_stats["active_connections"] -= 1
            log(f"[-] Tunnel client disconnected: {addr}")

# =============================================================================
# SERVICE THREADS AND MAIN
# =============================================================================
def stats_reporter() -> None:
    while not stop_event.is_set():
        time.sleep(STATS_INTERVAL_SECONDS)
        with stats_lock:
            snapshot = dict(vault_stats)
        log(
            "[STATS] "
            f"frames={snapshot['frames_received']} active={snapshot['active_connections']} "
            f"gaps={snapshot['sequence_gaps']} dup_reorder={snapshot['duplicates_or_reordered']} "
            f"malformed={snapshot['malformed_frames']} "
            f"pcap_rot={snapshot['pcap_rotations']} frame_rot={snapshot['frame_file_rotations']} "
            f"kafka_enq={snapshot['kafka_enqueued']} kafka_deliv={snapshot['kafka_delivered']} "
            f"kafka_err={snapshot['kafka_errors']}"
        )
 

def init_kafka() -> Optional[Producer]:
    if not ENABLE_KAFKA:
        log("[*] Kafka disabled by ENABLE_KAFKA=false")
        return None
    if Producer is None:
        log("[WARN] confluent_kafka is not installed; Kafka output disabled")
        return None

    return Producer({
        "bootstrap.servers": KAFKA_BROKER,
        "client.id": "vault-router-sc",
        "queue.buffering.max.messages": int(os.getenv("KAFKA_QUEUE_MAX_MESSAGES", "100000")),
        "queue.buffering.max.kbytes": int(os.getenv("KAFKA_QUEUE_MAX_KBYTES", "1048576")),
        "message.timeout.ms": int(os.getenv("KAFKA_MESSAGE_TIMEOUT_MS", "30000")),
        "compression.type": os.getenv("KAFKA_COMPRESSION", "lz4"),
    })


def main() -> None:
    global producer

    os.makedirs(PCAP_DIR, exist_ok=True)
    os.makedirs(FRAME_DIR, exist_ok=True)
    producer = init_kafka()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_RCVBUF)
    actual_rcvbuf = server.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    log(f"[*] SO_RCVBUF requested={SOCKET_RCVBUF}, actual={actual_rcvbuf}")

    server.bind((BIND_IP, BIND_PORT))
    server.listen(LISTEN_BACKLOG)
    server.settimeout(1.0)
    log(f"[*] Vault Router listening strictly on {BIND_IP}:{BIND_PORT}")

    threading.Thread(target=stats_reporter, daemon=True).start()

    try:
        while not stop_event.is_set():
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
    finally:
        server.close()
        if producer:
            producer.flush(5)
        log("[*] Vault Router shut down")


if __name__ == "__main__":
    main()