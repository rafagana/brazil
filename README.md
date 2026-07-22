# Arcis Smart City eBPF-to-Vault over Cloudflare Tunnel

Files:

- `ebpf_streamer_sc.py`: sensor-side TC/eBPF streamer. Connects to local Cloudflare Tunnel TCP forwarder at `127.0.0.1:9999` by default.
- `vault_router_sc.py`: Vault receiver. Binds to `127.0.0.1:9999`, reconstructs PCAP, archives binary frames, and streams to Kafka.
- `docker-compose.kafka.yml`: single-node Kafka KRaft stack plus Kafka UI for pilot use.
- `Dockerfile.kafka`: optional helper image reference.

## Kafka quick start

```bash
docker compose -f docker-compose.kafka.yml up -d
```

Kafka bootstrap server from the Vault host:

```text
127.0.0.1:9092
```

Kafka UI:

```text
http://127.0.0.1:8088
```

Create the expected topic manually if you disable auto-create topics:

```bash
docker exec -it arcis-kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server 127.0.0.1:9092 \
  --create \
  --if-not-exists \
  --topic iot-raw-telemetry \
  --partitions 3 \
  --replication-factor 1
```

## Vault quick start

```bash
pip install confluent-kafka
sudo mkdir -p /data/vault/pcap /data/vault/frames
python3 vault_router_sc.py
```

## Sensor quick start

```bash
sudo apt-get install -y python3-bpfcc python3-pyroute2
sudo CAPTURE_INTERFACE=ens192 CAPTURE_DIRECTION=ingress python3 ebpf_streamer_sc.py
```

## Cloudflare Tunnel topology

Typical runtime path:

```text
ebpf_streamer_sc.py -> 127.0.0.1:9999 -> cloudflared -> Cloudflare -> cloudflared -> vault_router_sc.py
```
