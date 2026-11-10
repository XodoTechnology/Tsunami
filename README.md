# Tsunami

High-performance BitTorrent tracker — UDP-first (BEP 15), with an HTTP
tracker plane (BEP 3/12) and a JSON stats API for website integration.

Designed for very large swarms (50M+ concurrent peers). Peer storage is a
dense `Vec` + hash index (~45 bytes/peer measured), sharded by info hash,
with io_uring multishot UDP I/O and `SO_REUSEPORT` workers.

## Features

- **UDP tracker** (BEP 15): connect / announce / scrape, IPv4 + IPv6.
  Two RX backends (`network.rx_backend`):
  - `io_uring` (default) — provided-buffer-ring `recvmsg` multishot + pooled `sendmsg`.
  - `af_packet` — `PACKET_RX_RING` tap with kernel hash-fanout; parses
    L2/L3/L4 in userspace and replies over UDP sockets. Trades ~1.5× CPU
    for much lower burst loss (the kernel ring absorbs floods that overflow
    UDP socket buffers). Needs `CAP_NET_RAW`; interface auto-detected from
    the default route, override with `TSUNAMI_PACKET_IFACE`.
- **HTTP tracker** (BEP 3 announce, BEP 12 scrape), `compact=1` and
  `compact=0` (peer_id echo when enabled).
- **WebSocket tracker** (`ws://host:port/announce`, `/scrape`, `/connect`)
  — BEP-15 binary messages inside WebSocket binary frames, for WebTorrent
  and browser-based peers.
- **Unified store**: UDP, HTTP, and WebSocket peers share one swarm store,
  so stats are consistent across protocols.
- **Peer-state snapshot/restore**: periodic + on-shutdown dump of the full
  swarm to disk; restored on startup so restarts don't cause a re-announce
  storm. See `[snapshot]`.
- **Rate limiting / DoS shedding**: per-worker token buckets shed announce
  and scrape load under flood while keeps the cheap connect/parse path
  open. See `[ratelimit]`.
- **Full scrape**: `GET /scrape` with no `info_hash` returns stats for every
  tracked torrent (BEP-12 format, same as opentracker's fullscrape). Enable
  with `http.full_scrape`. HTTP only — UDP scrape is per-hash-list by design.
- **Stats API** (JSON):
  - `GET /api/stats` — totals, per-protocol counters, rates, top clients
  - `GET /api/torrents?limit=&offset=` — torrent list sorted by swarm size
  - `GET /api/torrent/{info_hash_hex}?limit=` — per-torrent detail + peers
  - `GET /api/clients?n=` — top clients by announce count (BEP 20 names)
- **Prometheus metrics**: `GET /metrics` — counters, gauges, and rates in
  Prometheus text format (Grafana/alerting ready).
- **Scrape export**: periodic `infohash seeders leechers` file (for mirrors).
- **Access list**: allow/deny info hashes, reload on SIGHUP.
- **Anti-amplification**: stateless HMAC connection IDs (BEP 15 style).
- mimalloc allocator, lock-light sharded design.

## Build

```sh
cargo build --release
# binaries: target/release/tsunami, target/release/tsunami-loadgen
```

## Run

```sh
./target/release/tsunami -c tsunami.toml
```

See `tsunami.toml.example` for all options. Key knobs for large deployments:

- `network.socket_workers` — one io_uring + socket pair per worker; default = CPUs.
- `network.ring_size` — io_uring entries **and** provided RX buffers per worker.
  Each buffer is 2 KiB; 4096 → 8 MiB RX + ~17 MiB TX pool per worker.
- `network.swarm_shards` — power of two; more shards = less lock contention.
- `protocol.store_peer_id` — costs ~30–50 B/peer extra; only enable if you
  need `compact=0` peer_id echo or per-peer client detail.
- `protocol.client_stats` — per-client announce counters (cheap, striped).

### 50M-peer sizing (rough)

- Peer storage: ~45 B/peer (v4) → ~2.3 GiB; ~80 B/peer with `store_peer_id`.
- I/O buffers: `ring_size × workers × ~25 KiB` — e.g. 8 workers × 4096 ≈ 800 MiB.
- Announce rate needed at 30-min intervals: ~28K/s average — far below the
  ~500K+/s sustained UDP throughput measured on an 8-core box.
- Recommend: `socket_workers = #cores`, `ring_size = 4096–8192`,
  `socket_recv_buffer = 16–64 MiB`, `swarm_shards = 256+`,
  `store_peer_id = false` unless required.

## Load generator

```sh
./target/release/tsunami-loadgen --target 127.0.0.1:6881 \
    --peers 100000 --seconds 60 --numwant 50 --threads 16 --rate 500000
```

`--rate 0` = unlimited flood; `--seeders 0.3` = 30% seeders.
Sockets spread across `127/8` loopback aliases for many distinct peers.

## Endpoints

| Path | Protocol | Notes |
|------|----------|-------|
| `udp://host:port` | BEP 15 | announce/scrape/connect |
| `/announce` | BEP 3 | GET, bencoded dict |
| `/scrape` | BEP 12 | GET, repeated `info_hash` params; no params = full scrape (if enabled) |
| `/api/stats` | JSON | website stats snapshot |
| `/api/torrents` | JSON | `?limit=100&offset=0` |
| `/api/torrent/{hex}` | JSON | `?limit=200` peers |
| `/api/clients` | JSON | `?n=50` top clients |
| `/metrics` | Prometheus | text exposition format |
| `ws://host:port/announce` | WebSocket | BEP-15 in WS binary frames |
| `ws://host:port/scrape` | WebSocket | same |
| `ws://host:port/connect` | WebSocket | same |

## Verifying

```sh
cargo test
cargo build --release
```
