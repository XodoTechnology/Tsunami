# Tsunami

![Tsunami](logo.svg)

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
- **Raw BEP-15 over HTTP** (`POST /bep15`, alias `/udp`) — send the exact
  binary request a UDP client would send in the POST body and get the same
  binary BEP-15 reply back (`application/octet-stream`). Supports connect /
  announce / scrape, validates connection ids against your source IP, and
  returns `204 No Content` for protocol-level drops (same as a UDP client
  seeing no reply). Lets UDP-protocol tooling run over HTTP(S) or through
  proxies that can't do UDP.
- **Real client IP behind a proxy** (`http.proxy_ip_header`) — when
  Tsunami sits behind a reverse proxy / load balancer you control, set this
  to e.g. `"X-Forwarded-For"` and peers register their true IP instead of
  the proxy's, for `/announce`, `/scrape`, `/bep15` and WebSocket.
- **Client-supplied announce IP** (`protocol.allow_client_ip`) — privacy
  feature: honor the BEP-15 `ip` field / BEP-3 `ip=` param as the peer's
  swarm address so clients can announce a relay/non-source IP. The real
  connection IP still drives conn-id validation, rate limits and access
  checks, so stats stay honest. Off by default (swarm-poisoning risk).
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
- **HTML dashboard** at `/` and `/dashboard` — self-contained stats page
  (no CDN) covering every stats endpoint: live cards, full per-protocol
  counter matrix, SVG time-series graphs (requests/s, peers, bandwidth,
  per-protocol bandwidth, churn, memory, CPU), system gauges, top
  torrents (click for peer list), top clients, and raw JSON/Prometheus
  viewers. Every card, panel and chart can be toggled via the Customize
  drawer (persisted in `localStorage`). Enable with `http.dashboard`
  (default on).
- **Stats API** (JSON):
  - `GET /api/stats` — totals, per-protocol counters + rates, system gauges
    (RSS/CPU/swarm-bytes), announce-event breakdown, top clients
  - `GET /api/timeseries?seconds=` — per-second samples for graphing
  - `GET /api/torrents?limit=&offset=` — torrent list sorted by swarm size
  - `GET /api/torrent/{info_hash_hex}?limit=` — per-torrent detail + peers
    (ip, port, seeder flag, peer_id when `protocol.store_peer_id`).
    Peer IPs are masked by default (`http.mask_peer_ips`): IPv4 shows
    `a.xxx.xxx.d`, IPv6 `s0:s1:xxxx:xxxx::s7`; tracker protocol responses always
    carry full IPs since peers need them to connect.
  - `GET /api/clients?n=` — top clients by announce count (BEP 20 names)
- **Prometheus metrics**: `GET /metrics` — counters, gauges, and per-protocol
  rates in Prometheus text format (Grafana/alerting ready).
- **Admin-route protection**: `/api/*`, `/metrics`, `/dashboard`, `/` can be
  gated with HTTP Basic auth (`http.admin_user`/`admin_password`) and/or a
  source-IP allowlist (`http.admin_allowlist`). Public tracker endpoints are
  never gated. Off by default.
- **Scrape export**: periodic `infohash seeders leechers` file (for mirrors).
- **Access list**: allow/deny info hashes, reload on SIGHUP.
- **Anti-amplification**: stateless HMAC connection IDs (BEP 15 style).
- mimalloc allocator, lock-light sharded design.

## Build

```sh
cargo build --release
# binaries: target/release/tsunami, target/release/tsunami-loadgen
```

## Install & OS tuning (Linux)

```sh
sudo scripts/install.sh --tune --with-loadgen   # build + install + tune
sudo systemctl enable --now tsunami
```

Installs the binary, a `tsunami` service user, `/etc/tsunami/tsunami.toml`,
systemd units, and `/etc/sysctl.d/99-tsunami.conf` (socket buffers, RX
backlog, NAPI budgets — see `DEPLOYMENT.md`). `scripts/tune.sh` separately
handles CPU governor / THP / optional hugepages, RPS and busy-poll, with
`--check`, `--persist` (boot unit) and `--set KEY=V`. See
`DEPLOYMENT.md` → "One-command install + OS tuning".

## Run

```sh
./target/release/tsunami -c tsunami.toml
```

See `tsunami.toml.example` for all options. Key knobs for large deployments:

- `network.socket_workers` — one io_uring + socket pair per worker; default = CPUs.
- `network.ring_size` — io_uring **submission** entries per worker. The
  completion queue and provided RX-buffer ring are sized automatically from
  it (CQ ≈ 16× entries, clamped 16–64K; RX buffers ≈ 4× entries, clamped
  2–16K × 2 KiB each), so a bigger `ring_size` mostly means more in-flight
  sends, not proportionally more memory. Tune the CQ directly with the
  `TSUNAMI_CQ_SIZE` env var (power of two) if you need to.
- `network.swarm_shards` — power of two; more shards = less lock contention.
- `protocol.store_peer_id` — costs ~30–50 B/peer extra; only enable if you
  need `compact=0` peer_id echo or per-peer client detail.
- `protocol.client_stats` — per-client announce counters (cheap, striped).

### CQ-overflow self-healing (io_uring backend)

If a completion-queue overflow ever drops recv CQEs, the kernel can leak
provided-buffer ids and stall UDP RX. Tsunami detects this via the CQ
overflow counter and automatically rebuilds the RX buffer ring: it cancels
the multishot `recvmsg`s, drains their terminal completions, unregisters +
re-registers a fresh ring, and resubmits — no restart needed. Watch the
`cqe_overflow_total` counter / `tsunami_cqe_overflow_total` metric (and the
`udp worker: io_uring completion queue overflow` / `RX buffer ring rebuilt`
log lines) to see it happen. `TSUNAMI_DEBUG_REBUILD=1` forces the path once
at startup for testing on new kernels.

### 50M-peer sizing (rough)

- Peer storage: ~45 B/peer (v4) → ~2.3 GiB; ~80 B/peer with `store_peer_id`.
- I/O buffers: RX ring is clamped to ≤16K × 2 KiB (≤32 MiB) and the send
  pool to ≤8K buffers **per worker** regardless of `ring_size`, so e.g.
  8 workers stays ≈ 300 MiB worst-case; the CQ is ≤64K × 16 B (≤1 MiB).
- Announce rate needed at 30-min intervals: ~28K/s average — far below the
  ~500K+/s sustained UDP throughput measured on an 8-core box.
- Recommend: `socket_workers = #cores`, `ring_size = 4096–8192`,
  `socket_recv_buffer = 16–64 MiB`, `swarm_shards = 256+`,
  `store_peer_id = false` unless required. Under overload the kernel sheds
  excess packets with `ENOBUFS` (counted in `dropped`) rather than losing
  completions — that's expected backpressure, not a fault.

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
| `/api/stats` | JSON | website stats snapshot (per-proto rates, system gauges) |
| `/api/stats.csv` | CSV | tidy `group,metric,value` export of every scalar stat — for log pipelines |
| `/api/stats.txt` | text | flat `dotted.key=value` lines — grep/awk/shell friendly |
| `/api/timeseries` | JSON | `?seconds=` per-second samples for graphs |
| `/api/timeseries.csv` | CSV | wide per-second samples — history logging |
| `/api/torrents` | JSON | `?limit=100&offset=0` |
| `/api/torrent/{hex}` | JSON | `?limit=200` peers |
| `/api/clients` | JSON | `?n=50` top clients |
| `/metrics` | Prometheus | text exposition format |
| `/bep15`, `/udp` | Raw BEP-15 | POST binary request → binary response |
| `ws://host:port/announce` | WebSocket | BEP-15 in WS binary frames |
| `ws://host:port/scrape` | WebSocket | same |
| `ws://host:port/connect` | WebSocket | same |

## Verifying

```sh
cargo test
cargo build --release
```
