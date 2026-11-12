# Benchmarks

Head-to-head UDP tracker comparison: **Tsunami vs Aquatic vs opentracker**,
run sequentially on the same isolated VM under identical load.

Open [`index.html`](index.html) for the full report with embedded graphs,
or browse [`graphs/`](graphs/) directly.

## Setup

| | |
|---|---|
| Tracker VM | 20 vCPU / 40 GiB, Debian 13, virtio-net (16 queues) |
| Loadgen | 2 × 8 vCPU VMs, 7 source IPs each, custom BEP-15 loadgen |
| Workloads | sustain (~185K req/s, 50K peers, 200 torrents), flood (~440K/s — loadgen ceiling), dual-flood (both loadgen VMs), store (~220K peer burst) |
| Metric | per-second responses received by the loadgen |

All trackers saw the same binary, parameters, and kernel tuning
(`net.core.rmem_max=256MB`, RPS spread, raised TX backlog).

## Headline

- **Throughput:** all three keep up with every offered rate; differences are
  cost, not delivered rate.
- **CPU:** Tsunami at `socket_workers=8` + the sampling optimization is
  ~7% *more* efficient than Aquatic (~15.6µs vs ~16.8µs per request).
  Worker count matters — see `graphs/workers_scaling.png`.
- **Resilience:** opentracker (single-threaded) dropped 12.6M packets under
  dual-flood; Tsunami and Aquatic did not.
- **Memory:** opentracker ~14–25 B/peer, Aquatic ~80 B/peer,
  Tsunami ~45 B/peer at the swarm-store level.

## Caveats

- ~14% of simulated peers fail the BEP-15 connect handshake in the loadgen
  and announce with `conn_id=0`; they are rejected identically by all three
  trackers. This shows up as "loss" in the loadgen's own metric — it is not
  packet loss.
- Offered rates are bounded by the loadgen VMs (~440K/s single,
  ~400K/s dual), below tracker ceilings — throughput figures are floors.
- 200 hot torrents is a worst case for per-torrent lock contention;
  production swarms have far more.

## Reproducing

The load generator is `src/bin/loadgen.rs` (`cargo build --release`,
binary `tsunami-loadgen`). Example sustain cell:

```sh
./tsunami-loadgen --target TRACKER:36881 --peers 50000 --seconds 60 \
  --numwant 50 --threads 24 --seeders 0.3 --rate 200000 --torrents 200 \
  --srcips <list-of-source-ips>
```

Tracker configs used: `io_uring` RX backend, `socket_recv_buffer=16000000`,
`swarm_shards=256`, `store_peer_id=false`, `client_stats=false`,
`max_response_peers=50`, `peer_announce_interval=1800`,
`max_peer_age=2700`.
