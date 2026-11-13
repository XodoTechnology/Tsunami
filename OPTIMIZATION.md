# Tsunami optimization brief

Production: 46M+ peers, ~12.5M torrents, UDP BEP-15 primary, io_uring backend,
16 workers. Bench: 20 vCPU VM, results in `/root/bench/vm-results/`.

## Memory (biggest gap vs Aquatic: ~33MB vs ~180-280MB at 300K peers)

I/O buffer pools are now ~halved (`35e14a0`): RX provided-buffers 2x SQ size,
RESPONSE_BUF_LEN 4096. Remaining RSS is mostly **swarm storage** at scale:

- `src/swarm.rs`: `Swarm` = `Vec<Slot>` (12B/peer v4) + `HashMap<Key,u32>` index.
  Index entry ≈ key(12-16B)+val(4B)+ctrl ≈ ~25-30B/peer → ~40B/peer total.
  At 46M peers ≈ ~1.8GB. Ideas:
  - Pack `(ip,port)` key into u64 for v4 (already? check `S::Key`) and use
    `hashbrown::HashMap<u64,u32>` with `ahash`/fx — may already be close.
  - Consider `Vec`-based open addressing or `sxd`/`hashbrown` raw_entry API.
  - `peer_ids` map only exists when `store_peer_id=true` (prod: false) — fine.
- Store: `hashbrown::HashMap<InfoHash, RwLock<Swarm>>` per shard (256 shards).
  12.5M torrents → per-torrent `Swarm` struct overhead (Vec caps, HashMap caps)
  matters — check `Swarm::default()` allocation behavior for tiny swarms
  (most torrents have <10 peers; HashMap/Vec minimum caps may waste ~100B+ each
  → ~1GB+ at 12.5M torrents). **Lazy-init index/peers or SmallVec-style
  inline-first-peer could be the single biggest memory win.**

## CPU / throughput

- Announce hot path: parse (`protocol.rs`, zero-copy OK) → validator (BLAKE3)
  → store.announce → stratified sample (`d021b93` already incremental) →
  response build → sendmsg SQE. `client_stats` recording adds a striped-map
  lock+update per announce (prod has it ON — measure its cost, consider
  sampling or per-shard counters).
- `clean_shard` walks all 12.5M torrents every 30s × 2 threads — ~0.1-0.2
  cores now, grows with torrent count. Consider epoch-based skip for swarms
  with no recent announces (needs `last_activity` timestamp per swarm ~8B).
- io_uring: 16 workers prod. CQ size = ring×16 clamped [16384,65536].
  `submit_and_wait(1)` per loop — under heavy CQE load consider batch drain
  (`completion().sync()` once) — check if already minimal.
- AF_PACKET backend (`rx_packet.rs`) exists but prod uses io_uring.

## Correctness / ops already handled

- Conn_ids persist across restarts via `/var/lib/tsunami/conn.key`
  (wall-clock timestamps in `src/udp/validator.rs`).
- Per-IP connect limiter exists (`ratelimit.rs IpConnectLimiter`) — DISABLED
  on prod after legit-user impact; keep it off or make it CGNAT-aware.
- Synthetic all-digit peer_ids silently dropped on UDP (cheap reject).
- SQE starvation fix: rearm/cancel SQEs drain before pending sends
  (`run_inner` in `src/udp/mod.rs`) — do not reorder back.
- Response-size assert at startup guards fixed send buffers.

## Bench methodology notes

- Loadgen (`src/bin/loadgen.rs`) caps ~200K pkt/s DELIVERED per VM — use 2-3
  loadgen VMs for flood cells (`vmbench_dual_v2.sh`). "sent=" overstates wire
  rate; trust tracker-side `requests` counter + recv/s.
- Cells: sustain 200K/s×60s, store 300K peers once, flood unpaced.
- opentracker daemonizes — sampler pid trick fails; sample by process name.
