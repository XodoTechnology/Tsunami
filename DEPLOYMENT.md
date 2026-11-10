# Tsunami deployment guide — VMs and bare metal

Tsunami is designed to run **everywhere** — cloud VMs, containers, and bare
metal — but the fastest packet paths need specific kernel/driver features.
This guide maps each feature to what it requires and how to tune per
environment. Nothing is *required* beyond a modern Linux kernel; everything
below is opt-in.

## Quick capability matrix

| Feature | Kernel | Privilege | Hardware | Notes |
|---|---|---|---|---|
| UDP tracker (io_uring) | ≥ 5.1 | none | any | **default, works everywhere** |
| HTTP / WebSocket / stats | any | none | any | plain TCP |
| Peer snapshot/restore | any | write to `snapshot.path` | any | disk space ≈ 12 B/peer (v4) |
| Rate limiting | any | none | any | pure userspace |
| `af_packet` RX backend | any | `CAP_NET_RAW` (root) | any NIC | lower burst loss, ~1.5× CPU |
| AF_XDP (future) | ≥ 5.4 | `CAP_NET_ADMIN`+`CAP_NET_RAW` | **native-XDP NIC** | not yet shipped |

## Kernel requirements

- **io_uring backend (default):** Linux ≥ 5.1 for `recvmsg` multishot +
  provided buffer rings. Tested on 6.12. If io_uring is unavailable the
  worker fails at startup — there is no silent fallback, so check the log.
- **Everything else** is plain sockets/threads and works on any kernel.

## Choosing `network.rx_backend`

### `io_uring` (default) — lowest CPU, best for most deployments

Multishot `recvmsg` on a normal UDP socket with registered buffer rings and
pooled `sendmsg`. This is the right choice unless you see burst loss.

### `af_packet` — lower burst loss, higher CPU

`PACKET_RX_RING` kernel packet-mmap ring + `PACKET_FANOUT_HASH` fan-out
across workers. Parses Ethernet/IPv4/IPv6/UDP in userspace; replies go out
normal bound UDP sockets.

- **Requires `CAP_NET_RAW`** — run as root or grant the capability
  (`setcap cap_net_raw+ep ./tsunami`).
- **Interface selection:** auto-detected from the default route for
  wildcard binds; override with `TSUNAMI_PACKET_IFACE=<name>` (e.g. `lo`
  for loopback tests).
- **Trade-off:** ~15% lower peak throughput and ~1.5× CPU vs io_uring in
  our tests, but dramatically lower loss under flood because the kernel
  ring buffers bursts that would overflow UDP socket buffers. Use it when
  you see `dropped`/`ENOBUFS` spikes or run behind bursty traffic.
- Works on **any** NIC including virtio — it's the portable fast path.

### AF_XDP — the future bare-metal path (not shipped yet)

True zero-copy XDP needs a physical NIC whose driver supports native XDP
(mlx5, i40e, ice, bnxt, etc.). On virtio only generic SKB-mode XDP is
possible, which gives little benefit. The full implementation (UMEM +
RX/TX/fill/completion rings + XSKMAP eBPF redirect + netlink attach +
L2/L3/L4 TX frame construction) is designed but not yet shipped — see the
benchmark report. **Do not expect AF_XDP gains on a VM.**

## VM deployment (cloud / virtio)

- `rx_backend = "io_uring"` is the sane default. `af_packet` also works if
  you can grant `CAP_NET_RAW`.
- virtio_net has **no native XDP** — AF_XDP gains won't materialize.
- vCPUs are often oversubscribed: set `socket_workers` to the *allocated*
  vCPU count, not the host's.
- Snapshot file lands on whatever disk is mounted — size it for
  ~12 bytes/peer (v4) / ~24 bytes/peer (v6). At 50M peers ≈ 600 MB (v4).
- Watch `socket_recv_buffer`: on a shared host, very large buffers can
  hurt neighbors; 16–32 MiB is a reasonable ceiling.

## Bare-metal deployment

- `rx_backend = "io_uring"` still fine; `af_packet` if you want burst
  absorption and can run privileged.
- **NUMA:** pin workers to cores on the same NUMA node as the NIC
  (`numactl --cpunodebind --membind`), and size `swarm_shards` so peer
  memory sits near the workers that touch it.
- **Hugepages:** the peer store is a large `Vec`; backing it with huge
  pages reduces TLB misses at 50M-peer scale. Configure
  `vm.nr_hugepages` and, if needed, run with `MAP_HUGETLB` (future knob).
- **IRQ/RSS:** enable NIC receive-side scaling so queues spread across
  cores; with `af_packet` fanout or multi-queue io_uring workers, spread
  is automatic, but check `ethtool -l`/`-x`.
- **AF_XDP** becomes attractive here once shipped — that's where the
  >1M pps path pays off.

## Rate limiting (`[ratelimit]`)

Per-worker token buckets on announce + scrape (the store-mutating paths).
Connects and malformed packets are never limited — they're the cheap
handshake and dropping them just causes client retries anyway.

- `announce_per_sec` / `scrape_per_sec`: **per worker**; global ceiling ≈
  value × `socket_workers`. Start generous (e.g. 2–5× your expected
  announce rate) and tighten if you see abuse.
- `burst`: bucket capacity as a multiple of the per-second rate. `1.0`
  allows a 1-second burst; raise to absorb legitimate re-announce
  synchronized waves (e.g. after a tracker restart).
- Shed requests are counted in `*_rate_limited_total` (stats API +
  `/metrics`) so you can alert on them.

## Snapshot (`[snapshot]`)

- `enable`, `path`, `interval_secs` (0 = shutdown-only).
- Format is compact binary (~12 B/peer v4, ~24 B/peer v6) written to
  `<path>.tmp` then atomically renamed — safe against torn writes.
- Restore happens **before** workers bind; a 50M-peer snapshot adds startup
  latency (tens of seconds) while the index rebuilds. Announce retries
  cover the gap.
- `peer_id` side-table is **not** restored (only present when
  `store_peer_id=true`); it repopulates on each peer's next announce.
- Expired peers (`valid_until` passed during downtime) are skipped on load.

### Snapshot in RAM (tmpfs) — faster restarts

Important nuance: a snapshot buffer *inside the tracker process* cannot
survive a restart — process RAM is freed on exit. But you can put the
snapshot **file** on a RAM-backed filesystem so reads/writes run at memory
speed while still surviving process restarts:

```toml
[snapshot]
path = "/dev/shm/tsunami.snap"   # tmpfs = RAM-backed, survives restarts
```

`/dev/shm` (tmpfs) is RAM-backed and persists across process restarts —
it only disappears on machine reboot or explicit deletion. Measured on this
box: ~55K peers restored to "ready" in ~110 ms. Size tmpfs for the file
(~12 B/peer v4 → ~600 MB at 50M peers). For a snapshot that must also
survive a *machine* reboot, keep `path` on real disk — or write to both.

The restore cost is dominated by **index rebuild** (hash-inserting every
peer), not file I/O — `read_snapshot_torrent` pre-sizes each swarm's
HashMap/Vec from the recorded peer count to avoid rehash storms. Expect
roughly ~0.5–1M peers/sec restore ⇒ ~50–100 s for a full 50M-peer state.

For **zero-downtime** restarts (no gap at all), the real answer is running
two tracker instances behind a load balancer with peer-state sync
(livesync/cluster) — planned as future work; snapshots cover the
stop-start case.

## Full scrape (`http.full_scrape`)

`GET /scrape` with **no** `info_hash` params returns stats for **every**
tracked torrent in BEP-12 format — identical to opentracker's `fullscrape`
(`d5:filesd 20:<hash> d8:complete…ee … ee`). Intended for stats mirrors and
your website.

- **HTTP only.** UDP BEP-15 scrape is a per-hash-list request and the reply
  is a single datagram — it cannot carry millions of torrents, and there's
  no standard "dump all" action. Clients that need the full set should use
  the HTTP endpoint (or the periodic `scrape_export` file).
- Cost: iterates all swarms once; fine for periodic pulls, don't hammer it.

## Tuning checklist

| Knob | VM | Bare metal |
|---|---|---|
| `rx_backend` | `io_uring` (or `af_packet` if privileged) | `io_uring`; `af_packet` for burst absorption |
| `socket_workers` | = allocated vCPUs | = physical cores (mind NUMA) |
| `socket_recv_buffer` | 16–32 MiB | 32–64 MiB |
| `ring_size` | 2048–4096 | 4096–8192 |
| `swarm_shards` | 128–256 | 256+ |
| `snapshot.interval_secs` | 300 | 60–300 |
| `ratelimit.*` | set per expected load | set per expected load |
