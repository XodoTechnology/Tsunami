# I2P support — design notes

Status: **initial implementation on this branch** (`[i2p] enable = true`
→ `GET /i2p/announce` + `GET /i2p/scrape` on the HTTP listener). See
"Implemented" below, then "Remaining work" for what is still missing.
See also greatest-ape/aquatic#248, which reached the same conclusion
independently.

## Why it's not a feature flag

I2P (Invisible Internet Project) is an anonymous overlay network. Peers do
not have IP addresses — they are identified by ~516-character base64
*destination keys*. Three assumptions baked into Tsunami's design break:

1. **Peer lists can't carry I2P identities.** BEP-3's compact peer format is
   6 bytes (IPv4 + port); even the non-compact form is 6 bytes. There is no
   room for a destination key. I2P BitTorrent clients therefore use custom
   peer-exchange conventions — we would be *designing* protocol, not
   implementing a spec.
2. **The swarm store is keyed on `(IpAddr, port)`.** Every shard lookup,
   hash index, snapshot record, and conn-id check assumes an IP socket
   address. An opaque destination string is a different key type.
3. **There is no UDP over I2P.** BEP-15 (our primary transport) is
   impossible; I2P is TCP-stream only.

## What *is* easy: transport

Getting HTTP announces to the tracker over I2P is nearly free, because the
I2P side terminates the tunnel before us:

- **SAM bridge** (`127.0.0.1:7656` by default): the router's SAM API accepts
  a destination + stream request and hands the application a plain TCP
  socket. Tsunami's existing HTTP server could sit behind it unchanged.
- **I2P HTTP proxy** (`127.0.0.1:4444`): standard HTTP proxy that tunnels
  `http://*.i2p` requests — again, plain HTTP to us.

In both cases the TCP peer address we see is the local router/bridge —
**useless for peer identity**, which is the whole problem.

## Implemented (this branch)

A self-contained `src/i2p.rs` module — deliberately *not* the Phase-1
`PeerAddr` refactor. Rationale: I2P swarms are tiny, so a separate
`HashMap<InfoHash, HashMap<destination, I2pPeer>>` store behind a single
`RwLock` costs nothing on the IP hot path and cannot regress the 50M-peer
design. If I2P volume ever grows, revisit the unified-address refactor.

- `GET /i2p/announce` — params: `info_hash` (raw 20B or 40-hex),
  `destination` (required, ≤1024 ASCII chars, stored opaquely),
  `peer_id` (raw or hex), `port` (ignored — I2P has no ports), `left`,
  `event` (started/completed/stopped/**paused** — BEP-21 semantics kept),
  `numwant`. Returns a bencoded dict: `interval`, `min interval`,
  `complete`, `incomplete`, `downloaders`, and `peers` — a list of
  `{destination, peer_id}` dicts (self excluded, random sample).
- `GET /i2p/scrape` — repeated `info_hash` params (raw or hex); returns
  the BEP-48-style `files` dict including `downloaders`.
- Peer expiry via `max_peer_age`, lazy sweep on announce + periodic
  `clean()` from the existing cleaner thread.
- All existing HTTP stats counters apply; synthetic peer_ids rejected.

## Remaining work

1. **Client-format validation** — the `{destination, peer_id}` peer dict
   is a new convention. Before merge, verify against real I2P BT clients
   (i2p-bt, qBittorrent-I2P, libtorrent-I2P) what they parse; adjust the
   response shape to match reality.
2. **Rate limiting** — no per-IP limits apply (no IPs); add a
   per-destination token bucket if abused.
3. **Transport hardening** — optionally bind a dedicated listener for the
   SAM bridge so I2P traffic is isolated from clearnet HTTP.
4. **Peer_id requirement** — currently optional (defaults to zeros);
   tighten if clients always send one.
5. **The Phase-1 `PeerAddr` refactor** — only if I2P volume ever
   justifies unifying the stores; not needed at current scope.

## Original analysis (superseded by the standalone-module approach above)

### Phase 1 — address abstraction (the prerequisite refactor)

Introduce a peer-identity type that can be either a socket address or an
I2P destination:

```rust
pub enum PeerAddr {
    Ip { ip: IpAddr, port: u16 },
    I2p { destination: Box<str> },  // ~516-char base64 key
}
```

This touches `Slot4`/`Slot6`, `PeerEndpoint`, `key_for`, snapshot
serialization, the stats API, and every place `IpAddr` flows through
announce/scrape. It is the bulk of the work and must land *before* any I2P
protocol code — exactly the "fundamental refactory" aquatic's maintainer
warned about. Do it as a pure refactor with zero behavior change, verified
by the existing benchmark suite.

### Phase 2 — I2P announce transport

- Accept announces on a dedicated HTTP listener bound for the SAM bridge /
  I2P proxy path (e.g. `/i2p/announce`), or detect I2P peers via a marker.
- Peer identity comes from a client-supplied destination parameter (the
  exact parameter name needs checking against I2P BT client
  implementations — qBittorrent/libtorrent I2P patches, i2p-bt clients).
- No conn-ids (UDP-only concept), no per-IP rate limiting (no IPs) —
  rate-limit by destination hash instead.

### Phase 3 — peer exchange format

The hard design question. Options, in increasing order of cleanliness:

- **Custom response format**: return destinations in a non-BEP-3 JSON or
  bencoded extension that I2P clients already understand (needs research
  into what i2p-bt clients actually parse — this is the biggest unknown).
- **Repurposed compact field**: some I2P trackers stuff a destination
  *index* into the 6-byte peer field and resolve it via a second lookup —
  fragile, probably wrong.
- **Tracker-local peer exchange**: since the I2P swarm is small, maybe
  clients don't need tracker peer lists at all (I2P has its own peer
  discovery) — the tracker could be announce/scrape-only for stats. Worth
  verifying what I2P BT clients actually require.

## Open questions (need research before coding)

1. What do real I2P BitTorrent clients send/expect? (Survey
   i2p-bt/qBittorrent-I2P/libtorrent-I2P announce formats and peer-list
   parsing.)
2. Does any deployed I2P tracker exist to interoperate with, and what
   format does it use?
3. Is announce/scrape-only (no peer lists) viable for the I2P swarm size?
4. How are I2P destinations validated/normalized (case, padding)?

## Effort estimate

Phase 1 alone is a multi-day refactor touching the storage core. Phases 2–3
are unbounded until the client-format question is answered. This is a
**research project**, not a feature — which is why it lives on a branch.
