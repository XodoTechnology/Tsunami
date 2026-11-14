# I2P support — design notes

Status: **experimental implementation on this branch** (`[i2p] enable =
true`). Implements the tracker-side behavior documented by the I2P
project for BitTorrent-over-I2P (see "Protocol notes" below). See
"Implemented" and "Remaining work" — the peer-exchange format still
needs validation against real I2P clients before this is production
material. See also greatest-ape/aquatic#248, which reached the same
conclusion independently.

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

Endpoints (all gated by `[i2p] enable = true`, off by default):

- `GET /a` (alias) and `GET /i2p/announce` — params: `info_hash` (raw
  20B or 40-hex), **`ip`** = base64 Destination with optional `.i2p`
  suffix (spec parameter; `destination` accepted as an alias), `peer_id`
  (**required**, 20 bytes raw or hex — synthetic IDs rejected), `port`
  (fake compatibility value, echoed but meaningless), `left`, `event`
  (started/completed/stopped/**paused** — BEP-21 semantics kept),
  `numwant`, `compact`.
- Response `peers` format follows the spec:
  - `compact=1`: single byte string of concatenated **32-byte SHA-256
    hashes of the binary Destinations** (self excluded, `numwant`-limited
    random sample).
  - `compact=0` (default): BEP-3-style list of dicts with `ip` =
    destination base64 + `.i2p` re-appended for older clients, `port`,
    and `peer id`.
- `GET /i2p/scrape` — repeated `info_hash` params (raw or hex); returns
  the BEP-48-style `files` dict including `downloaders`.
- `GET /i2p/stats` — JSON `{torrents, peers}` totals for the I2P store.
- Access-list enforcement: `[access_list]` allow/deny modes apply to I2P
  announces identically to clearnet (403 when forbidden).
- Event hooks: `protocol.event_hook_url` receives I2P lifecycle events
  with a `peer_dest` field (the Destination) instead of `peer_ip`.
- Destination enforcement headers (added by the I2P HTTP server / tunnel,
  unspoofable by clients): `X-I2P-DestB64` (full Destination, preferred),
  `X-I2P-DestHash` (SHA-256 of binary Destination → hash-only identity,
  compact responses only), `X-I2P-DestB32` (base32 Destination, decoded
  and re-encoded to base64). When present they override the `ip` param.
- `[i2p] enforce_destination = true` requires those headers on every
  announce (403 otherwise) and ignores the `ip` param entirely — the
  strict mode the spec recommends for trackers that want to prevent
  destination spoofing. Note it also rejects clients that announce via
  the plain I2P HTTP proxy (port 4444), which adds no enforcement
  headers; only own-tunnel announces pass.
- Cross-network prevention: any request to an I2P endpoint carrying an
  `X-Forwarded-For` header is rejected (403) — per the spec, such
  requests came through an HTTP proxy rather than a dedicated tunnel.
- Per-destination rate limit: `[i2p] announce_rate` announces/sec
  (fixed window, default 5; 0 = unlimited) → HTTP 429.
- Optional dedicated listener: `[i2p] listen` binds a separate HTTP port
  that serves **only** `/i2p/*` and `/a` (everything else 404s — checked
  before WebSocket/raw-BEP15 handling). Point the SAM bridge or I2P
  HTTP proxy at it to isolate I2P traffic from clearnet HTTP.
- Peer expiry via `max_peer_age`, lazy sweep on announce + periodic
  `clean()` from the existing cleaner thread; existing HTTP stats
  counters apply.

## Protocol notes

Behavior follows the I2P project's BitTorrent tracker documentation:

- Clients announce a fake `port` (commonly 6881) for compatibility;
  trackers ignore its meaning.
- `ip` carries the base64 Destination in the I2P alphabet
  (`A-Za-z0-9-~`), optionally suffixed `.i2p`; both forms accepted.
- Compact peer identity is the SHA-256 of the *binary* Destination —
  not the base64 text.
- Non-compact `ip` values get `.i2p` appended for older-client
  compatibility.

## Validation status

Verified locally (unit tests + live HTTP smoke): compact/non-compact
response encodings, self-exclusion, scrape counts, all parameter
validation, header enforcement precedence, B32 decode, dedicated-listener
isolation (incl. WebSocket rejection), access-list 403, per-destination
429, XFF rejection, `enforce_destination` mode, and snapshot
round-trip.

Verified over the **real I2P network** (i2pd router, ~388 peers, live
tunnels — see `scripts/i2p/`): an HTTP request through the router's HTTP
proxy reached the I2P server tunnel and was served by Tsunami on the
dedicated I2P listener (`/i2p/stats` → 200). Real announces over the same
path returned correct bencode: compact 32-byte peer hashes, non-compact
peer dicts carrying full base64 Destinations with `.i2p`, scrape
`complete/incomplete/downloaders/downloaded` agreeing with announce
counts, and `paused`/`stopped` events honoring BEP-21 semantics (paused
peers stay in the swarm but leave `downloaders`).

Not yet verified end-to-end: `X-I2P-Dest*` enforcement headers over real
I2P (requires an I2P HTTP server that injects them — i2pd's tunnel and
HTTP proxy do not), and real client software (qBittorrent-I2P,
libtorrent-I2P) interoperability.

## Remaining work

1. **Client-format validation** — the spec documents tracker *requests*
   and response encodings. The wire format is now proven over real I2P
   (above), but pointing an actual I2P BitTorrent client
   (i2p-bt/qBittorrent-I2P/libtorrent-I2P) at a running instance is still
   the final compatibility check.
2. ~~Snapshot coverage~~ — done: I2P peers persist to
   `<snapshot.path stem>.i2p.snap` on the same schedule as clearnet
   snapshots (expired peers are skipped on load).
3. **Native I2P UDP announces** — the Datagram3 spec was finalized
   2025-06, but requests arrive as I2CP protocol-20 datagrams inside
   the I2P network. Terminating those requires either an I2P router
   (i2pd/Java I2P) or SAM v3.3 datagram sessions — which i2pd does not
   yet implement and libtorrent does not use. Not actionable inside
   Tsunami today; revisit if SAM v3.3 datagrams see adoption. HTTP
   announces over the SAM bridge cover all current clients.
4. **The Phase-1 `PeerAddr` refactor** — only if I2P volume ever
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
