# I2P interop test harness

End-to-end test of Tsunami's I2P tracker endpoints through a real I2P
network via the SAM bridge (i2pd or Java I2P router).

## Setup

1. Run an I2P router with SAM enabled (i2pd enables it by default on
   `127.0.0.1:7656`; Java I2P needs SAM enabled in the console).
2. Run Tsunami with `[i2p] enable = true` (optionally `i2p.listen`).
3. Wait for the router to finish network integration — fresh routers
   take 15-60 minutes before tunnels work.

## Usage

```sh
# Terminal 1: tracker-side SAM endpoint forwarding to Tsunami.
# Prints TRACKER_DEST=<destination> — clients connect to this.
python3 tracker_fwd.py            # forwards to 127.0.0.1:3999

# Terminal 2: announce over real I2P.
python3 client_announce.py <TRACKER_DEST> [info_hash_hex] [compact] \
    ["X-Header: v\r\n"]
```

`client_announce.py` creates a SAM session (its destination is the
peer's I2P identity, sent as the `ip` announce parameter), opens a
stream to the tracker destination, and issues `GET /a` exactly as an
I2P BitTorrent client would.

## Notes

- `samlib.py` implements the SAM v3 text protocol (HELLO handshake,
  SESSION CREATE, STREAM CONNECT/ACCEPT/FORWARD). i2pd specifics:
  commands follow HELLO directly (no CONNECT registration), replies
  use `RESULT=OK`, and STREAM CONNECT/ACCEPT/FORWARD must be issued on
  a *separate* SAM socket from the session-owning one.
- The tracker destination from `tracker_fwd.py` is ephemeral — it
  changes every run.
- To test destination enforcement, run `tracker_fwd.py` and inject
  `X-I2P-DestB64` headers carrying the client's `ip` value (this is
  what the I2PTunnel HTTP server does in production), or enable
  `[i2p] enforce_destination` and verify announces without headers
  get 403.
