//! I2P tracker support (HTTP-only; I2P has no UDP).
//!
//! Protocol follows the public "BitTorrent over I2P" spec
//! (https://i2p.net/en/docs/applications/bittorrent/):
//!
//! - The client's `ip` announce parameter carries its base64-encoded
//!   Destination (I2P base64 alphabet `A-Za-z0-9-~`, optional ".i2p"
//!   suffix). `port` is a fake compatibility value and is ignored for
//!   identity but echoed back in responses.
//! - Non-compact responses return peers as BEP-3-style dicts
//!   `{ip: "<b64>.i2p", port, "peer id"}`.
//! - Compact responses (`compact=1`) return `peers` as one byte string of
//!   concatenated 32-byte SHA-256 hashes of the binary Destinations.
//! - `X-I2P-DestB64` / `X-I2P-DestHash` / `X-I2P-DestB32` headers (added
//!   by the I2PTunnel HTTP server, unspoofable) may override the `ip`
//!   parameter for destination enforcement.
//!
//! This module keeps a separate, deliberately simple store keyed on
//! `(info_hash, destination)` rather than touching the IP-based swarm
//! core. Transport is plain HTTP: the SAM bridge / I2P proxy terminates
//! the tunnel and delivers normal TCP connections to the HTTP listener.

use std::collections::HashMap;

use parking_lot::RwLock;
use sha2::{Digest, Sha256};

use crate::swarm::{AnnounceEvent, InfoHash, Rng};

/// One I2P peer record.
pub struct I2pPeer {
    pub peer_id: [u8; 20],
    /// Fake compatibility port echoed in non-compact responses.
    pub port: u16,
    pub left: i64,
    pub seeder: bool,
    pub paused: bool,
    /// Unix seconds of last announce; drives expiry.
    pub last_seen: u32,
    /// SHA-256 of the binary Destination — the compact-response identity.
    pub dest_hash: [u8; 32],
}

/// Peer entry handed to the HTTP layer for response encoding.
pub struct I2pPeerEntry {
    /// Canonical base64 destination (no ".i2p" suffix).
    pub destination: String,
    pub peer_id: [u8; 20],
    pub port: u16,
    pub dest_hash: [u8; 32],
}

pub struct I2pAnnounceResult {
    pub seeders: u32,
    pub leechers: u32,
    pub downloaders: u32,
    /// Sampled peers, self excluded.
    pub peers: Vec<I2pPeerEntry>,
}

pub struct I2pStore {
    inner: RwLock<HashMap<InfoHash, HashMap<String, I2pPeer>>>,
    /// Per-destination announce rate limiter: destination -> (window_start,
    /// count). Fixed 1-second windows.
    rl: RwLock<HashMap<String, (u32, u32)>>,
    max_peer_age: u32,
    max_response_peers: usize,
    /// Max announces per destination per second (0 = unlimited).
    announce_rate: u32,
}

impl I2pStore {
    pub fn new(max_peer_age: u32, max_response_peers: usize, announce_rate: u32) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            rl: RwLock::new(HashMap::new()),
            max_peer_age,
            max_response_peers,
            announce_rate,
        }
    }

    /// Process an announce. `destination` must already be normalized via
    /// [`normalize_destination`]. Returns None when rate-limited.
    #[allow(clippy::too_many_arguments)]
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        destination: &str,
        peer_id: [u8; 20],
        port: u16,
        left: i64,
        event: AnnounceEvent,
        numwant: i32,
        dest_hash: [u8; 32],
        now: u32,
        rng: &mut Rng,
    ) -> Option<I2pAnnounceResult> {
        // Per-destination fixed-window rate limit.
        if self.announce_rate > 0 {
            let mut rl = self.rl.write();
            let e = rl.entry(destination.to_string()).or_insert((now, 0));
            if e.0 != now {
                *e = (now, 0);
            }
            if e.1 >= self.announce_rate {
                return None;
            }
            e.1 += 1;
        }

        let is_stopped = event == AnnounceEvent::Stopped;
        let seeder = !is_stopped && left == 0;
        let paused = event == AnnounceEvent::Paused && !seeder;

        let mut g = self.inner.write();
        let swarm = g.entry(*info_hash).or_default();

        if is_stopped {
            swarm.remove(destination);
        } else {
            match swarm.get_mut(destination) {
                Some(p) => {
                    p.peer_id = peer_id;
                    p.port = port;
                    p.left = left;
                    p.seeder = seeder;
                    p.paused = paused;
                    p.last_seen = now;
                    p.dest_hash = dest_hash;
                }
                None => {
                    swarm.insert(
                        destination.to_string(),
                        I2pPeer {
                            peer_id,
                            port,
                            left,
                            seeder,
                            paused,
                            last_seen: now,
                            dest_hash,
                        },
                    );
                }
            }
        }

        // Lazily drop this swarm's expired peers while we hold the write
        // lock — keeps memory bounded even if the cleaner thread is slow.
        let cutoff = now.wrapping_sub(self.max_peer_age);
        swarm.retain(|_, p| p.last_seen > cutoff);
        if swarm.is_empty() {
            g.remove(info_hash);
        }
        let swarm = match g.get(info_hash) {
            Some(s) => s,
            None => {
                return Some(I2pAnnounceResult {
                    seeders: 0,
                    leechers: 0,
                    downloaders: 0,
                    peers: Vec::new(),
                })
            }
        };

        let mut seeders = 0u32;
        let mut leechers = 0u32;
        let mut downloaders = 0u32;
        for p in swarm.values() {
            if p.seeder {
                seeders += 1;
            } else {
                leechers += 1;
                if !p.paused {
                    downloaders += 1;
                }
            }
        }

        // Sample up to `want` peers, excluding the announcer.
        let want = if numwant <= 0 {
            self.max_response_peers
        } else {
            (numwant as usize).min(self.max_response_peers)
        };
        let mut keys: Vec<&String> = swarm
            .keys()
            .filter(|k| k.as_str() != destination)
            .collect();
        // Partial Fisher-Yates for an unbiased sample without replacement.
        let take = want.min(keys.len());
        let mut peers = Vec::with_capacity(take);
        for i in 0..take {
            let j = i + rng.below(keys.len() - i);
            keys.swap(i, j);
            let k = keys[i];
            let p = &swarm[k];
            peers.push(I2pPeerEntry {
                destination: k.clone(),
                peer_id: p.peer_id,
                port: p.port,
                dest_hash: p.dest_hash,
            });
        }

        Some(I2pAnnounceResult {
            seeders,
            leechers,
            downloaders,
            peers,
        })
    }

    /// Scrape: (seeders, leechers, downloaders) per hash.
    pub fn scrape(&self, info_hashes: &[[u8; 20]]) -> Vec<(u32, u32, u32)> {
        let g = self.inner.read();
        info_hashes
            .iter()
            .map(|h| match g.get(h) {
                Some(swarm) => {
                    let mut s = 0u32;
                    let mut l = 0u32;
                    let mut d = 0u32;
                    for p in swarm.values() {
                        if p.seeder {
                            s += 1;
                        } else {
                            l += 1;
                            if !p.paused {
                                d += 1;
                            }
                        }
                    }
                    (s, l, d)
                }
                None => (0, 0, 0),
            })
            .collect()
    }

    /// Expire peers older than max_peer_age; drop empty torrents and stale
    /// rate-limit entries. Returns (peers_removed, torrents_removed).
    pub fn clean(&self, now: u32) -> (u64, u64) {
        let cutoff = now.wrapping_sub(self.max_peer_age);
        let mut g = self.inner.write();
        let mut peers_removed = 0u64;
        let mut torrents_removed = 0u64;
        g.retain(|_, swarm| {
            let before = swarm.len();
            swarm.retain(|_, p| p.last_seen > cutoff);
            peers_removed += (before - swarm.len()) as u64;
            if swarm.is_empty() {
                torrents_removed += 1;
                false
            } else {
                true
            }
        });
        drop(g);
        // Rate-limit windows older than 60s are dead weight.
        let mut rl = self.rl.write();
        rl.retain(|_, (w, _)| now.wrapping_sub(*w) < 60);
        (peers_removed, torrents_removed)
    }

    /// (torrents, peers) totals for stats endpoints.
    pub fn totals(&self) -> (usize, usize) {
        let g = self.inner.read();
        let peers: usize = g.values().map(|s| s.len()).sum();
        (g.len(), peers)
    }
}

// ---------------------------------------------------------------------------
// Destination handling (I2P base64 + spec validation)
// ---------------------------------------------------------------------------

/// Normalize an announced `ip`/`destination` value to the canonical
/// base64 destination (no ".i2p" suffix). Returns None on malformed input:
/// the spec asks trackers to decode and reject bad base64.
pub fn normalize_destination(raw: &str) -> Option<String> {
    let s = raw.strip_suffix(".i2p").unwrap_or(raw);
    if s.is_empty() || s.len() > 1024 || !s.is_ascii() {
        return None;
    }
    let bin = i2p_b64_decode(s.as_bytes())?;
    // Destinations are 387+ bytes; allow a generous band for future growth.
    if !(256..=1024).contains(&bin.len()) {
        return None;
    }
    Some(s.to_string())
}

/// Decode the I2P base64 alphabet (`A-Za-z0-9-~`, `=` padding) to bytes.
fn i2p_b64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'-' => Some(62),
            b'~' => Some(63),
            _ => None,
        }
    }
    let mut sextets: Vec<u32> = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'=' => break,
            _ => sextets.push(val(b)?),
        }
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let n = chunk.len();
        if n < 2 {
            return None;
        }
        let triple = (chunk[0] << 18) | (chunk[1] << 12)
            | (if n > 2 { chunk[2] << 6 } else { 0 })
            | (if n > 3 { chunk[3] } else { 0 });
        out.push((triple >> 16) as u8);
        if n > 2 {
            out.push((triple >> 8) as u8);
        }
        if n > 3 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

/// SHA-256 of the binary Destination — the compact-response peer hash.
pub fn dest_hash_of(canonical_b64: &str) -> [u8; 32] {
    // normalize_destination already validated the input, so decode failure
    // is impossible in practice — fall back to hashing the string.
    match i2p_b64_decode(canonical_b64.as_bytes()) {
        Some(bin) => Sha256::digest(&bin).into(),
        None => Sha256::digest(canonical_b64.as_bytes()).into(),
    }
}

/// Parse an `X-I2P-DestHash` header value (base64 SHA-256 of the binary
/// Destination). Returns the 32-byte hash for compact responses.
pub fn parse_dest_hash_b64(s: &str) -> Option<[u8; 32]> {
    let bin = i2p_b64_decode(s.as_bytes())?;
    if bin.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bin);
    Some(out)
}

/// Decode an `X-I2P-DestB32` header value (RFC 4648 base32, optional
/// ".b32.i2p" suffix) and re-encode the binary Destination in the I2P
/// base64 alphabet so it flows through `normalize_destination` like any
/// other announced destination.
pub fn dest_b32_to_b64(s: &str) -> Option<String> {
    let s = s
        .strip_suffix(".b32.i2p")
        .or_else(|| s.strip_suffix(".i2p"))
        .unwrap_or(s);
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    let mut bin = Vec::with_capacity(s.len() * 5 / 8);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            b'=' => break,
            _ => return None,
        } as u64;
        acc = (acc << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            bin.push((acc >> nbits) as u8);
        }
    }
    if bin.is_empty() {
        return None;
    }
    Some(i2p_b64_encode(&bin))
}

/// Encode binary Destination bytes in the I2P base64 alphabet
/// (`A-Za-z0-9-~`, no padding).
fn i2p_b64_encode(bin: &[u8]) -> String {
    const ALPH: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
    let mut out = String::with_capacity(bin.len() * 4 / 3 + 4);
    for chunk in bin.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPH[(n >> 18) as usize & 63] as char);
        out.push(ALPH[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPH[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPH[n as usize & 63] as char);
        }
    }
    out
}

/// Loose pre-check used before normalize (cheap reject of obvious junk).
pub fn looks_like_destination(s: &str) -> bool {
    s.len() >= 64 && s.len() <= 1024 && s.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a syntactically valid I2P destination: 387 zero bytes ->
    /// base64 in the I2P alphabet, no ".i2p" suffix.
    fn dest(n: u8) -> String {
        // 387 bytes -> 516 base64 chars; vary last byte for uniqueness.
        let mut bin = vec![b'A'; 387];
        bin[386] = n;
        // Standard base64 then translate +/ -> -~ (I2P alphabet).
        let std = base64_encode(&bin);
        std.replace('+', "-").replace('/', "~")
    }

    fn base64_encode(data: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
                | (*chunk.get(2).unwrap_or(&0) as u32);
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn announce_scrape_pause_clean() {
        let store = I2pStore::new(100, 50, 0);
        let mut rng = Rng::new();
        let ih: InfoHash = [9u8; 20];
        let now = 1_000_000u32;
        let pid = [7u8; 20];
        let d1 = normalize_destination(&dest(1)).unwrap();
        let d2 = normalize_destination(&(dest(2) + ".i2p")).unwrap();

        let r = store
            .announce(&ih, &d1, pid, 6881, 100, AnnounceEvent::Started, 0, dest_hash_of(&d1), now, &mut rng)
            .unwrap();
        assert_eq!((r.seeders, r.leechers, r.downloaders), (0, 1, 1));

        let r = store
            .announce(&ih, &d2, pid, 6881, 100, AnnounceEvent::Paused, 0, dest_hash_of(&d2), now, &mut rng)
            .unwrap();
        assert_eq!((r.seeders, r.leechers, r.downloaders), (0, 2, 1));

        let s = store.scrape(&[ih]);
        assert_eq!(s, vec![(0, 2, 1)]);

        let r = store
            .announce(&ih, &d2, pid, 6881, 100, AnnounceEvent::None, 0, dest_hash_of(&d2), now, &mut rng)
            .unwrap();
        assert_eq!(r.downloaders, 2);

        store.announce(&ih, &d1, pid, 6881, 100, AnnounceEvent::Stopped, 0, dest_hash_of(&d1), now, &mut rng);
        let s = store.scrape(&[ih]);
        assert_eq!(s, vec![(0, 1, 1)]);

        let (pr, tr) = store.clean(now + 200);
        assert_eq!((pr, tr), (1, 1));
    }

    #[test]
    fn rate_limit() {
        let store = I2pStore::new(100, 50, 2);
        let mut rng = Rng::new();
        let ih: InfoHash = [1u8; 20];
        let d = normalize_destination(&dest(9)).unwrap();
        let pid = [3u8; 20];
        let now = 5_000_000u32;
        for _ in 0..2 {
            assert!(store
                .announce(&ih, &d, pid, 6881, 1, AnnounceEvent::None, 0, dest_hash_of(&d), now, &mut rng)
                .is_some());
        }
        // Third announce in the same second is shed.
        assert!(store
            .announce(&ih, &d, pid, 6881, 1, AnnounceEvent::None, 0, dest_hash_of(&d), now, &mut rng)
            .is_none());
        // Next second resets the window.
        assert!(store
            .announce(&ih, &d, pid, 6881, 1, AnnounceEvent::None, 0, dest_hash_of(&d), now + 1, &mut rng)
            .is_some());
    }

    #[test]
    fn destination_normalization() {
        let d = dest(3);
        // ".i2p" suffix is stripped.
        assert_eq!(normalize_destination(&(d.clone() + ".i2p")).unwrap(), d);
        // junk rejected
        assert!(normalize_destination("not a destination!!!").is_none());
        assert!(normalize_destination("").is_none());
        assert!(normalize_destination(&"A".repeat(50)).is_none()); // too short -> decodes <256B
    }
}
