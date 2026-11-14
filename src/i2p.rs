//! I2P tracker support (HTTP-only; I2P has no UDP).
//!
//! I2P peers have no IP addresses — they are identified by opaque
//! ~500-char base64 *destination keys*. This module keeps a separate,
//! deliberately simple store keyed on `(info_hash, destination)` rather
//! than touching the IP-based swarm core. Transport is plain HTTP: the
//! I2P SAM bridge / HTTP proxy terminates the tunnel and delivers normal
//! TCP connections to the regular HTTP listener, so `/i2p/announce` and
//! `/i2p/scrape` are the only new surface.
//!
//! Peer exchange returns destination strings in a bencoded response —
//! BEP-3's 6-byte peer format cannot carry I2P identities, so clients
//! must be I2P-aware (this is a new convention, see docs/I2P.md).

use std::collections::HashMap;

use parking_lot::RwLock;

use crate::swarm::{AnnounceEvent, InfoHash, Rng};

/// One I2P peer record. `destination` is the map key; everything else is
/// small enough that the whole store stays compact at I2P swarm sizes.
pub struct I2pPeer {
    pub peer_id: [u8; 20],
    pub left: i64,
    pub seeder: bool,
    pub paused: bool,
    /// Unix seconds of last announce; drives expiry.
    pub last_seen: u32,
}

pub struct I2pStore {
    inner: RwLock<HashMap<InfoHash, HashMap<String, I2pPeer>>>,
    max_peer_age: u32,
    max_response_peers: usize,
}

/// Announce outcome handed back to the HTTP layer.
pub struct I2pAnnounceResult {
    pub interval: i32,
    pub seeders: u32,
    pub leechers: u32,
    pub downloaders: u32,
    /// (destination, peer_id) pairs for the response, self excluded.
    pub peers: Vec<(String, [u8; 20])>,
}

impl I2pStore {
    pub fn new(max_peer_age: u32, max_response_peers: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_peer_age,
            max_response_peers,
        }
    }

    /// Process an announce. Returns None only for a malformed destination.
    /// `numwant <= 0` means "use the configured maximum".
    #[allow(clippy::too_many_arguments)]
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        destination: &str,
        peer_id: [u8; 20],
        left: i64,
        event: AnnounceEvent,
        numwant: i32,
        now: u32,
        rng: &mut Rng,
    ) -> Option<I2pAnnounceResult> {
        if !valid_destination(destination) {
            return None;
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
                    p.left = left;
                    p.seeder = seeder;
                    p.paused = paused;
                    p.last_seen = now;
                }
                None => {
                    swarm.insert(
                        destination.to_string(),
                        I2pPeer {
                            peer_id,
                            left,
                            seeder,
                            paused,
                            last_seen: now,
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
                    interval: 0,
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
            peers.push((k.clone(), p.peer_id));
        }

        Some(I2pAnnounceResult {
            interval: 0, // filled by caller from protocol config
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

    /// Expire peers older than max_peer_age; drop empty torrents.
    /// Returns (peers_removed, torrents_removed).
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
        (peers_removed, torrents_removed)
    }

    #[allow(dead_code)]
    pub fn len_torrents(&self) -> usize {
        self.inner.read().len()
    }
}

/// I2P destinations are long base64/base32-ish ASCII keys (typically
/// ~500 chars). Accept a generous charset/length range — the value is
/// stored opaquely and only needs to be unique per peer.
pub fn valid_destination(d: &str) -> bool {
    !d.is_empty() && d.len() <= 1024 && d.is_ascii()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(n: u8) -> String {
        "A".repeat(500) + &n.to_string()
    }

    #[test]
    fn announce_scrape_pause_clean() {
        let store = I2pStore::new(100, 50);
        let mut rng = Rng::new();
        let ih: InfoHash = [9u8; 20];
        let now = 1_000_000u32;
        let pid = [7u8; 20];

        let r = store
            .announce(&ih, &dest(1), pid, 100, AnnounceEvent::Started, 0, now, &mut rng)
            .unwrap();
        assert_eq!((r.seeders, r.leechers, r.downloaders), (0, 1, 1));

        // Second peer pauses -> downloaders drops, leechers stays.
        let r = store
            .announce(&ih, &dest(2), pid, 100, AnnounceEvent::Paused, 0, now, &mut rng)
            .unwrap();
        assert_eq!((r.seeders, r.leechers, r.downloaders), (0, 2, 1));

        // Scrape agrees.
        let s = store.scrape(&[ih]);
        assert_eq!(s, vec![(0, 2, 1)]);

        // Unpause -> downloaders back up.
        let r = store
            .announce(&ih, &dest(2), pid, 100, AnnounceEvent::None, 0, now, &mut rng)
            .unwrap();
        assert_eq!(r.downloaders, 2);

        // Stopped removes.
        store.announce(&ih, &dest(1), pid, 100, AnnounceEvent::Stopped, 0, now, &mut rng);
        let s = store.scrape(&[ih]);
        assert_eq!(s, vec![(0, 1, 1)]);

        // Expiry: now beyond max_peer_age removes both.
        let (pr, tr) = store.clean(now + 200);
        assert_eq!((pr, tr), (1, 1));
        assert!(store.scrape(&[ih])[0].0 == 0);
    }
}
