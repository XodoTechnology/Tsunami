//! Compact swarm storage engine.
//!
//! Design goals for 10^7-10^8 peer scale:
//! - Dense `Vec<Slot>` peer arrays (12 bytes/peer IPv4, 24 bytes IPv6)
//! - `HashMap<Key, u32>` index for O(1) announce lookup/update
//! - No per-peer heap allocation, no peer_id stored in the hot path
//! - Two-level locking: shard RwLock<HashMap<InfoHash, RwLock<Swarm>>>
//!   * shard read lock is shared -> announces never block each other
//!   * per-swarm write lock only serializes same-torrent announces
//! - Stratified-random peer sampling: O(n), no duplicates, cache friendly
//! - Incremental seeder/leecher counters; expiry via backward swap-remove
//!   with index fixups (no full index rebuild)

use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashMap;
use parking_lot::RwLock;

pub type InfoHash = [u8; 20];
pub type PeerId = [u8; 20];

// ---------------------------------------------------------------------------
// PRNG: xoshiro256** — fast, tiny state, good enough for peer sampling.
// ---------------------------------------------------------------------------

pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        let _ = getrandom::fill(&mut seed);
        let mut s = [0u64; 4];
        for (i, chunk) in seed.chunks_exact(8).enumerate() {
            s[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        // avoid all-zero state
        if s.iter().all(|&x| x == 0) {
            s[0] = 0x9E3779B97F4A7C15;
        }
        Self { s }
    }

    #[inline]
    fn next(&mut self) -> u64 {
        let result = (self.s[1].wrapping_mul(5)).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform-ish value in [0, n). Modulo bias is negligible for our sizes.
    #[inline]
    pub fn below(&mut self, n: usize) -> usize {
        debug_assert!(n > 0);
        (self.next() % n as u64) as usize
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Peer endpoints (what goes on the wire / into responses)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PeerEndpoint {
    pub ip: IpAddr,
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Slot trait + concrete slot types
// ---------------------------------------------------------------------------

pub trait Slot: Copy + Send + Sync + 'static {
    type Key: Copy + Eq + Hash + Send + Sync + 'static;

    /// Identity key for (ip, port). None if ip family doesn't match.
    fn key_for(ip: &IpAddr, port: u16) -> Option<Self::Key>;
    /// Construct a slot. Caller guarantees ip family matches.
    fn new_slot(ip: &IpAddr, port: u16, seeder: bool, valid_until: u32) -> Self;

    fn key(&self) -> Self::Key;
    fn is_seeder(&self) -> bool;
    fn set_seeder(&mut self, seeder: bool);
    fn valid_until(&self) -> u32;
    fn set_valid_until(&mut self, t: u32);
    fn endpoint(&self) -> PeerEndpoint;
}

const SEEDER_FLAG: u8 = 1;

/// IPv4 peer slot — 12 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Slot4 {
    ip: u32, // u32::from(Ipv4Addr) canonical form
    port: u16,
    flags: u8,
    _pad: u8,
    valid_until: u32,
}

impl Slot for Slot4 {
    type Key = u64; // (ip << 16) | port

    #[inline]
    fn key_for(ip: &IpAddr, port: u16) -> Option<u64> {
        match ip {
            IpAddr::V4(v4) => Some(((u32::from(*v4) as u64) << 16) | port as u64),
            _ => None,
        }
    }

    #[inline]
    fn new_slot(ip: &IpAddr, port: u16, seeder: bool, valid_until: u32) -> Self {
        let ip = match ip {
            IpAddr::V4(v4) => u32::from(*v4),
            _ => unreachable!("Slot4 with non-v4 ip"),
        };
        Self {
            ip,
            port,
            flags: if seeder { SEEDER_FLAG } else { 0 },
            _pad: 0,
            valid_until,
        }
    }

    #[inline]
    fn key(&self) -> u64 {
        ((self.ip as u64) << 16) | self.port as u64
    }
    #[inline]
    fn is_seeder(&self) -> bool {
        self.flags & SEEDER_FLAG != 0
    }
    #[inline]
    fn set_seeder(&mut self, seeder: bool) {
        if seeder {
            self.flags |= SEEDER_FLAG;
        } else {
            self.flags &= !SEEDER_FLAG;
        }
    }
    #[inline]
    fn valid_until(&self) -> u32 {
        self.valid_until
    }
    #[inline]
    fn set_valid_until(&mut self, t: u32) {
        self.valid_until = t;
    }
    #[inline]
    fn endpoint(&self) -> PeerEndpoint {
        PeerEndpoint {
            ip: IpAddr::V4(Ipv4Addr::from(self.ip)),
            port: self.port,
        }
    }
}

/// IPv6 peer key — 18 bytes (16 ip + 2 port).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Key6 {
    ip: [u8; 16],
    port: u16,
}

/// IPv6 peer slot — 24 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Slot6 {
    ip: [u8; 16],
    port: u16,
    flags: u8,
    _pad: u8,
    valid_until: u32,
}

impl Slot for Slot6 {
    type Key = Key6;

    #[inline]
    fn key_for(ip: &IpAddr, port: u16) -> Option<Key6> {
        match ip {
            IpAddr::V6(v6) => Some(Key6 {
                ip: v6.octets(),
                port,
            }),
            _ => None,
        }
    }

    #[inline]
    fn new_slot(ip: &IpAddr, port: u16, seeder: bool, valid_until: u32) -> Self {
        let ip = match ip {
            IpAddr::V6(v6) => v6.octets(),
            _ => unreachable!("Slot6 with non-v6 ip"),
        };
        Self {
            ip,
            port,
            flags: if seeder { SEEDER_FLAG } else { 0 },
            _pad: 0,
            valid_until,
        }
    }

    #[inline]
    fn key(&self) -> Key6 {
        Key6 {
            ip: self.ip,
            port: self.port,
        }
    }
    #[inline]
    fn is_seeder(&self) -> bool {
        self.flags & SEEDER_FLAG != 0
    }
    #[inline]
    fn set_seeder(&mut self, seeder: bool) {
        if seeder {
            self.flags |= SEEDER_FLAG;
        } else {
            self.flags &= !SEEDER_FLAG;
        }
    }
    #[inline]
    fn valid_until(&self) -> u32 {
        self.valid_until
    }
    #[inline]
    fn set_valid_until(&mut self, t: u32) {
        self.valid_until = t;
    }
    #[inline]
    fn endpoint(&self) -> PeerEndpoint {
        PeerEndpoint {
            ip: IpAddr::V6(Ipv6Addr::from(self.ip)),
            port: self.port,
        }
    }
}

// ---------------------------------------------------------------------------
// Announce event
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnnounceEvent {
    None,
    Completed,
    Started,
    Stopped,
}

impl AnnounceEvent {
    #[inline]
    pub fn from_wire(v: i32) -> Self {
        match v {
            1 => Self::Completed,
            2 => Self::Started,
            3 => Self::Stopped,
            _ => Self::None,
        }
    }
}

/// Everything a swarm needs to process an announce.
pub struct AnnounceInput {
    pub ip: IpAddr,
    pub port: u16,
    pub peer_id: PeerId,
    pub left: i64,
    pub event: AnnounceEvent,
    pub numwant: i32,
}

impl AnnounceInput {
    pub fn new(ip: IpAddr, port: u16, peer_id: PeerId, left: i64, event: AnnounceEvent, numwant: i32) -> Self {
        Self {
            ip,
            port,
            peer_id,
            left,
            event,
            numwant,
        }
    }
}

// ---------------------------------------------------------------------------
// Swarm: one info hash's peer set
// ---------------------------------------------------------------------------

pub struct Swarm<S: Slot> {
    peers: Vec<S>,
    index: HashMap<S::Key, u32>,
    seeders: u32,
    /// Optional peer_id side table (only populated when store_peer_id enabled).
    /// Used for HTTP compact=0 peer_id echo and per-torrent peer detail API.
    peer_ids: Option<HashMap<S::Key, PeerId>>,
}

impl<S: Slot> Swarm<S> {
    pub fn new(store_peer_id: bool) -> Self {
        Self {
            peers: Vec::new(),
            index: HashMap::new(),
            seeders: 0,
            peer_ids: store_peer_id.then(HashMap::new),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    #[inline]
    pub fn num_peers(&self) -> (u32, u32) {
        (self.seeders, self.peers.len() as u32 - self.seeders)
    }

    /// Process an announce. Returns (seeders, leechers, added, removed)
    /// AFTER the update, including the announcing peer in the counts
    /// (but never in `out`).
    ///
    /// `out` is cleared then filled with up to `max_peers` endpoints,
    /// excluding the announcing peer itself.
    pub fn announce(
        &mut self,
        input: &AnnounceInput,
        now: u32,
        max_peer_age: u32,
        max_peers: usize,
        rng: &mut Rng,
        out: &mut Vec<PeerEndpoint>,
    ) -> (u32, u32, bool, bool) {
        out.clear();

        let Some(key) = S::key_for(&input.ip, input.port) else {
            // family mismatch — shouldn't happen; respond with zeros
            let (s, l) = self.num_peers();
            return (s, l, false, false);
        };

        let is_stopped = input.event == AnnounceEvent::Stopped;
        let is_seeder = !is_stopped && input.left == 0;
        let existing = self.index.get(&key).copied();
        let mut added = false;
        let mut removed = false;

        let mut self_slot: Option<usize> = None;

        if is_stopped {
            if let Some(slot) = existing {
                self.remove_at(slot as usize);
                removed = true;
            }
        } else {
            match existing {
                Some(slot) => {
                    let s = &mut self.peers[slot as usize];
                    let was_seeder = s.is_seeder();
                    s.set_seeder(is_seeder);
                    s.set_valid_until(now.wrapping_add(max_peer_age));
                    if was_seeder != is_seeder {
                        if is_seeder {
                            self.seeders += 1;
                        } else {
                            self.seeders -= 1;
                        }
                    }
                    self_slot = Some(slot as usize);
                    if let Some(m) = self.peer_ids.as_mut() {
                        m.insert(key, input.peer_id);
                    }
                }
                None => {
                    let slot = self.peers.len();
                    self.peers.push(S::new_slot(
                        &input.ip,
                        input.port,
                        is_seeder,
                        now.wrapping_add(max_peer_age),
                    ));
                    self.index.insert(key, slot as u32);
                    if is_seeder {
                        self.seeders += 1;
                    }
                    self_slot = Some(slot);
                    added = true;
                    if let Some(m) = self.peer_ids.as_mut() {
                        m.insert(key, input.peer_id);
                    }
                }
            }
        }

        let (seeders, leechers) = self.num_peers();

        // Sample up to max_peers + (self present ? 1 : 0) candidates so that
        // after excluding self we still have a full response when possible.
        let want = max_peers + self_slot.is_some() as usize;
        self.sample_peers(want, self_slot, rng, out);
        out.truncate(max_peers);

        (seeders, leechers, added, removed)
    }

    /// Stratified random sample of peer endpoints.
    ///
    /// Divides the peer array into `want` contiguous buckets and picks one
    /// random slot per bucket: O(want), no duplicates, good spread across
    /// insertion epochs. `exclude` skips the announcer's own slot.
    fn sample_peers(
        &self,
        want: usize,
        exclude: Option<usize>,
        rng: &mut Rng,
        out: &mut Vec<PeerEndpoint>,
    ) {
        let len = self.peers.len();
        if len == 0 || want == 0 {
            return;
        }
        let want = want.min(len);

        if want >= len {
            for (i, p) in self.peers.iter().enumerate() {
                if Some(i) != exclude {
                    out.push(p.endpoint());
                }
            }
            return;
        }

        for b in 0..want {
            let start = b * len / want;
            let end = ((b + 1) * len / want).max(start + 1).min(len);
            if start >= end {
                continue;
            }
            let mut idx = start + rng.below(end - start);
            if Some(idx) == exclude {
                if idx + 1 < end {
                    idx += 1;
                } else if idx > start {
                    idx -= 1;
                } else {
                    continue; // single-element bucket holding only self
                }
            }
            out.push(self.peers[idx].endpoint());
        }
    }

    /// Remove peer at `slot` via swap_remove, fixing the moved element's index.
    fn remove_at(&mut self, slot: usize) {
        let removed = self.peers.swap_remove(slot);
        if slot < self.peers.len() {
            let moved_key = self.peers[slot].key();
            self.index.insert(moved_key, slot as u32);
        }
        let removed_key = removed.key();
        self.index.remove(&removed_key);
        if let Some(m) = self.peer_ids.as_mut() {
            m.remove(&removed_key);
        }
        if removed.is_seeder() {
            self.seeders -= 1;
        }
    }

    /// Expire peers whose valid_until has passed. Returns number removed.
    /// O(n) with index fixups only for removed/moved peers.
    pub fn clean(&mut self, now: u32) -> usize {
        let mut removed = 0usize;
        let mut i = self.peers.len();
        while i > 0 {
            i -= 1;
            if self.peers[i].valid_until() <= now {
                self.remove_at(i);
                removed += 1;
            }
        }
        removed
    }

    /// Look up a peer endpoint by key (for stats APIs).
    pub fn peer_id_of(&self, key: &S::Key) -> Option<PeerId> {
        self.peer_ids.as_ref()?.get(key).copied()
    }

    /// Append every peer as a snapshot record. Caller holds the swarm read
    /// lock, so the copy is consistent. Buffer is cleared first.
    pub fn peers_snapshot(&self, out: &mut Vec<PeerSnap>) {
        out.clear();
        out.reserve(self.peers.len());
        for p in &self.peers {
            let e = p.endpoint();
            out.push(PeerSnap {
                ip: e.ip,
                port: e.port,
                seeder: p.is_seeder(),
                valid_until: p.valid_until(),
            });
        }
    }

    /// Pre-size storage before a bulk restore so the per-peer inserts don't
    /// trigger repeated HashMap rehashes / Vec reallocs.
    pub fn reserve_restore(&mut self, additional: usize) {
        self.peers.reserve(additional);
        self.index.reserve(additional);
        if let Some(m) = self.peer_ids.as_mut() {
            m.reserve(additional);
        }
    }

    /// Restore one peer from a snapshot. Returns false on IP-family
    /// mismatch or if the (ip,port) is already present.
    pub fn restore_peer(
        &mut self,
        ip: &IpAddr,
        port: u16,
        seeder: bool,
        valid_until: u32,
    ) -> bool {
        let Some(key) = S::key_for(ip, port) else {
            return false;
        };
        if self.index.contains_key(&key) {
            return false;
        }
        let slot = self.peers.len();
        self.peers
            .push(S::new_slot(ip, port, seeder, valid_until));
        self.index.insert(key, slot as u32);
        if seeder {
            self.seeders += 1;
        }
        true
    }
}

/// One peer record in a snapshot file.
#[derive(Clone, Copy)]
pub struct PeerSnap {
    pub ip: IpAddr,
    pub port: u16,
    pub seeder: bool,
    pub valid_until: u32,
}

/// Per-family totals: ((torrents, peers, seeders, leechers) v4, same v6).
pub type FamilyTotals = ((u64, u64, u64, u64), (u64, u64, u64, u64));

// ---------------------------------------------------------------------------
// FamilyStore: sharded map of infohash -> swarm, per IP family
// ---------------------------------------------------------------------------

/// Per-shard statistics snapshot (written by cleaner, read by stats API).
#[derive(Default)]
pub struct ShardStats {
    pub torrents: AtomicU64,
    pub peers: AtomicU64,
    pub seeders: AtomicU64,
    pub leechers: AtomicU64,
}

pub struct FamilyStore<S: Slot> {
    shards: Vec<RwLock<HashMap<InfoHash, RwLock<Swarm<S>>>>>,
    /// store_peer_id propagated to new swarms
    store_peer_id: bool,
    /// Per-shard stats slots, parallel to `shards`.
    shard_stats: Vec<ShardStats>,
    /// Global counters for this family.
    pub announces: AtomicU64,
    pub scrapes: AtomicU64,
    /// Live torrent count (incremented on create, decremented on clean-remove).
    pub torrents_live: AtomicU64,
    /// Cumulative torrents ever created.
    pub torrents_created: AtomicU64,
    /// Live peer accounting: added - removed == current peer count.
    pub peers_added: AtomicU64,
    pub peers_removed: AtomicU64,
    pub errors: AtomicU64,
}

impl<S: Slot> FamilyStore<S> {
    pub fn new(num_shards: usize, store_peer_id: bool) -> Self {
        // round up to power of two for masking
        let n = num_shards.next_power_of_two().max(1);
        Self {
            shards: (0..n)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            store_peer_id,
            shard_stats: (0..n).map(|_| ShardStats::default()).collect(),
            announces: AtomicU64::new(0),
            scrapes: AtomicU64::new(0),
            torrents_live: AtomicU64::new(0),
            torrents_created: AtomicU64::new(0),
            peers_added: AtomicU64::new(0),
            peers_removed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    #[inline]
    fn shard_index(&self, info_hash: &InfoHash) -> usize {
        // first 8 bytes of SHA1 infohash are uniform
        let x = u64::from_le_bytes(info_hash[..8].try_into().unwrap());
        (x as usize) & (self.shards.len() - 1)
    }

    pub fn num_shards(&self) -> usize {
        self.shards.len()
    }

    /// Announce on this family store. `ip` must match the family.
    /// Returns (seeders, leechers, added, removed) post-update, or None on family mismatch.
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        input: &AnnounceInput,
        now: u32,
        max_peer_age: u32,
        max_peers: usize,
        rng: &mut Rng,
        out: &mut Vec<PeerEndpoint>,
    ) -> Option<(u32, u32, bool, bool)> {
        if S::key_for(&input.ip, input.port).is_none() {
            return None;
        }
        let shard = &self.shards[self.shard_index(info_hash)];

        // Fast path: existing torrent — shared shard read lock throughout.
        let fast = {
            let r = shard.read();
            r.get(info_hash).map(|lock| {
                let mut swarm = lock.write();
                swarm.announce(input, now, max_peer_age, max_peers, rng, out)
            })
        };
        let res = match fast {
            Some(r) => Some(r),
            None => {
                // Slow path: create torrent — exclusive shard write lock (brief).
                let mut w = shard.write();
                match w.entry(*info_hash) {
                    hashbrown::hash_map::Entry::Occupied(e) => {
                        let mut swarm = e.get().write();
                        Some(swarm.announce(input, now, max_peer_age, max_peers, rng, out))
                    }
                    hashbrown::hash_map::Entry::Vacant(e) => {
                        self.torrents_live.fetch_add(1, Ordering::Relaxed);
                        self.torrents_created.fetch_add(1, Ordering::Relaxed);
                        let lock = e.insert(RwLock::new(Swarm::new(self.store_peer_id)));
                        let mut swarm = lock.write();
                        Some(swarm.announce(input, now, max_peer_age, max_peers, rng, out))
                    }
                }
            }
        };
        if let Some((_, _, added, removed)) = res {
            if added {
                self.peers_added.fetch_add(1, Ordering::Relaxed);
            }
            if removed {
                self.peers_removed.fetch_add(1, Ordering::Relaxed);
            }
        }
        res
    }

    /// Scrape stats for a list of info hashes. Returns (seeders, leechers) each.
    pub fn scrape(&self, info_hashes: &[[u8; 20]]) -> Vec<(u32, u32)> {
        let mut out = Vec::with_capacity(info_hashes.len());
        for hash in info_hashes {
            let shard = &self.shards[self.shard_index(hash)];
            let r = shard.read();
            if let Some(lock) = r.get(hash) {
                let swarm = lock.read();
                out.push(swarm.num_peers());
            } else {
                out.push((0, 0));
            }
        }
        out
    }

    /// Get peer_id for a (ip,port) on a torrent — stats API helper.
    pub fn peer_id_for(
        &self,
        info_hash: &InfoHash,
        ip: &IpAddr,
        port: u16,
    ) -> Option<PeerId> {
        let key = S::key_for(ip, port)?;
        let shard = &self.shards[self.shard_index(info_hash)];
        let r = shard.read();
        let lock = r.get(info_hash)?;
        let swarm = lock.read();
        swarm.peer_id_of(&key)
    }

    /// Clean one shard: expire peers, remove empty torrents, publish stats.
    /// Returns (peers_removed, torrents_removed).
    pub fn clean_shard(&self, shard_idx: usize, now: u32) -> (u64, u64) {
        let shard = &self.shards[shard_idx];
        let mut empty: Vec<InfoHash> = Vec::new();
        let mut peers_removed = 0u64;
        let mut torrents = 0u64;
        let mut peers = 0u64;
        let mut seeders = 0u64;

        // Phase 1: shared read lock — announces proceed concurrently;
        // only per-swarm write locks are taken briefly.
        {
            let r = shard.read();
            for (hash, lock) in r.iter() {
                let mut swarm = lock.write();
                peers_removed += swarm.clean(now) as u64;
                if swarm.is_empty() {
                    empty.push(*hash);
                } else {
                    torrents += 1;
                    let (s, l) = swarm.num_peers();
                    peers += (s + l) as u64;
                    seeders += s as u64;
                }
            }
        }

        // Phase 2: exclusive write lock — remove verified-empty torrents.
        let mut torrents_removed = 0u64;
        if !empty.is_empty() {
            let mut w = shard.write();
            for hash in empty {
                if let Some(lock) = w.get_mut(&hash) {
                    // &mut RwLock -> &mut Swarm; safe because shard.write()
                    // excludes all readers, so no swarm guard can be held.
                    let swarm = lock.get_mut();
                    if swarm.is_empty() {
                        w.remove(&hash);
                        torrents_removed += 1;
                    }
                }
            }
        }
        if torrents_removed > 0 {
            self.torrents_live
                .fetch_sub(torrents_removed, Ordering::Relaxed);
        }

        let stats = &self.shard_stats[shard_idx];
        stats.torrents.store(torrents, Ordering::Relaxed);
        stats.peers.store(peers, Ordering::Relaxed);
        stats.seeders.store(seeders, Ordering::Relaxed);
        stats.leechers.store(peers - seeders, Ordering::Relaxed);
        self.peers_removed.fetch_add(peers_removed, Ordering::Relaxed);

        (peers_removed, torrents_removed)
    }

    /// Totals: (torrents, peers, seeders, leechers).
    /// Torrents/peers are live atomics; seeders/leechers come from the
    /// per-shard stats refreshed by the last cleaning pass.
    pub fn totals(&self) -> (u64, u64, u64, u64) {
        let mut t = 0u64;
        let mut p = 0u64;
        let mut s = 0u64;
        let mut l = 0u64;
        t += self.torrents_live.load(Ordering::Relaxed);
        p += self
            .peers_added
            .load(Ordering::Relaxed)
            .saturating_sub(self.peers_removed.load(Ordering::Relaxed));
        for st in &self.shard_stats {
            s += st.seeders.load(Ordering::Relaxed);
            l += st.leechers.load(Ordering::Relaxed);
        }
        (t, p, s, l)
    }

    /// Iterate all torrents for scrape-export / top-N (read locks).
    /// `f` is called with (info_hash, seeders, leechers).
    pub fn for_each_torrent<F: FnMut(&InfoHash, u32, u32)>(&self, mut f: F) {
        for shard in &self.shards {
            let r = shard.read();
            for (hash, lock) in r.iter() {
                let swarm = lock.read();
                let (s, l) = swarm.num_peers();
                f(hash, s, l);
            }
        }
    }

    /// Find a swarm's peer list for the torrent-detail API.
    /// Returns (seeders, leechers, peers) where peers are (endpoint, seeder).
    pub fn torrent_peers(
        &self,
        info_hash: &InfoHash,
        max_peers: usize,
    ) -> Option<(u32, u32, Vec<(PeerEndpoint, bool)>)> {
        let shard = &self.shards[self.shard_index(info_hash)];
        let r = shard.read();
        let lock = r.get(info_hash)?;
        let swarm = lock.read();
        let (s, l) = swarm.num_peers();
        let mut out = Vec::with_capacity(max_peers.min(swarm.len()));
        // take-all path (want >= len handled inside)
        swarm.sample_for_api(max_peers, &mut out);
        Some((s, l, out))
    }

    /// Write every torrent + its peers for this family to `w`, each record
    /// prefixed with `tag` (SNAP_V4 / SNAP_V6). Peers are copied out under a
    /// brief read lock, then written without holding the swarm lock, so
    /// announces on that torrent are not blocked by file I/O.
    pub fn write_snapshot<W: std::io::Write>(
        &self,
        w: &mut W,
        tag: u8,
    ) -> std::io::Result<()> {
        let mut recs: Vec<PeerSnap> = Vec::new();
        for shard in &self.shards {
            let r = shard.read();
            for (hash, lock) in r.iter() {
                // Copy peers under the swarm read lock, release it, then write.
                let mut buf = std::mem::take(&mut recs);
                {
                    let swarm = lock.read();
                    swarm.peers_snapshot(&mut buf);
                }
                w.write_all(&[tag])?;
                w.write_all(hash)?;
                w.write_all(&(buf.len() as u32).to_le_bytes())?;
                for p in &buf {
                    match p.ip {
                        IpAddr::V4(v4) => w.write_all(&v4.octets())?,
                        IpAddr::V6(v6) => w.write_all(&v6.octets())?,
                    }
                    w.write_all(&p.port.to_le_bytes())?;
                    w.write_all(&[p.seeder as u8])?;
                    w.write_all(&p.valid_until.to_le_bytes())?;
                }
                recs = buf;
            }
        }
        Ok(())
    }

    /// Read one torrent record (tag already consumed) and restore its peers.
    /// `now` is used to skip peers that already expired while we were down.
    /// `ip_len` is 4 for the IPv4 store, 16 for IPv6.
    /// Returns (torrents_touched, peers_added).
    pub fn read_snapshot_torrent<R: std::io::Read>(
        &self,
        r: &mut R,
        now: u32,
        ip_len: usize,
    ) -> std::io::Result<(u64, u64)> {
        let mut hash = [0u8; 20];
        r.read_exact(&mut hash)?;
        let mut cb = [0u8; 4];
        r.read_exact(&mut cb)?;
        let count = u32::from_le_bytes(cb) as usize;
        // Restore into the correct shard; create the swarm if absent.
        let shard = &self.shards[self.shard_index(&hash)];
        let mut w = shard.write();
        let lock = match w.entry(hash) {
            hashbrown::hash_map::Entry::Occupied(e) => e.into_mut(),
            hashbrown::hash_map::Entry::Vacant(e) => {
                self.torrents_live.fetch_add(1, Ordering::Relaxed);
                self.torrents_created.fetch_add(1, Ordering::Relaxed);
                e.insert(RwLock::new(Swarm::new(self.store_peer_id)))
            }
        };
        let mut swarm = lock.write();
        // Pre-size for the incoming peer_count so inserts don't rehash.
        swarm.reserve_restore(count);
        let mut peers_added = 0u64;
        let mut ipbuf = [0u8; 16];
        for _ in 0..count {
            r.read_exact(&mut ipbuf[..ip_len])?;
            let ip = if ip_len == 4 {
                IpAddr::V4(Ipv4Addr::new(ipbuf[0], ipbuf[1], ipbuf[2], ipbuf[3]))
            } else {
                let mut o = [0u8; 16];
                o.copy_from_slice(&ipbuf[..16]);
                IpAddr::V6(Ipv6Addr::from(o))
            };
            let mut pb = [0u8; 2];
            r.read_exact(&mut pb)?;
            let port = u16::from_le_bytes(pb);
            let mut fb = [0u8; 1];
            r.read_exact(&mut fb)?;
            let seeder = fb[0] != 0;
            let mut vb = [0u8; 4];
            r.read_exact(&mut vb)?;
            let valid_until = u32::from_le_bytes(vb);
            if valid_until <= now {
                continue; // expired during downtime
            }
            if swarm.restore_peer(&ip, port, seeder, valid_until) {
                peers_added += 1;
            }
        }
        if peers_added > 0 {
            self.peers_added.fetch_add(peers_added, Ordering::Relaxed);
        }
        // If the swarm ended up empty (all peers expired), leave it; the
        // next clean pass will reclaim it.
        Ok((1, peers_added))
    }
}

// Helper on Swarm for the API path (sample without exclude, cap at len).
impl<S: Slot> Swarm<S> {
    fn sample_for_api(&self, max_peers: usize, out: &mut Vec<(PeerEndpoint, bool)>) {
        out.clear();
        if self.peers.is_empty() || max_peers == 0 {
            return;
        }
        // For an admin API, "first N" is acceptable and cheapest; peer order
        // is already arbitrary due to swap_remove churn.
        for p in self.peers.iter().take(max_peers) {
            out.push((p.endpoint(), p.is_seeder()));
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level store: both families + shared config
// ---------------------------------------------------------------------------

pub struct Store {
    pub v4: FamilyStore<Slot4>,
    pub v6: FamilyStore<Slot6>,
    pub peer_announce_interval: i32,
    pub max_peer_age: u32,
    pub max_response_peers: usize,
    pub store_peer_id: bool,
}

impl Store {
    pub fn new(
        num_shards: usize,
        store_peer_id: bool,
        peer_announce_interval: i32,
        max_peer_age: u32,
        max_response_peers: usize,
    ) -> Self {
        Self {
            v4: FamilyStore::new(num_shards, store_peer_id),
            v6: FamilyStore::new(num_shards, store_peer_id),
            peer_announce_interval,
            max_peer_age,
            max_response_peers,
            store_peer_id,
        }
    }

    /// Announce dispatch by source IP family. Returns (interval, seeders,
    /// leechers, added, removed) and fills `out` with peer endpoints.
    /// None on family/key mismatch.
    pub fn announce(
        &self,
        info_hash: &InfoHash,
        ip: IpAddr,
        port: u16,
        peer_id: PeerId,
        left: i64,
        event: AnnounceEvent,
        numwant: i32,
        now: u32,
        rng: &mut Rng,
        out: &mut Vec<PeerEndpoint>,
    ) -> Option<(i32, u32, u32, bool, bool)> {
        let input = AnnounceInput::new(ip, port, peer_id, left, event, numwant);
        let max_peers = if numwant <= 0 {
            self.max_response_peers
        } else {
            (numwant as usize).min(self.max_response_peers)
        };
        let res = match ip {
            IpAddr::V4(_) => self.v4.announce(
                info_hash,
                &input,
                now,
                self.max_peer_age,
                max_peers,
                rng,
                out,
            ),
            IpAddr::V6(_) => self.v6.announce(
                info_hash,
                &input,
                now,
                self.max_peer_age,
                max_peers,
                rng,
                out,
            ),
        };
        res.map(|(s, l, a, r)| (self.peer_announce_interval, s, l, a, r))
    }

    /// Scrape summed across both families.
    pub fn scrape(&self, info_hashes: &[[u8; 20]]) -> Vec<(u32, u32, u32)> {
        let a = self.v4.scrape(info_hashes);
        let b = self.v6.scrape(info_hashes);
        a.into_iter()
            .zip(b)
            .map(|((s4, l4), (s6, l6))| (s4 + s6, 0, l4 + l6))
            .collect()
    }

    /// Clean a slice of shards on both families. Used by cleaner threads.
    /// `shard_indices` are indices into each family's shard array.
    pub fn clean_shards(&self, shard_indices: &[usize], now: u32) -> (u64, u64) {
        let mut peers_removed = 0u64;
        let mut torrents_removed = 0u64;
        for &i in shard_indices {
            let (p, t) = self.v4.clean_shard(i, now);
            peers_removed += p;
            torrents_removed += t;
            let (p, t) = self.v6.clean_shard(i, now);
            peers_removed += p;
            torrents_removed += t;
        }
        (peers_removed, torrents_removed)
    }

    /// Cumulative torrents created across both families.
    pub fn torrents_created_total(&self) -> u64 {
        self.v4.torrents_created.load(Ordering::Relaxed)
            + self.v6.torrents_created.load(Ordering::Relaxed)
    }

    /// Totals across both families: (torrents, peers, seeders, leechers).
    pub fn totals(&self) -> (u64, u64, u64, u64) {
        let (t4, p4, s4, l4) = self.v4.totals();
        let (t6, p6, s6, l6) = self.v6.totals();
        (t4 + t6, p4 + p6, s4 + s6, l4 + l6)
    }

    /// Totals split by IP family: (v4 tuple, v6 tuple). Each tuple is
    /// (torrents, peers, seeders, leechers). Note torrents are counted
    /// per family store, so a dual-stack torrent appears in both.
    pub fn totals_by_family(&self) -> FamilyTotals {
        (self.v4.totals(), self.v6.totals())
    }

    /// Rough estimate of swarm-store heap bytes: dense peer slots + per-peer
    /// hash-index entries + per-torrent map/RwLock overhead + optional
    /// peer_id side table. Used for capacity observability; not exact
    /// (excludes Vec/HashMap capacity slack and allocator overhead).
    pub fn memory_estimate_bytes(&self) -> u64 {
        let (t4, p4, _, _) = self.v4.totals();
        let (t6, p6, _, _) = self.v6.totals();
        // Per peer: slot in the dense Vec + one entry in the swarm's
        // index HashMap (key + u32 slot index + 1B control, at hashbrown's
        // ~87.5% max load => x8/7). peer_ids adds key + 20B PeerId + ctrl.
        let key4 = std::mem::size_of::<u64>() as u64;
        let key6 = std::mem::size_of::<Key6>() as u64;
        let idx4 = (key4 + 4 + 1) * 8 / 7;
        let idx6 = (key6 + 4 + 1) * 8 / 7;
        let pid4 = (key4 + 20 + 1) * 8 / 7;
        let pid6 = (key6 + 20 + 1) * 8 / 7;
        let mut bytes = p4 * (std::mem::size_of::<Slot4>() as u64 + idx4)
            + p6 * (std::mem::size_of::<Slot6>() as u64 + idx6);
        // Per-torrent: InfoHash key + HashMap node + RwLock<Swarm> header.
        let torrent_overhead = (std::mem::size_of::<InfoHash>() + 232) as u64;
        bytes += (t4 + t6) * torrent_overhead;
        if self.store_peer_id {
            bytes += p4 * pid4 + p6 * pid6;
        }
        bytes
    }

    pub fn for_each_torrent<F: FnMut(&InfoHash, u32, u32)>(&self, mut f: F) {
        self.v4.for_each_torrent(&mut f);
        self.v6.for_each_torrent(f);
    }

    /// Look up a peer's id on a torrent (only when store_peer_id enabled).
    pub fn peer_id_for(&self, info_hash: &InfoHash, ip: &IpAddr, port: u16) -> Option<PeerId> {
        match ip {
            IpAddr::V4(_) => self.v4.peer_id_for(info_hash, ip, port),
            IpAddr::V6(_) => self.v6.peer_id_for(info_hash, ip, port),
        }
    }

    /// Per-torrent detail summed across families is not possible for peer
    /// lists (families are separate); return per-family instead.
    /// Peers are (endpoint, seeder) pairs.
    pub fn torrent_detail(
        &self,
        info_hash: &InfoHash,
        max_peers: usize,
    ) -> Option<(u32, u32, Vec<(PeerEndpoint, bool)>)> {
        // prefer whichever family has the torrent; if both, merge counts and
        // take peers from v4 first then v6
        let d4 = self.v4.torrent_peers(info_hash, max_peers);
        let d6 = self.v6.torrent_peers(info_hash, max_peers);
        match (d4, d6) {
            (Some((s4, l4, mut p4)), Some((s6, l6, p6))) => {
                p4.extend(p6);
                p4.truncate(max_peers);
                Some((s4 + s6, l4 + l6, p4))
            }
            (Some(d), None) | (None, Some(d)) => Some(d),
            (None, None) => None,
        }
    }

    // ---------------- snapshot / restore ----------------

    /// Snapshot file magic + format version.
    pub const SNAP_MAGIC: &[u8; 8] = b"TSNAPI01";
    pub const SNAP_V4: u8 = 1;
    pub const SNAP_V6: u8 = 2;
    pub const SNAP_END: u8 = 0;

    /// Write the full peer-state snapshot to `w` (already open for writing).
    /// Format: magic[8] | version u32 | created u64 | then tagged records
    /// (SNAP_V4/SNAP_V6 torrent records) terminated by SNAP_END.
    pub fn write_snapshot<W: std::io::Write>(&self, w: &mut W) -> std::io::Result<()> {
        let created = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        w.write_all(Self::SNAP_MAGIC)?;
        w.write_all(&1u32.to_le_bytes())?; // version
        w.write_all(&created.to_le_bytes())?;
        self.v4.write_snapshot(w, Self::SNAP_V4)?;
        self.v6.write_snapshot(w, Self::SNAP_V6)?;
        w.write_all(&[Self::SNAP_END])?;
        w.flush()?;
        Ok(())
    }

    /// Load a snapshot previously written by `write_snapshot`. Peers whose
    /// valid_until already passed are skipped. Returns (torrents, peers).
    pub fn load_snapshot<R: std::io::Read>(&self, r: &mut R) -> std::io::Result<(u64, u64)> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != Self::SNAP_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bad snapshot magic",
            ));
        }
        let mut vb = [0u8; 4];
        r.read_exact(&mut vb)?;
        let version = u32::from_le_bytes(vb);
        if version != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported snapshot version {version}"),
            ));
        }
        let mut cb = [0u8; 8];
        r.read_exact(&mut cb)?; // created timestamp (informational)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut torrents = 0u64;
        let mut peers = 0u64;
        loop {
            let mut tag = [0u8; 1];
            r.read_exact(&mut tag)?;
            match tag[0] {
                Self::SNAP_END => break,
                Self::SNAP_V4 => {
                    let (t, p) = self.v4.read_snapshot_torrent(r, now, 4)?;
                    torrents += t;
                    peers += p;
                }
                Self::SNAP_V6 => {
                    let (t, p) = self.v6.read_snapshot_torrent(r, now, 16)?;
                    torrents += t;
                    peers += p;
                }
                other => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("bad snapshot tag {other}"),
                    ))
                }
            }
        }
        Ok((torrents, peers))
    }

    /// All torrents' (info_hash, seeders, leechers) across both families —
    /// used by the HTTP full-scrape endpoint.
    pub fn all_scrape(&self) -> Vec<(InfoHash, u32, u32)> {
        let mut out = Vec::new();
        self.v4.for_each_torrent(|h, s, l| out.push((*h, s, l)));
        self.v6.for_each_torrent(|h, s, l| out.push((*h, s, l)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip() {
        let store = Store::new(16, false, 900, 1800, 50);
        let mut rng = Rng::new();
        let mut out = Vec::new();
        let hash: InfoHash = [7u8; 20];
        // `now` far in the future so restored peers aren't seen as expired.
        let now = 4_000_000_000u32;
        for i in 0..10u16 {
            store.announce(
                &hash,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8 + 1)),
                5000 + i,
                [1u8; 20],
                100,
                AnnounceEvent::Started,
                50,
                now,
                &mut rng,
                &mut out,
            );
        }
        // one seeder (left == 0)
        store.announce(
            &hash,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)),
            6000,
            [2u8; 20],
            0,
            AnnounceEvent::Started,
            50,
            now,
            &mut rng,
            &mut out,
        );
        let before = store.totals();
        assert_eq!(before.1, 11);

        let mut buf = Vec::new();
        store.write_snapshot(&mut buf).unwrap();

        let store2 = Store::new(16, false, 900, 1800, 50);
        let mut cur = std::io::Cursor::new(&buf);
        let (t, p) = store2.load_snapshot(&mut cur).unwrap();
        let after = store2.totals();
        assert_eq!(t, 1);
        assert_eq!(p, 11);
        assert_eq!(after, before);
        // scrape parity between original and restored store
        assert_eq!(store.scrape(&[hash]), store2.scrape(&[hash]));
    }

    #[test]
    fn snapshot_skips_expired() {
        let store = Store::new(8, false, 900, 1800, 50);
        let mut rng = Rng::new();
        let mut out = Vec::new();
        let hash: InfoHash = [9u8; 20];
        // announce with valid_until already in the past relative to load-time `now`
        store.announce(
            &hash,
            IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)),
            4000,
            [3u8; 20],
            100,
            AnnounceEvent::Started,
            50,
            1000, // now=1000 -> valid_until=2800 (long past)
            &mut rng,
            &mut out,
        );
        let mut buf = Vec::new();
        store.write_snapshot(&mut buf).unwrap();
        let store2 = Store::new(8, false, 900, 1800, 50);
        let mut cur = std::io::Cursor::new(&buf);
        let (_t, p) = store2.load_snapshot(&mut cur).unwrap();
        assert_eq!(p, 0); // expired peer skipped
    }
}
