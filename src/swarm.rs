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
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use hashbrown::{HashMap, HashTable};
use parking_lot::{RwLock, RwLockWriteGuard};

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

pub trait Slot: Clone + Send + Sync + 'static {
    type Key: Copy + Eq + Hash + Send + Sync + 'static;

    /// Identity key for (ip, port). None if ip family doesn't match.
    fn key_for(ip: &IpAddr, port: u16) -> Option<Self::Key>;
    /// Fast 64-bit hash of `Key` for index table probing.
    fn hash_key(key: &Self::Key) -> u64;
    /// Construct a slot. Caller guarantees ip family matches.
    fn new_slot(ip: &IpAddr, port: u16, seeder: bool, valid_until: u32) -> Self;

    fn key(&self) -> Self::Key;
    fn is_seeder(&self) -> bool;
    fn set_seeder(&mut self, seeder: bool);
    fn is_paused(&self) -> bool;
    fn set_paused(&mut self, paused: bool);
    fn valid_until(&self) -> u32;
    fn set_valid_until(&mut self, t: u32);
    fn refresh_valid_until(&self, t: u32);
    fn endpoint(&self) -> PeerEndpoint;
}

const SEEDER_FLAG: u8 = 1;
const PAUSED_FLAG: u8 = 2;

#[inline]
fn mix64(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// IPv4 peer slot — 12 bytes.
#[repr(C)]
pub struct Slot4 {
    ip: u32, // u32::from(Ipv4Addr) canonical form
    port: u16,
    flags: u8,
    _pad: u8,
    valid_until: AtomicU32,
}

impl Clone for Slot4 {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            ip: self.ip,
            port: self.port,
            flags: self.flags,
            _pad: self._pad,
            valid_until: AtomicU32::new(self.valid_until.load(Ordering::Relaxed)),
        }
    }
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
    fn hash_key(key: &u64) -> u64 {
        mix64(*key)
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
            valid_until: AtomicU32::new(valid_until),
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
    fn is_paused(&self) -> bool {
        self.flags & PAUSED_FLAG != 0
    }
    #[inline]
    fn set_paused(&mut self, paused: bool) {
        if paused {
            self.flags |= PAUSED_FLAG;
        } else {
            self.flags &= !PAUSED_FLAG;
        }
    }
    #[inline]
    fn valid_until(&self) -> u32 {
        self.valid_until.load(Ordering::Relaxed)
    }
    #[inline]
    fn set_valid_until(&mut self, t: u32) {
        *self.valid_until.get_mut() = t;
    }
    #[inline]
    fn refresh_valid_until(&self, t: u32) {
        if self.valid_until.load(Ordering::Relaxed) != t {
            self.valid_until.store(t, Ordering::Relaxed);
        }
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
#[repr(C)]
pub struct Slot6 {
    ip: [u8; 16],
    port: u16,
    flags: u8,
    _pad: u8,
    valid_until: AtomicU32,
}

impl Clone for Slot6 {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            ip: self.ip,
            port: self.port,
            flags: self.flags,
            _pad: self._pad,
            valid_until: AtomicU32::new(self.valid_until.load(Ordering::Relaxed)),
        }
    }
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
    fn hash_key(key: &Key6) -> u64 {
        let a = u64::from_ne_bytes(key.ip[0..8].try_into().unwrap());
        let b = u64::from_ne_bytes(key.ip[8..16].try_into().unwrap());
        let c = key.port as u64;
        mix64(a.wrapping_mul(0x9E3779B97F4A7C15) ^ b.rotate_left(23) ^ c)
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
            valid_until: AtomicU32::new(valid_until),
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
    fn is_paused(&self) -> bool {
        self.flags & PAUSED_FLAG != 0
    }
    #[inline]
    fn set_paused(&mut self, paused: bool) {
        if paused {
            self.flags |= PAUSED_FLAG;
        } else {
            self.flags &= !PAUSED_FLAG;
        }
    }
    #[inline]
    fn valid_until(&self) -> u32 {
        self.valid_until.load(Ordering::Relaxed)
    }
    #[inline]
    fn set_valid_until(&mut self, t: u32) {
        *self.valid_until.get_mut() = t;
    }
    #[inline]
    fn refresh_valid_until(&self, t: u32) {
        if self.valid_until.load(Ordering::Relaxed) != t {
            self.valid_until.store(t, Ordering::Relaxed);
        }
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
    /// BEP-21: peer stays in the swarm and keeps its expiry refreshed, but is
    /// counted as incomplete while excluded from downloader statistics.
    Paused,
}

impl AnnounceEvent {
    #[inline]
    pub fn from_wire(v: i32) -> Self {
        match v {
            1 => Self::Completed,
            2 => Self::Started,
            3 => Self::Stopped,
            4 => Self::Paused,
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

/// Peers stored inline before spilling to a heap `Vec<S>`.
/// 2 IPv4 slots = 24 bytes (exact size of a Vec header), eliminating all
/// per-swarm heap allocations for 1- and 2-peer torrents.
const INLINE_CAP: usize = 2;

/// Swarms up to this size use linear scan over contiguous slots instead of
/// allocating a `HashTable<u32>` index (8 slots = 96B = 1.5 cache lines).
const INDEX_THRESHOLD: usize = 8;

enum PeerVec<S: Slot> {
    Inline {
        len: u8,
        slots: [MaybeUninit<S>; INLINE_CAP],
    },
    Heap(Vec<S>),
}

impl<S: Slot> PeerVec<S> {
    #[inline]
    fn new() -> Self {
        Self::Inline {
            len: 0,
            slots: [const { MaybeUninit::uninit() }; INLINE_CAP],
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len as usize,
            Self::Heap(v) => v.len(),
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    fn as_slice(&self) -> &[S] {
        match self {
            Self::Inline { len, slots } => unsafe {
                std::slice::from_raw_parts(slots.as_ptr() as *const S, *len as usize)
            },
            Self::Heap(v) => v.as_slice(),
        }
    }

    #[inline]
    fn as_mut_slice(&mut self) -> &mut [S] {
        match self {
            Self::Inline { len, slots } => unsafe {
                std::slice::from_raw_parts_mut(slots.as_mut_ptr() as *mut S, *len as usize)
            },
            Self::Heap(v) => v.as_mut_slice(),
        }
    }

    #[inline]
    fn push(&mut self, val: S) {
        match self {
            Self::Inline { len, slots } => {
                let l = *len as usize;
                if l < INLINE_CAP {
                    slots[l].write(val);
                    *len = (l + 1) as u8;
                } else {
                    let mut v = Vec::with_capacity(4);
                    for s in slots.iter() {
                        v.push(unsafe { s.assume_init_read() });
                    }
                    v.push(val);
                    *self = Self::Heap(v);
                }
            }
            Self::Heap(v) => v.push(val),
        }
    }

    #[inline]
    fn swap_remove(&mut self, index: usize) -> S {
        match self {
            Self::Inline { len, slots } => {
                let l = *len as usize;
                debug_assert!(index < l);
                *len = (l - 1) as u8;
                let removed = unsafe { slots[index].assume_init_read() };
                if index != l - 1 {
                    slots[index] = unsafe { std::ptr::read(&slots[l - 1]) };
                }
                removed
            }
            Self::Heap(v) => v.swap_remove(index),
        }
    }

    fn reserve(&mut self, additional: usize) {
        let needed = self.len().saturating_add(additional);
        if needed <= INLINE_CAP {
            return;
        }
        match self {
            Self::Inline { len, slots } => {
                let l = *len as usize;
                let mut v = Vec::with_capacity(needed);
                for s in &slots[..l] {
                    v.push(unsafe { s.assume_init_read() });
                }
                *self = Self::Heap(v);
            }
            Self::Heap(v) => v.reserve(additional),
        }
    }

    fn shrink_if_sparse(&mut self) {
        if let Self::Heap(v) = self {
            if v.len() <= INLINE_CAP {
                let mut slots = [const { MaybeUninit::uninit() }; INLINE_CAP];
                let l = v.len();
                for (i, item) in v.drain(..).enumerate() {
                    slots[i].write(item);
                }
                *self = Self::Inline {
                    len: l as u8,
                    slots,
                };
            } else if v.capacity() > 32 && v.capacity() > v.len() * 4 {
                v.shrink_to(v.len().max(4));
            }
        }
    }
}

pub struct Swarm<S: Slot> {
    peers: PeerVec<S>,
    /// Lazy index table storing only `u32` slot indices (4B/entry instead of
    /// duplicating `S::Key` in every bucket). `None` for swarms <= INDEX_THRESHOLD.
    index: Option<Box<HashTable<u32>>>,
    /// Optional peer_id side table (only populated when store_peer_id enabled).
    /// Used for HTTP compact=0 peer_id echo and per-torrent peer detail API.
    peer_ids: Option<Box<HashMap<S::Key, PeerId>>>,
    seeders: u32,
    /// Lower bound on `valid_until` across all peers in this swarm (`u32::MAX`
    /// when empty). Lets the cleaner skip unexpired swarms in O(1) under a
    /// shared read lock without scanning `peers`.
    min_valid_until: u32,
}

impl<S: Slot> Swarm<S> {
    pub fn new(store_peer_id: bool) -> Self {
        Self {
            peers: PeerVec::new(),
            index: None,
            peer_ids: store_peer_id.then(|| Box::new(HashMap::new())),
            seeders: 0,
            min_valid_until: u32::MAX,
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

    /// BEP-21 downloader count: leechers that are not paused. O(n) over the
    /// swarm's peers — only called from scrape paths, which are rare and
    /// bounded by max_scrape_torrents.
    pub fn downloaders(&self) -> u32 {
        self.peers
            .as_slice()
            .iter()
            .filter(|p| !p.is_seeder() && !p.is_paused())
            .count() as u32
    }

    #[inline]
    pub fn needs_clean(&self, now: u32) -> bool {
        self.peers.is_empty() || self.min_valid_until <= now
    }

    #[inline]
    fn find_slot(&self, key: &S::Key) -> Option<u32> {
        let peers = self.peers.as_slice();
        match &self.index {
            Some(idx) => {
                let h = S::hash_key(key);
                idx.find(h, |&slot| peers[slot as usize].key() == *key)
                    .copied()
            }
            None => peers.iter().position(|p| p.key() == *key).map(|i| i as u32),
        }
    }

    #[inline]
    fn insert_slot(&mut self, new_slot: S) -> usize {
        let key = new_slot.key();
        let exp = new_slot.valid_until();
        if exp < self.min_valid_until {
            self.min_valid_until = exp;
        }
        let slot = self.peers.len();
        self.peers.push(new_slot);
        let new_len = self.peers.len();
        if let Some(idx) = self.index.as_mut() {
            let peers = self.peers.as_slice();
            idx.insert_unique(S::hash_key(&key), slot as u32, |&s| {
                S::hash_key(&peers[s as usize].key())
            });
        } else if new_len > INDEX_THRESHOLD {
            let peers = self.peers.as_slice();
            let mut idx = Box::new(HashTable::with_capacity(new_len * 2));
            for (i, p) in peers.iter().enumerate() {
                let k = p.key();
                idx.insert_unique(S::hash_key(&k), i as u32, |&s| {
                    S::hash_key(&peers[s as usize].key())
                });
            }
            self.index = Some(idx);
        }
        slot
    }

    /// Fast read-only announce path for existing peers whose seeder state has
    /// not changed. Runs entirely under the swarm's shared `RwLock::read()`
    /// guard, refreshing `valid_until` atomically and sampling peers without
    /// serializing concurrent workers on the same torrent.
    #[inline]
    pub fn try_announce_read(
        &self,
        input: &AnnounceInput,
        key: &S::Key,
        now: u32,
        max_peer_age: u32,
        max_peers: usize,
        rng: &mut Rng,
        out: &mut Vec<PeerEndpoint>,
    ) -> Option<(u32, u32, bool, bool)> {
        if input.event == AnnounceEvent::Stopped
            || input.event == AnnounceEvent::Paused
            || self.peer_ids.is_some()
        {
            return None;
        }
        let slot = self.find_slot(key)? as usize;
        let is_seeder = input.left == 0;
        let peers = self.peers.as_slice();
        let s = &peers[slot];
        if s.is_seeder() != is_seeder || s.is_paused() {
            return None;
        }
        s.refresh_valid_until(now.wrapping_add(max_peer_age));
        out.clear();
        let (seeders, leechers) = self.num_peers();
        let want = max_peers + 1;
        self.sample_peers(want, Some(slot), rng, out);
        out.truncate(max_peers);
        Some((seeders, leechers, false, false))
    }

    /// Mutating part of an announce (insert, remove, or seeder-flag flip).
    /// Returns `(self_slot, added, removed)`; caller may downgrade the write
    /// lock to a shared read lock before calling `sample_peers`.
    #[inline]
    fn announce_mutate(
        &mut self,
        input: &AnnounceInput,
        key: S::Key,
        now: u32,
        max_peer_age: u32,
    ) -> (Option<usize>, bool, bool) {
        let is_stopped = input.event == AnnounceEvent::Stopped;
        let is_seeder = !is_stopped && input.left == 0;
        let paused = input.event == AnnounceEvent::Paused && !is_seeder;
        let existing = self.find_slot(&key);
        let mut added = false;
        let mut removed = false;
        let mut self_slot: Option<usize> = None;

        if is_stopped {
            if let Some(slot) = existing {
                self.remove_at(slot as usize);
                removed = true;
            }
        } else {
            let exp = now.wrapping_add(max_peer_age);
            match existing {
                Some(slot) => {
                    let peers = self.peers.as_mut_slice();
                    let len = peers.len();
                    let s = &mut peers[slot as usize];
                    let was_seeder = s.is_seeder();
                    s.set_seeder(is_seeder);
                    s.set_paused(paused);
                    s.set_valid_until(exp);
                    if len == 1 {
                        self.min_valid_until = exp;
                    }
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
                    let mut slot = S::new_slot(&input.ip, input.port, is_seeder, exp);
                    slot.set_paused(paused);
                    let slot = self.insert_slot(slot);
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
        (self_slot, added, removed)
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
            let (s, l) = self.num_peers();
            return (s, l, false, false);
        };

        let (self_slot, added, removed) = self.announce_mutate(input, key, now, max_peer_age);
        let (seeders, leechers) = self.num_peers();

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
        let peers = self.peers.as_slice();
        let len = peers.len();
        if len == 0 || want == 0 {
            return;
        }
        let want = want.min(len);

        if want >= len {
            for (i, p) in peers.iter().enumerate() {
                if Some(i) != exclude {
                    out.push(p.endpoint());
                }
            }
            return;
        }

        // Bucket sizes differ by at most one; boundaries are cumulative so
        // the loop needs no division per bucket.
        let q = len / want;
        let r = len % want;
        let mut start = 0usize;
        for b in 0..want {
            let end = (start + q + usize::from(b < r)).min(len);
            if start >= end {
                break;
            }
            let mut idx = start + rng.below(end - start);
            if Some(idx) == exclude {
                if idx + 1 < end {
                    idx += 1;
                } else if idx > start {
                    idx -= 1;
                } else {
                    start = end;
                    continue; // single-element bucket holding only self
                }
            }
            out.push(peers[idx].endpoint());
            start = end;
        }
    }

    /// Remove peer at `slot` via swap_remove, fixing the moved element's index.
    fn remove_at(&mut self, slot: usize) {
        let removed = self.peers.swap_remove(slot);
        let new_len = self.peers.len();
        if new_len <= INDEX_THRESHOLD / 2 {
            self.index = None;
        } else if let Some(idx) = self.index.as_mut() {
            let removed_key = removed.key();
            if let Ok(entry) = idx.find_entry(S::hash_key(&removed_key), |&s| s == slot as u32) {
                entry.remove();
            }
            if slot < new_len {
                let moved_key = self.peers.as_slice()[slot].key();
                let old_slot = new_len as u32;
                if let Some(e) = idx.find_mut(S::hash_key(&moved_key), |&s| s == old_slot) {
                    *e = slot as u32;
                }
            }
        }
        if let Some(m) = self.peer_ids.as_mut() {
            let removed_key = removed.key();
            m.remove(&removed_key);
        }
        if removed.is_seeder() {
            self.seeders -= 1;
        }
        if new_len == 0 {
            self.min_valid_until = u32::MAX;
        }
    }

    /// Expire peers whose valid_until has passed. Returns number removed.
    /// O(n) with index fixups only for removed/moved peers; O(1) when
    /// `min_valid_until > now`.
    pub fn clean(&mut self, now: u32) -> usize {
        if !self.peers.is_empty() && self.min_valid_until > now {
            return 0;
        }
        let mut removed = 0usize;
        let mut next_min = u32::MAX;
        let mut i = self.peers.len();
        while i > 0 {
            i -= 1;
            let v = self.peers.as_slice()[i].valid_until();
            if v <= now {
                self.remove_at(i);
                removed += 1;
            } else if v < next_min {
                next_min = v;
            }
        }
        self.min_valid_until = next_min;
        if removed > 0 {
            self.peers.shrink_if_sparse();
            if let Some(idx) = self.index.as_mut() {
                let len = self.peers.len();
                if idx.capacity() > 32 && idx.capacity() > len * 4 {
                    let peers = self.peers.as_slice();
                    idx.shrink_to(len.max(INDEX_THRESHOLD + 1), |&s| {
                        S::hash_key(&peers[s as usize].key())
                    });
                }
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
        let peers = self.peers.as_slice();
        out.reserve(peers.len());
        for p in peers {
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
        let total = self.peers.len().saturating_add(additional);
        if total > INDEX_THRESHOLD {
            match self.index.as_mut() {
                Some(idx) => {
                    let peers = self.peers.as_slice();
                    idx.reserve(additional, |&s| S::hash_key(&peers[s as usize].key()));
                }
                None => {
                    let peers = self.peers.as_slice();
                    let mut idx = Box::new(HashTable::with_capacity(total));
                    for (i, p) in peers.iter().enumerate() {
                        let k = p.key();
                        idx.insert_unique(S::hash_key(&k), i as u32, |&s| {
                            S::hash_key(&peers[s as usize].key())
                        });
                    }
                    self.index = Some(idx);
                }
            }
        }
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
        if self.find_slot(&key).is_some() {
            return false;
        }
        self.insert_slot(S::new_slot(ip, port, seeder, valid_until));
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

/// Cache-line padded shard RwLock to prevent false sharing between workers
/// locking adjacent shards.
#[repr(align(64))]
struct AlignedShard<S: Slot>(RwLock<HashMap<InfoHash, RwLock<Swarm<S>>>>);

impl<S: Slot> std::ops::Deref for AlignedShard<S> {
    type Target = RwLock<HashMap<InfoHash, RwLock<Swarm<S>>>>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Per-shard statistics snapshot (written by cleaner, read by stats API).
#[derive(Default)]
pub struct ShardStats {
    pub torrents: AtomicU64,
    pub peers: AtomicU64,
    pub seeders: AtomicU64,
    pub leechers: AtomicU64,
}

pub struct FamilyStore<S: Slot> {
    shards: Vec<AlignedShard<S>>,
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
                .map(|_| AlignedShard(RwLock::new(HashMap::new())))
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
        // Mix all 20 bytes so both uniform SHA1s and synthetic/sequential
        // hashes (e.g. benchmark hashes varying only in bytes 0..4) spread
        // evenly across all shards.
        let a = u64::from_ne_bytes(info_hash[0..8].try_into().unwrap());
        let b = u64::from_ne_bytes(info_hash[8..16].try_into().unwrap());
        let c = u32::from_ne_bytes(info_hash[16..20].try_into().unwrap()) as u64;
        let h = (a ^ b.rotate_left(29) ^ c).wrapping_mul(0x9E3779B97F4A7C15);
        ((h >> 32) as usize ^ (h as usize)) & (self.shards.len() - 1)
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
        let key = S::key_for(&input.ip, input.port)?;
        let shard = &self.shards[self.shard_index(info_hash)];

        // Fast path: existing torrent — shared shard read lock throughout.
        let fast = {
            let r = shard.read();
            if let Some(lock) = r.get(info_hash) {
                if input.event != AnnounceEvent::Stopped && !self.store_peer_id {
                    let swarm = lock.read();
                    if let Some(res) = swarm.try_announce_read(
                        input,
                        &key,
                        now,
                        max_peer_age,
                        max_peers,
                        rng,
                        out,
                    ) {
                        return Some(res);
                    }
                }
                let mut swarm = lock.write();
                let (self_slot, added, removed) =
                    swarm.announce_mutate(input, key, now, max_peer_age);
                let swarm = RwLockWriteGuard::downgrade(swarm);
                out.clear();
                let (seeders, leechers) = swarm.num_peers();
                let want = max_peers + self_slot.is_some() as usize;
                swarm.sample_peers(want, self_slot, rng, out);
                out.truncate(max_peers);
                Some((seeders, leechers, added, removed))
            } else if input.event == AnnounceEvent::Stopped {
                out.clear();
                return Some((0, 0, false, false));
            } else {
                None
            }
        };
        let res = match fast {
            Some(r) => Some(r),
            None => {
                // Slow path: create torrent — exclusive shard write lock (brief).
                let mut w = shard.write();
                let lock = match w.entry(*info_hash) {
                    hashbrown::hash_map::Entry::Occupied(e) => e.into_mut(),
                    hashbrown::hash_map::Entry::Vacant(e) => {
                        self.torrents_live.fetch_add(1, Ordering::Relaxed);
                        self.torrents_created.fetch_add(1, Ordering::Relaxed);
                        e.insert(RwLock::new(Swarm::new(self.store_peer_id)))
                    }
                };
                let mut swarm = lock.write();
                let (self_slot, added, removed) =
                    swarm.announce_mutate(input, key, now, max_peer_age);
                let (seeders, leechers) = swarm.num_peers();
                out.clear();
                let want = max_peers + self_slot.is_some() as usize;
                swarm.sample_peers(want, self_slot, rng, out);
                out.truncate(max_peers);
                Some((seeders, leechers, added, removed))
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

    /// Scrape stats for a list of info hashes. Returns (seeders, leechers,
    /// downloaders) each.
    pub fn scrape(&self, info_hashes: &[[u8; 20]]) -> Vec<(u32, u32, u32)> {
        let mut out = Vec::with_capacity(info_hashes.len());
        for hash in info_hashes {
            let shard = &self.shards[self.shard_index(hash)];
            let r = shard.read();
            if let Some(lock) = r.get(hash) {
                let swarm = lock.read();
                let (s, l) = swarm.num_peers();
                out.push((s, l, swarm.downloaders()));
            } else {
                out.push((0, 0, 0));
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
        // unexpired swarms are skipped under a shared swarm read lock without
        // taking a swarm write lock or touching the peer slice.
        {
            let r = shard.read();
            for (hash, lock) in r.iter() {
                {
                    let swarm = lock.read();
                    if !swarm.needs_clean(now) {
                        torrents += 1;
                        let (s, l) = swarm.num_peers();
                        peers += (s + l) as u64;
                        seeders += s as u64;
                        continue;
                    }
                }
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

        // Phase 2: exclusive write lock — remove verified-empty torrents in
        // bounded chunks so a large wave of expirations never holds the shard
        // write lock long enough to stall announces.
        let mut torrents_removed = 0u64;
        for chunk in empty.chunks(512) {
            let mut w = shard.write();
            for hash in chunk {
                if let Some(lock) = w.get_mut(hash) {
                    let swarm = lock.get_mut();
                    if swarm.is_empty() {
                        w.remove(hash);
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

    /// Like `for_each_torrent` but also reports BEP-21 downloader counts;
    /// walks every peer, so reserve for rare full-scrape use.
    fn for_each_torrent_full(&self, out: &mut Vec<(InfoHash, u32, u32, u32)>) {
        for shard in &self.shards {
            let r = shard.read();
            for (hash, lock) in r.iter() {
                let swarm = lock.read();
                let (s, l) = swarm.num_peers();
                out.push((*hash, s, l, swarm.downloaders()));
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
        let peers = self.peers.as_slice();
        if peers.is_empty() || max_peers == 0 {
            return;
        }
        // For an admin API, "first N" is acceptable and cheapest; peer order
        // is already arbitrary due to swap_remove churn.
        for p in peers.iter().take(max_peers) {
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
    pub announce_jitter_secs: u32,
    pub max_peer_age: u32,
    pub max_response_peers: usize,
    pub store_peer_id: bool,
}

impl Store {
    pub fn new(
        num_shards: usize,
        store_peer_id: bool,
        peer_announce_interval: i32,
        announce_jitter_secs: u32,
        max_peer_age: u32,
        max_response_peers: usize,
    ) -> Self {
        Self {
            v4: FamilyStore::new(num_shards, store_peer_id),
            v6: FamilyStore::new(num_shards, store_peer_id),
            peer_announce_interval,
            announce_jitter_secs,
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
        res.map(|(s, l, a, r)| {
            let interval = if self.announce_jitter_secs > 0 {
                let span = (self.announce_jitter_secs * 2 + 1) as usize;
                let delta = rng.below(span) as i32 - self.announce_jitter_secs as i32;
                (self.peer_announce_interval + delta).max(30)
            } else {
                self.peer_announce_interval
            };
            (interval, s, l, a, r)
        })
    }

    /// Scrape summed across both families. Returns (seeders, downloaded,
    /// leechers, downloaders) per hash — `downloaded` is always 0 (untracked).
    pub fn scrape(&self, info_hashes: &[[u8; 20]]) -> Vec<(u32, u32, u32, u32)> {
        let a = self.v4.scrape(info_hashes);
        let b = self.v6.scrape(info_hashes);
        a.into_iter()
            .zip(b)
            .map(|((s4, l4, d4), (s6, l6, d6))| (s4 + s6, 0, l4 + l6, d4 + d6))
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
        // Per peer: slot in the dense Vec + one 4B u32 entry in the swarm's
        // HashTable<u32> index (u32 slot index + 1B control, at hashbrown's
        // ~87.5% max load => x8/7; 0 for swarms <= INDEX_THRESHOLD).
        let idx_entry = (4 + 1) * 8 / 7;
        let key4 = std::mem::size_of::<u64>() as u64;
        let key6 = std::mem::size_of::<Key6>() as u64;
        let pid4 = (key4 + 20 + 1) * 8 / 7;
        let pid6 = (key6 + 20 + 1) * 8 / 7;
        let mut bytes = p4 * (std::mem::size_of::<Slot4>() as u64 + idx_entry)
            + p6 * (std::mem::size_of::<Slot6>() as u64 + idx_entry);
        // Per-torrent: InfoHash key + RwLock<Swarm> header + control byte.
        let torrent_overhead4 = (std::mem::size_of::<InfoHash>()
            + std::mem::size_of::<RwLock<Swarm<Slot4>>>()
            + 8) as u64;
        let torrent_overhead6 = (std::mem::size_of::<InfoHash>()
            + std::mem::size_of::<RwLock<Swarm<Slot6>>>()
            + 8) as u64;
        bytes += t4 * torrent_overhead4 + t6 * torrent_overhead6;
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
    /// used by the HTTP full-scrape endpoint. Includes BEP-21 downloader
    /// counts, so it walks every peer — only for the rare full scrape.
    pub fn all_scrape(&self) -> Vec<(InfoHash, u32, u32, u32)> {
        let mut out = Vec::new();
        self.v4.for_each_torrent_full(&mut out);
        self.v6.for_each_torrent_full(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_roundtrip() {
        let store = Store::new(16, false, 900, 0, 1800, 50);
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

        let store2 = Store::new(16, false, 900, 0, 1800, 50);
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
        let store = Store::new(8, false, 900, 0, 1800, 50);
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
        let store2 = Store::new(8, false, 900, 0, 1800, 50);
        let mut cur = std::io::Cursor::new(&buf);
        let (_t, p) = store2.load_snapshot(&mut cur).unwrap();
        assert_eq!(p, 0); // expired peer skipped
    }

    #[test]
    fn swarm_compact_layout_and_transitions() {
        assert!(std::mem::size_of::<Swarm<Slot4>>() <= 56);
        assert!(std::mem::size_of::<RwLock<Swarm<Slot4>>>() <= 64);

        let mut swarm = Swarm::<Slot4>::new(false);
        let mut rng = Rng::new();
        let mut out = Vec::new();

        // 1..=INLINE_CAP stay inline with no index
        for i in 1..=INLINE_CAP {
            let input = AnnounceInput::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                6881,
                [0u8; 20],
                if i == 1 { 0 } else { 100 },
                AnnounceEvent::Started,
                50,
            );
            swarm.announce(&input, 1000, 1800, 50, &mut rng, &mut out);
        }
        assert!(matches!(swarm.peers, PeerVec::Inline { .. }));
        assert!(swarm.index.is_none());
        assert_eq!(swarm.num_peers(), (1, (INLINE_CAP - 1) as u32));

        // 3..=INDEX_THRESHOLD spill to Heap Vec but still no index HashTable
        for i in (INLINE_CAP + 1)..=INDEX_THRESHOLD {
            let input = AnnounceInput::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                6881,
                [0u8; 20],
                100,
                AnnounceEvent::Started,
                50,
            );
            swarm.announce(&input, 1000, 1800, 50, &mut rng, &mut out);
        }
        assert!(matches!(swarm.peers, PeerVec::Heap(_)));
        assert!(swarm.index.is_none());
        assert_eq!(swarm.len(), INDEX_THRESHOLD);

        // > INDEX_THRESHOLD builds the HashTable<u32> index
        for i in (INDEX_THRESHOLD + 1)..=20 {
            let input = AnnounceInput::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                6881,
                [0u8; 20],
                100,
                AnnounceEvent::Started,
                50,
            );
            swarm.announce(&input, 2000, 1800, 50, &mut rng, &mut out);
        }
        assert!(swarm.index.is_some());
        assert_eq!(swarm.len(), 20);

        // Expire first 19 peers -> shrinks back to Inline and drops index
        let expired_input = AnnounceInput::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20)),
            6881,
            [0u8; 20],
            0,
            AnnounceEvent::Completed,
            50,
        );
        swarm.announce(&expired_input, 5000, 1800, 50, &mut rng, &mut out);
        let removed = swarm.clean(4000);
        assert_eq!(removed, 19);
        assert_eq!(swarm.len(), 1);
        assert!(matches!(swarm.peers, PeerVec::Inline { .. }));
        assert!(swarm.index.is_none());
        assert_eq!(swarm.num_peers(), (1, 0));
    }

    #[test]
    fn sequential_hashes_spread_across_shards() {
        let store = FamilyStore::<Slot4>::new(256, false);
        let mut counts = vec![0usize; 256];
        for t in 0..500u32 {
            let mut h = [0x42u8; 20];
            h[0..4].copy_from_slice(&t.to_be_bytes());
            counts[store.shard_index(&h)] += 1;
        }
        let non_empty = counts.iter().filter(|&&c| c > 0).count();
        assert!(non_empty > 200, "expected spread across shards, got {non_empty}/256");
    }
}
