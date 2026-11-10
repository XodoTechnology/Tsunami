//! Stateless connection-id creation/validation (anti-amplification).
//!
//! connection_id = [elapsed_secs u32][truncated keyed-BLAKE3 hash u32] as i64.
//! The hash covers elapsed + client IP, so ids can't be forged for other IPs
//! and expire after `max_age` seconds.

use std::net::IpAddr;
use std::time::Instant;

use constant_time_eq::constant_time_eq;

pub struct Validator {
    key: [u8; 32],
    hasher: blake3::Hasher,
    start: Instant,
    max_age_secs: u64,
}

impl Validator {
    pub fn new(max_age_secs: u64) -> Self {
        let mut key = [0u8; 32];
        let _ = getrandom::fill(&mut key);
        let hasher = blake3::Hasher::new_keyed(&key);
        Self {
            key,
            hasher,
            start: Instant::now(),
            max_age_secs,
        }
    }

    /// Cheap per-worker clone sharing the same key.
    pub fn for_worker(&self) -> Self {
        Self {
            key: self.key,
            hasher: blake3::Hasher::new_keyed(&self.key),
            start: self.start,
            max_age_secs: self.max_age_secs,
        }
    }

    #[inline]
    fn now_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }

    pub fn create(&mut self, ip: IpAddr) -> i64 {
        let elapsed = self.now_secs() as u32;
        let hash = self.hash(elapsed, ip);
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&elapsed.to_be_bytes());
        b[4..].copy_from_slice(&hash);
        i64::from_be_bytes(b)
    }

    pub fn valid(&mut self, ip: IpAddr, connection_id: i64) -> bool {
        let b = connection_id.to_be_bytes();
        let elapsed = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let expected = self.hash(elapsed, ip);
        if !constant_time_eq(&b[4..8], &expected) {
            return false;
        }
        let now = self.now_secs();
        let client_elapsed = elapsed as u64;
        let not_expired = client_elapsed + self.max_age_secs > now;
        let not_far_future = client_elapsed <= now.saturating_add(60);
        not_expired && not_far_future
    }

    fn hash(&mut self, elapsed: u32, ip: IpAddr) -> [u8; 4] {
        self.hasher.reset();
        self.hasher.update(&elapsed.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                self.hasher.update(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.hasher.update(&v6.octets());
            }
        }
        let mut out = [0u8; 4];
        self.hasher.finalize_xof().fill(&mut out);
        out
    }
}
