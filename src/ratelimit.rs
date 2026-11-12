//! Per-worker token-bucket rate limiting for DoS shedding.
//!
//! Two independent buckets — one for announce requests (the expensive
//! store-mutating path) and one for scrape requests. Connects and parse
//! failures are not limited (they're cheap and are the client's handshake).
//!
//! Rates are configured per socket worker; the effective global ceiling is
//! `rate × socket_workers`. A bucket with rate 0 is unlimited.

use std::time::Instant;

/// A simple token bucket. `rate` tokens/sec, capacity = rate × burst_secs.
struct Bucket {
    tokens: f64,
    rate: f64,   // tokens per second; <= 0 means unlimited
    cap: f64,    // max burst capacity
    last: Instant,
}

impl Bucket {
    fn new(rate_per_sec: f64, burst: f64) -> Self {
        let cap = (rate_per_sec * burst).max(1.0);
        Self {
            tokens: cap,
            rate: rate_per_sec,
            cap,
            last: Instant::now(),
        }
    }

    #[inline]
    fn allow(&mut self) -> bool {
        if self.rate <= 0.0 {
            return true; // unlimited
        }
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Holds the announce + scrape buckets for one worker.
pub struct RateLimiter {
    announce: Bucket,
    scrape: Bucket,
}

impl RateLimiter {
    /// `announce_per_sec` / `scrape_per_sec` are per-worker rates (0 = off).
    /// `burst` is the bucket capacity as a multiple of the per-second rate.
    pub fn new(announce_per_sec: u64, scrape_per_sec: u64, burst: f64) -> Self {
        Self {
            announce: Bucket::new(announce_per_sec as f64, burst),
            scrape: Bucket::new(scrape_per_sec as f64, burst),
        }
    }

    /// Unlimited limiter (rate limiting disabled).
    pub fn unlimited() -> Self {
        Self::new(0, 0, 1.0)
    }

    #[inline]
    pub fn allow_announce(&mut self) -> bool {
        self.announce.allow()
    }

    #[inline]
    pub fn allow_scrape(&mut self) -> bool {
        self.scrape.allow()
    }
}

// ---------------------------------------------------------------------------
// Per-IP connect limiting
// ---------------------------------------------------------------------------
//
// BEP-15 connect packets carry no peer_id, so signature filters can't catch
// connect floods. Legit clients connect rarely (conn_id is per-IP and lives
// for max_connection_age), while a flooder handshakes continuously. This
// limiter is shared across all socket workers — SO_REUSEPORT spreads one
// IP's source ports over every worker, so per-worker state would be bypassed.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Idle entries are evicted after this long without a connect attempt.
const IP_BUCKET_IDLE: std::time::Duration = std::time::Duration::from_secs(120);
const SHARDS: usize = 128;

struct IpBucket {
    tokens: f32,
    /// Last allow() call — doubles as token-refill base and idle timestamp.
    last: Instant,
}

struct Shard {
    map: HashMap<IpAddr, IpBucket>,
    last_sweep: Instant,
}

/// Global per-IP token bucket for connect requests. Rate is tokens/sec;
/// capacity is `rate × burst_secs` so a burst of connects is absorbed then
/// throttled to the sustained rate. `rate <= 0` disables limiting.
pub struct IpConnectLimiter {
    shards: Vec<Mutex<Shard>>,
    rate: f32,
    cap: f32,
}

impl IpConnectLimiter {
    pub fn new(rate_per_sec: f64, burst_secs: f64) -> Arc<Self> {
        let rate = rate_per_sec.max(0.0) as f32;
        let cap = (rate * burst_secs.max(1.0) as f32).max(1.0);
        Arc::new(Self {
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        map: HashMap::new(),
                        last_sweep: Instant::now(),
                    })
                })
                .collect(),
            rate,
            cap,
        })
    }

    #[inline]
    fn shard_for(ip: &IpAddr) -> usize {
        // FxHash-style mix: cheap and well distributed for IPv4/IPv6 octets.
        let mut h: u64 = match ip {
            IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u64,
            IpAddr::V6(v6) => {
                let o = v6.octets();
                u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                    ^ u64::from_be_bytes([o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]])
                        .rotate_left(17)
            }
        };
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51afd7ed558ccd);
        h ^= h >> 33;
        (h % SHARDS as u64) as usize
    }

    /// Returns true if this IP may connect now (consumes a token).
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.rate <= 0.0 {
            return true;
        }
        let now = Instant::now();
        let shard = &mut *self.shards[Self::shard_for(&ip)].lock().unwrap();

        // Amortized sweep: at most once per 30s per shard, drop buckets
        // idle longer than IP_BUCKET_IDLE so the map stays bounded.
        if shard.last_sweep.elapsed() > std::time::Duration::from_secs(30) {
            shard.last_sweep = now;
            if shard.map.len() > 1024 {
                shard
                    .map
                    .retain(|_, b| now.duration_since(b.last) < IP_BUCKET_IDLE);
            }
        }

        let map = &mut shard.map;
        let b = map.entry(ip).or_insert(IpBucket {
            tokens: self.cap,
            last: now,
        });
        let dt = now.duration_since(b.last).as_secs_f32();
        b.last = now;
        b.tokens = (b.tokens + dt * self.rate).min(self.cap);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    #[test]
    fn per_ip_connect_bucket() {
        // rate 10/s, burst 1s -> cap 10
        let lim = IpConnectLimiter::new(10.0, 1.0);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // full burst passes
        for _ in 0..10 {
            assert!(lim.allow(ip));
        }
        // bucket drained -> rejected
        assert!(!lim.allow(ip));
        // after ~150ms ~1.5 tokens refill -> one passes
        sleep(std::time::Duration::from_millis(150));
        assert!(lim.allow(ip));
        assert!(!lim.allow(ip));
    }

    #[test]
    fn per_ip_independent_and_disabled() {
        let lim = IpConnectLimiter::new(1.0, 1.0);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(lim.allow(a));
        assert!(!lim.allow(a)); // a drained
        assert!(lim.allow(b)); // b independent

        let off = IpConnectLimiter::new(0.0, 1.0);
        for _ in 0..1000 {
            assert!(off.allow(a));
        }
    }
}
