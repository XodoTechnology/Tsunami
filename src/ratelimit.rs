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
