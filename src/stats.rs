//! Global statistics: atomics updated by workers, JSON snapshot for the
//! HTTP stats API, Prometheus exposition, and a per-second time series
//! feeding both windowed rates and the dashboard graphs.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::swarm::FamilyTotals;

#[derive(Default)]
pub struct ProtoStats {
    pub requests: AtomicU64,
    pub connects: AtomicU64,
    pub announces: AtomicU64,
    pub scrapes: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub dropped: AtomicU64,      // responses dropped (no send buffer)
    pub rate_limited: AtomicU64, // requests shed by the rate limiter
    pub blocked: AtomicU64,      // requests rejected by abuse filters
    // Announce lifecycle events (BEP-15/3 `event` field). Regular announces
    // (event=None) are `announces - (started+completed+stopped)`.
    pub ev_started: AtomicU64,
    pub ev_completed: AtomicU64,
    pub ev_stopped: AtomicU64,
}

impl ProtoStats {
    #[inline]
    pub fn add(&self, other: &ProtoStats) {
        self.requests
            .fetch_add(other.requests.load(Ordering::Relaxed), Ordering::Relaxed);
        self.connects
            .fetch_add(other.connects.load(Ordering::Relaxed), Ordering::Relaxed);
        self.announces
            .fetch_add(other.announces.load(Ordering::Relaxed), Ordering::Relaxed);
        self.scrapes
            .fetch_add(other.scrapes.load(Ordering::Relaxed), Ordering::Relaxed);
        self.errors
            .fetch_add(other.errors.load(Ordering::Relaxed), Ordering::Relaxed);
        self.bytes_rx
            .fetch_add(other.bytes_rx.load(Ordering::Relaxed), Ordering::Relaxed);
        self.bytes_tx
            .fetch_add(other.bytes_tx.load(Ordering::Relaxed), Ordering::Relaxed);
        self.dropped
            .fetch_add(other.dropped.load(Ordering::Relaxed), Ordering::Relaxed);
        self.rate_limited
            .fetch_add(other.rate_limited.load(Ordering::Relaxed), Ordering::Relaxed);
        self.blocked
            .fetch_add(other.blocked.load(Ordering::Relaxed), Ordering::Relaxed);
        self.ev_started
            .fetch_add(other.ev_started.load(Ordering::Relaxed), Ordering::Relaxed);
        self.ev_completed
            .fetch_add(other.ev_completed.load(Ordering::Relaxed), Ordering::Relaxed);
        self.ev_stopped
            .fetch_add(other.ev_stopped.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// Striping for client stats to reduce lock contention.
const CLIENT_STRIPES: usize = 64;

/// BEP 20 client signature = first 8 bytes of peer_id.
pub type ClientKey = [u8; 8];

pub struct ClientStats {
    stripes: Vec<Mutex<std::collections::HashMap<ClientKey, u64>>>,
    /// peer_id prefixes excluded from stats (e.g. loadgen's "-TS").
    ignore: std::sync::OnceLock<Vec<Vec<u8>>>,
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            stripes: (0..CLIENT_STRIPES)
                .map(|_| Mutex::new(std::collections::HashMap::new()))
                .collect(),
            ignore: std::sync::OnceLock::new(),
        }
    }

    /// Exclude peer_ids starting with any of these prefixes from stats.
    /// Call once at startup before traffic flows.
    pub fn set_ignore_prefixes(&self, prefixes: Vec<String>) {
        let v: Vec<Vec<u8>> = prefixes.into_iter().map(String::into_bytes).collect();
        let _ = self.ignore.set(v);
    }

    /// Record an announce for a peer client, keyed by the 8-byte client
    /// signature at the start of peer_id.
    #[inline]
    pub fn record(&self, peer_id: &[u8; 20]) {
        if let Some(ign) = self.ignore.get() {
            if ign.iter().any(|p| peer_id.as_slice().starts_with(p.as_slice())) {
                return;
            }
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&peer_id[..8]);
        let stripe = (key[0] as usize ^ ((key[1] as usize) << 4)) & (CLIENT_STRIPES - 1);
        let mut m = self.stripes[stripe].lock().unwrap();
        *m.entry(key).or_insert(0) += 1;
    }

    /// Top clients by announce count.
    pub fn top(&self, n: usize) -> Vec<(ClientKey, u64)> {
        let mut all: Vec<(ClientKey, u64)> = Vec::new();
        for stripe in &self.stripes {
            let m = stripe.lock().unwrap();
            all.extend(m.iter().map(|(&k, &v)| (k, v)));
        }
        all.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        all.truncate(n);
        all
    }
}

/// Gauge values gathered by the sampler thread each tick (swarm totals come
/// from the store; system values from /proc). Passed into push_rate_sample.
#[derive(Clone, Copy, Default)]
pub struct GaugeInput {
    pub torrents: u64,
    pub peers: u64,
    pub seeders: u64,
    pub leechers: u64,
    pub rss_bytes: u64,
    /// Estimated swarm-store heap bytes.
    pub swarm_bytes: u64,
    /// CPU utilisation in percent * 10 (one decimal) since last sample.
    pub cpu_percent_x10: u64,
}

/// One point-in-time reading recorded once per second. Holds cumulative
/// protocol counters plus instantaneous gauges so a single ring serves both
/// windowed rates and the dashboard time series.
#[derive(Clone, Copy, Default)]
pub struct RateSample {
    pub ts_ms: u64,
    // Combined cumulative counters.
    pub requests: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    // Per-protocol cumulative counters.
    pub udp4_requests: u64,
    pub udp6_requests: u64,
    pub http_requests: u64,
    pub udp4_bytes_rx: u64,
    pub udp6_bytes_rx: u64,
    pub http_bytes_rx: u64,
    pub udp4_bytes_tx: u64,
    pub udp6_bytes_tx: u64,
    pub http_bytes_tx: u64,
    // Per-protocol cumulative action counters (for per-second action rates:
    // announces/connects/scrapes/errors — what external stats consumers need
    // to match classic tracker stat pages).
    pub udp4_announces: u64,
    pub udp4_connects: u64,
    pub udp4_scrapes: u64,
    pub udp4_errors: u64,
    pub udp4_blocked: u64,
    pub udp6_announces: u64,
    pub udp6_connects: u64,
    pub udp6_scrapes: u64,
    pub udp6_errors: u64,
    pub udp6_blocked: u64,
    pub http_announces: u64,
    pub http_connects: u64,
    pub http_scrapes: u64,
    pub http_errors: u64,
    pub http_blocked: u64,
    // Swarm gauges (instantaneous).
    pub torrents: u64,
    pub peers: u64,
    pub seeders: u64,
    pub leechers: u64,
    // Cumulative churn counters.
    pub peers_added: u64,
    pub peers_removed: u64,
    // System gauges.
    pub rss_bytes: u64,
    pub swarm_bytes: u64,
    pub cpu_percent_x10: u64,
}

/// How often the sampler thread records a point (drives ring density).
pub const RATE_SAMPLE_MS: u64 = 1_000;
/// How long the ring retains samples. 1h at 1s resolution is ~3600 points —
/// plenty for live graphs; long-term trending is what Prometheus is for.
const RATE_RING_MS: u64 = 3_600_000;
/// Hard cap on retained samples (guards against clock weirdness).
const RATE_RING_MAX: usize = 4096;
/// Trailing window over which per-second rates are computed.
const RATE_WINDOW_MS: u64 = 10_000;

pub struct Stats {
    pub started: Instant,
    pub udp_ipv4: ProtoStats,
    pub udp_ipv6: ProtoStats,
    pub http: ProtoStats,
    /// Peers added/removed totals (all protocols).
    pub peers_added: AtomicU64,
    pub peers_removed: AtomicU64,
    /// Active HTTP connections.
    pub http_connections: AtomicU64,
    /// io_uring completions dropped due to CQ-ring overflow (UDP backend).
    /// Each drop can leak a provided-buffer id; the worker rebuilds the ring.
    pub cqe_overflow: AtomicU64,
    /// Latest system gauges (updated by the sampler thread).
    pub rss_bytes: AtomicU64,
    pub cpu_percent_x10: AtomicU64,
    pub client_stats: ClientStats,
    /// Ring of per-second samples feeding windowed rates and /api/timeseries.
    /// Fed by a dedicated sampler thread so every consumer sees the SAME
    /// window regardless of poll timing.
    rate_samples: Mutex<VecDeque<RateSample>>,
}

/// Per-protocol rate set.
#[derive(Clone, Copy, Default)]
pub struct ProtoRate {
    pub requests_per_sec: u64,
    pub bytes_rx_per_sec: u64,
    pub bytes_tx_per_sec: u64,
    pub announces_per_sec: u64,
    pub connects_per_sec: u64,
    pub scrapes_per_sec: u64,
    pub errors_per_sec: u64,
    pub blocked_per_sec: u64,
}

/// Windowed rates over a fixed trailing window, combined + per-protocol.
#[derive(Clone, Copy, Default)]
pub struct Rates {
    pub requests_per_sec: u64,
    pub bytes_rx_per_sec: u64,
    pub bytes_tx_per_sec: u64,
    pub udp4: ProtoRate,
    pub udp6: ProtoRate,
    pub http: ProtoRate,
    pub peers_added_per_sec: u64,
    pub peers_removed_per_sec: u64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            started: Instant::now(),
            udp_ipv4: ProtoStats::default(),
            udp_ipv6: ProtoStats::default(),
            http: ProtoStats::default(),
            peers_added: AtomicU64::new(0),
            peers_removed: AtomicU64::new(0),
            http_connections: AtomicU64::new(0),
            cqe_overflow: AtomicU64::new(0),
            rss_bytes: AtomicU64::new(0),
            cpu_percent_x10: AtomicU64::new(0),
            client_stats: ClientStats::new(),
            rate_samples: Mutex::new(VecDeque::with_capacity(
                (RATE_RING_MS / RATE_SAMPLE_MS) as usize + 2,
            )),
        })
    }

    /// Record the current cumulative counters + gauges into the rate ring.
    /// Called by the sampler thread once per RATE_SAMPLE_MS.
    pub fn push_rate_sample(&self, gauges: &GaugeInput) {
        self.rss_bytes.store(gauges.rss_bytes, Ordering::Relaxed);
        self.cpu_percent_x10
            .store(gauges.cpu_percent_x10, Ordering::Relaxed);

        let ts_ms = self.started.elapsed().as_millis() as u64;
        let sample = RateSample {
            ts_ms,
            requests: self.total_requests(),
            bytes_rx: self.total_bytes_rx(),
            bytes_tx: self.total_bytes_tx(),
            udp4_requests: self.udp_ipv4.requests.load(Ordering::Relaxed),
            udp6_requests: self.udp_ipv6.requests.load(Ordering::Relaxed),
            http_requests: self.http.requests.load(Ordering::Relaxed),
            udp4_bytes_rx: self.udp_ipv4.bytes_rx.load(Ordering::Relaxed),
            udp6_bytes_rx: self.udp_ipv6.bytes_rx.load(Ordering::Relaxed),
            http_bytes_rx: self.http.bytes_rx.load(Ordering::Relaxed),
            udp4_bytes_tx: self.udp_ipv4.bytes_tx.load(Ordering::Relaxed),
            udp6_bytes_tx: self.udp_ipv6.bytes_tx.load(Ordering::Relaxed),
            http_bytes_tx: self.http.bytes_tx.load(Ordering::Relaxed),
            udp4_announces: self.udp_ipv4.announces.load(Ordering::Relaxed),
            udp4_connects: self.udp_ipv4.connects.load(Ordering::Relaxed),
            udp4_scrapes: self.udp_ipv4.scrapes.load(Ordering::Relaxed),
            udp4_errors: self.udp_ipv4.errors.load(Ordering::Relaxed),
            udp4_blocked: self.udp_ipv4.blocked.load(Ordering::Relaxed),
            udp6_announces: self.udp_ipv6.announces.load(Ordering::Relaxed),
            udp6_connects: self.udp_ipv6.connects.load(Ordering::Relaxed),
            udp6_scrapes: self.udp_ipv6.scrapes.load(Ordering::Relaxed),
            udp6_errors: self.udp_ipv6.errors.load(Ordering::Relaxed),
            udp6_blocked: self.udp_ipv6.blocked.load(Ordering::Relaxed),
            http_announces: self.http.announces.load(Ordering::Relaxed),
            http_connects: self.http.connects.load(Ordering::Relaxed),
            http_scrapes: self.http.scrapes.load(Ordering::Relaxed),
            http_errors: self.http.errors.load(Ordering::Relaxed),
            http_blocked: self.http.blocked.load(Ordering::Relaxed),
            torrents: gauges.torrents,
            peers: gauges.peers,
            seeders: gauges.seeders,
            leechers: gauges.leechers,
            peers_added: self.peers_added.load(Ordering::Relaxed),
            peers_removed: self.peers_removed.load(Ordering::Relaxed),
            rss_bytes: gauges.rss_bytes,
            swarm_bytes: gauges.swarm_bytes,
            cpu_percent_x10: gauges.cpu_percent_x10,
        };
        let mut q = self.rate_samples.lock().unwrap();
        q.push_back(sample);
        // Evict samples older than the ring horizon (and enforce a hard cap).
        while let Some(&front) = q.front() {
            if ts_ms.saturating_sub(front.ts_ms) > RATE_RING_MS || q.len() > RATE_RING_MAX {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// Borrow the rate ring for timeseries export. Caller holds the lock only
    /// for the duration of the copy.
    pub fn with_samples<R>(&self, f: impl FnOnce(&VecDeque<RateSample>) -> R) -> R {
        let q = self.rate_samples.lock().unwrap();
        f(&q)
    }

    /// Windowed rates over a fixed trailing window (requests, rx B/s, tx B/s
    /// — combined and per-protocol, plus peer churn). Read-only: the rate is
    /// (now - sample@window-ago) / window, so every consumer sees the same
    /// value regardless of poll order.
    fn compute_rates(&self) -> Rates {
        let now_ms = self.started.elapsed().as_millis() as u64;
        let q = self.rate_samples.lock().unwrap();
        // Newest sample at or before the window start is the rate baseline.
        let target = now_ms.saturating_sub(RATE_WINDOW_MS);
        let base = q
            .iter()
            .rev()
            .find(|s| s.ts_ms <= target)
            .or_else(|| q.front())
            .copied();

        let dt_ms = match base {
            Some(b) => now_ms.saturating_sub(b.ts_ms).max(1),
            // No samples yet (first second after boot): rate since start.
            None => now_ms.max(1),
        };
        let dt = dt_ms as f64 / 1000.0;
        let per = |now: u64, then: u64| -> u64 {
            ((now.saturating_sub(then)) as f64 / dt) as u64
        };

        let (b_req, b_rx, b_tx, b_padd, b_prem) = match base {
            Some(b) => (b.requests, b.bytes_rx, b.bytes_tx, b.peers_added, b.peers_removed),
            None => (0, 0, 0, 0, 0),
        };
        let (u4r, u6r, hr) = match base {
            Some(b) => (b.udp4_requests, b.udp6_requests, b.http_requests),
            None => (0, 0, 0),
        };
        let (u4rx, u6rx, hrx) = match base {
            Some(b) => (b.udp4_bytes_rx, b.udp6_bytes_rx, b.http_bytes_rx),
            None => (0, 0, 0),
        };
        let (u4tx, u6tx, htx) = match base {
            Some(b) => (b.udp4_bytes_tx, b.udp6_bytes_tx, b.http_bytes_tx),
            None => (0, 0, 0),
        };
        // Action counters: (announces, connects, scrapes, errors, blocked) per proto.
        let (u4an, u4cn, u4sn, u4en, u4bn) = match base {
            Some(b) => (
                b.udp4_announces,
                b.udp4_connects,
                b.udp4_scrapes,
                b.udp4_errors,
                b.udp4_blocked,
            ),
            None => (0, 0, 0, 0, 0),
        };
        let (u6an, u6cn, u6sn, u6en, u6bn) = match base {
            Some(b) => (
                b.udp6_announces,
                b.udp6_connects,
                b.udp6_scrapes,
                b.udp6_errors,
                b.udp6_blocked,
            ),
            None => (0, 0, 0, 0, 0),
        };
        let (han, hcn, hsn, hen, hbn) = match base {
            Some(b) => (
                b.http_announces,
                b.http_connects,
                b.http_scrapes,
                b.http_errors,
                b.http_blocked,
            ),
            None => (0, 0, 0, 0, 0),
        };

        Rates {
            requests_per_sec: per(self.total_requests(), b_req),
            bytes_rx_per_sec: per(self.total_bytes_rx(), b_rx),
            bytes_tx_per_sec: per(self.total_bytes_tx(), b_tx),
            udp4: ProtoRate {
                requests_per_sec: per(self.udp_ipv4.requests.load(Ordering::Relaxed), u4r),
                bytes_rx_per_sec: per(self.udp_ipv4.bytes_rx.load(Ordering::Relaxed), u4rx),
                bytes_tx_per_sec: per(self.udp_ipv4.bytes_tx.load(Ordering::Relaxed), u4tx),
                announces_per_sec: per(self.udp_ipv4.announces.load(Ordering::Relaxed), u4an),
                connects_per_sec: per(self.udp_ipv4.connects.load(Ordering::Relaxed), u4cn),
                scrapes_per_sec: per(self.udp_ipv4.scrapes.load(Ordering::Relaxed), u4sn),
                errors_per_sec: per(self.udp_ipv4.errors.load(Ordering::Relaxed), u4en),
                blocked_per_sec: per(self.udp_ipv4.blocked.load(Ordering::Relaxed), u4bn),
            },
            udp6: ProtoRate {
                requests_per_sec: per(self.udp_ipv6.requests.load(Ordering::Relaxed), u6r),
                bytes_rx_per_sec: per(self.udp_ipv6.bytes_rx.load(Ordering::Relaxed), u6rx),
                bytes_tx_per_sec: per(self.udp_ipv6.bytes_tx.load(Ordering::Relaxed), u6tx),
                announces_per_sec: per(self.udp_ipv6.announces.load(Ordering::Relaxed), u6an),
                connects_per_sec: per(self.udp_ipv6.connects.load(Ordering::Relaxed), u6cn),
                scrapes_per_sec: per(self.udp_ipv6.scrapes.load(Ordering::Relaxed), u6sn),
                errors_per_sec: per(self.udp_ipv6.errors.load(Ordering::Relaxed), u6en),
                blocked_per_sec: per(self.udp_ipv6.blocked.load(Ordering::Relaxed), u6bn),
            },
            http: ProtoRate {
                requests_per_sec: per(self.http.requests.load(Ordering::Relaxed), hr),
                bytes_rx_per_sec: per(self.http.bytes_rx.load(Ordering::Relaxed), hrx),
                bytes_tx_per_sec: per(self.http.bytes_tx.load(Ordering::Relaxed), htx),
                announces_per_sec: per(self.http.announces.load(Ordering::Relaxed), han),
                connects_per_sec: per(self.http.connects.load(Ordering::Relaxed), hcn),
                scrapes_per_sec: per(self.http.scrapes.load(Ordering::Relaxed), hsn),
                errors_per_sec: per(self.http.errors.load(Ordering::Relaxed), hen),
                blocked_per_sec: per(self.http.blocked.load(Ordering::Relaxed), hbn),
            },
            peers_added_per_sec: per(self.peers_added.load(Ordering::Relaxed), b_padd),
            peers_removed_per_sec: per(self.peers_removed.load(Ordering::Relaxed), b_prem),
        }
    }

    /// JSON-serializable snapshot for /api/stats.
    /// `family_totals` = per-IP-family (torrents, peers, seeders, leechers);
    /// `swarm_bytes` = estimated swarm-store memory.
    pub fn snapshot_json(
        &self,
        family_totals: FamilyTotals,
        torrents_created: u64,
        swarm_bytes: u64,
        version: &str,
    ) -> serde_json::Value {
        let uptime = self.started.elapsed().as_secs();
        let ((t4, p4, s4, l4), (t6, p6, s6, l6)) = family_totals;
        let (torrents, peers, seeders, leechers) =
            (t4 + t6, p4 + p6, s4 + s6, l4 + l6);
        let rates = self.compute_rates();

        let clients = self.client_stats.top(20);
        let client_list: Vec<serde_json::Value> = clients
            .iter()
            .map(|&(k, c)| {
                serde_json::json!({ "client": crate::peerid::client_name(&k), "announces": c })
            })
            .collect();

        serde_json::json!({
            "version": version,
            "uptime_seconds": uptime,
            "rates": {
                "requests_per_sec": rates.requests_per_sec,
                "bytes_rx_per_sec": rates.bytes_rx_per_sec,
                "bytes_tx_per_sec": rates.bytes_tx_per_sec,
                "peers_added_per_sec": rates.peers_added_per_sec,
                "peers_removed_per_sec": rates.peers_removed_per_sec,
                "udp_ipv4": proto_rate_json(&rates.udp4),
                "udp_ipv6": proto_rate_json(&rates.udp6),
                "http": proto_rate_json(&rates.http),
            },
            "udp": {
                "ipv4": proto_json(&self.udp_ipv4),
                "ipv6": proto_json(&self.udp_ipv6),
            },
            "http": proto_json(&self.http),
            "swarm": {
                "torrents": torrents,
                "peers": peers,
                "seeders": seeders,
                "leechers": leechers,
                "ipv4": { "torrents": t4, "peers": p4, "seeders": s4, "leechers": l4 },
                "ipv6": { "torrents": t6, "peers": p6, "seeders": s6, "leechers": l6 },
                "peers_added_total": self.peers_added.load(Ordering::Relaxed),
                "peers_removed_total": self.peers_removed.load(Ordering::Relaxed),
                "torrents_created_total": torrents_created,
            },
            "system": {
                "rss_bytes": self.rss_bytes.load(Ordering::Relaxed),
                "cpu_percent": self.cpu_percent_x10.load(Ordering::Relaxed) as f64 / 10.0,
                "swarm_estimate_bytes": swarm_bytes,
            },
            "http_connections": self.http_connections.load(Ordering::Relaxed),
            "cqe_overflow_total": self.cqe_overflow.load(Ordering::Relaxed),
            "top_clients": client_list,
        })
    }

    /// Time series for /api/timeseries. `seconds` = lookback window;
    /// samples are the 1s ring points within it (most recent last).
    pub fn timeseries_json(&self, seconds: u64) -> serde_json::Value {
        let now_ms = self.started.elapsed().as_millis() as u64;
        let cutoff = now_ms.saturating_sub(seconds.saturating_mul(1000));
        let samples = self.with_samples(|q| {
            q.iter()
                .filter(|s| s.ts_ms >= cutoff)
                .map(|s| {
                    serde_json::json!({
                        "t": s.ts_ms / 1000,
                        "requests": s.requests,
                        "bytes_rx": s.bytes_rx,
                        "bytes_tx": s.bytes_tx,
                        "udp4_requests": s.udp4_requests,
                        "udp6_requests": s.udp6_requests,
                        "http_requests": s.http_requests,
                        "udp4_bytes_rx": s.udp4_bytes_rx,
                        "udp6_bytes_rx": s.udp6_bytes_rx,
                        "http_bytes_rx": s.http_bytes_rx,
                        "udp4_bytes_tx": s.udp4_bytes_tx,
                        "udp6_bytes_tx": s.udp6_bytes_tx,
                        "http_bytes_tx": s.http_bytes_tx,
                        "udp4_blocked": s.udp4_blocked,
                        "udp6_blocked": s.udp6_blocked,
                        "http_blocked": s.http_blocked,
                        "torrents": s.torrents,
                        "peers": s.peers,
                        "seeders": s.seeders,
                        "leechers": s.leechers,
                        "peers_added": s.peers_added,
                        "peers_removed": s.peers_removed,
                        "rss_bytes": s.rss_bytes,
                        "swarm_bytes": s.swarm_bytes,
                        "cpu_percent": s.cpu_percent_x10 as f64 / 10.0,
                    })
                })
                .collect::<Vec<_>>()
        });
        serde_json::json!({ "seconds": seconds, "samples": samples })
    }

    /// Every scalar stat as (dotted-key, formatted-value) pairs — shared by
    /// the CSV and key=value exporters so the formats can never drift apart.
    /// Non-scalar data (top_clients, per-torrent lists) has its own endpoints.
    fn flat_stats(
        &self,
        family_totals: FamilyTotals,
        torrents_created: u64,
        swarm_bytes: u64,
        version: &str,
    ) -> Vec<(String, String)> {
        let uptime = self.started.elapsed().as_secs();
        let ((t4, p4, s4, l4), (t6, p6, s6, l6)) = family_totals;
        let (torrents, peers, seeders, leechers) =
            (t4 + t6, p4 + p6, s4 + s6, l4 + l6);
        let rates = self.compute_rates();
        let mut out: Vec<(String, String)> = Vec::with_capacity(80);
        macro_rules! put {
            ($k:expr, $v:expr) => {
                out.push(($k.to_string(), $v.to_string()))
            };
        }
        put!("meta.version", version);
        put!("meta.uptime_seconds", uptime);
        // Windowed rates (fixed 10s trailing window).
        put!("rates.requests_per_sec", rates.requests_per_sec);
        put!("rates.bytes_rx_per_sec", rates.bytes_rx_per_sec);
        put!("rates.bytes_tx_per_sec", rates.bytes_tx_per_sec);
        put!("rates.peers_added_per_sec", rates.peers_added_per_sec);
        put!("rates.peers_removed_per_sec", rates.peers_removed_per_sec);
        for (name, r) in [
            ("udp_ipv4", rates.udp4),
            ("udp_ipv6", rates.udp6),
            ("http", rates.http),
        ] {
            put!(&format!("rates.{name}.requests_per_sec"), r.requests_per_sec);
            put!(&format!("rates.{name}.bytes_rx_per_sec"), r.bytes_rx_per_sec);
            put!(&format!("rates.{name}.bytes_tx_per_sec"), r.bytes_tx_per_sec);
            put!(&format!("rates.{name}.announces_per_sec"), r.announces_per_sec);
            put!(&format!("rates.{name}.connects_per_sec"), r.connects_per_sec);
            put!(&format!("rates.{name}.scrapes_per_sec"), r.scrapes_per_sec);
            put!(&format!("rates.{name}.errors_per_sec"), r.errors_per_sec);
            put!(&format!("rates.{name}.blocked_per_sec"), r.blocked_per_sec);
        }
        // Per-protocol cumulative counters.
        for (name, p) in [
            ("udp.ipv4", &self.udp_ipv4),
            ("udp.ipv6", &self.udp_ipv6),
            ("http", &self.http),
        ] {
            let fields: [(&str, u64); 13] = [
                ("requests", p.requests.load(Ordering::Relaxed)),
                ("connects", p.connects.load(Ordering::Relaxed)),
                ("announces", p.announces.load(Ordering::Relaxed)),
                ("scrapes", p.scrapes.load(Ordering::Relaxed)),
                ("errors", p.errors.load(Ordering::Relaxed)),
                ("blocked", p.blocked.load(Ordering::Relaxed)),
                ("bytes_rx", p.bytes_rx.load(Ordering::Relaxed)),
                ("bytes_tx", p.bytes_tx.load(Ordering::Relaxed)),
                ("dropped", p.dropped.load(Ordering::Relaxed)),
                ("rate_limited", p.rate_limited.load(Ordering::Relaxed)),
                ("ev_started", p.ev_started.load(Ordering::Relaxed)),
                ("ev_completed", p.ev_completed.load(Ordering::Relaxed)),
                ("ev_stopped", p.ev_stopped.load(Ordering::Relaxed)),
            ];
            for (f, v) in fields {
                put!(&format!("{name}.{f}"), v);
            }
        }
        // Swarm totals (combined + per family).
        put!("swarm.torrents", torrents);
        put!("swarm.peers", peers);
        put!("swarm.seeders", seeders);
        put!("swarm.leechers", leechers);
        put!("swarm.ipv4.torrents", t4);
        put!("swarm.ipv4.peers", p4);
        put!("swarm.ipv4.seeders", s4);
        put!("swarm.ipv4.leechers", l4);
        put!("swarm.ipv6.torrents", t6);
        put!("swarm.ipv6.peers", p6);
        put!("swarm.ipv6.seeders", s6);
        put!("swarm.ipv6.leechers", l6);
        put!("swarm.peers_added_total", self.peers_added.load(Ordering::Relaxed));
        put!("swarm.peers_removed_total", self.peers_removed.load(Ordering::Relaxed));
        put!("swarm.torrents_created_total", torrents_created);
        // System gauges.
        put!("system.rss_bytes", self.rss_bytes.load(Ordering::Relaxed));
        put!(
            "system.cpu_percent",
            format!("{:.1}", self.cpu_percent_x10.load(Ordering::Relaxed) as f64 / 10.0)
        );
        put!("system.swarm_estimate_bytes", swarm_bytes);
        // Misc gauges.
        put!("meta.http_connections", self.http_connections.load(Ordering::Relaxed));
        put!("meta.cqe_overflow_total", self.cqe_overflow.load(Ordering::Relaxed));
        out
    }

    /// CSV export for GET /api/stats.csv — tidy `group,metric,value` rows.
    pub fn stats_csv(
        &self,
        family_totals: FamilyTotals,
        torrents_created: u64,
        swarm_bytes: u64,
        version: &str,
    ) -> String {
        let mut s = String::with_capacity(8192);
        s.push_str("group,metric,value\n");
        for (k, v) in self.flat_stats(family_totals, torrents_created, swarm_bytes, version) {
            let (g, m) = k.split_once('.').unwrap_or((k.as_str(), ""));
            s.push_str(g);
            s.push(',');
            s.push_str(m);
            s.push(',');
            s.push_str(&v);
            s.push('\n');
        }
        s
    }

    /// key=value export for GET /api/stats.txt — one `dotted.key=value`
    /// per line, trivially parseable by shells, awk, and log pipelines.
    pub fn stats_txt(
        &self,
        family_totals: FamilyTotals,
        torrents_created: u64,
        swarm_bytes: u64,
        version: &str,
    ) -> String {
        let mut s = String::with_capacity(8192);
        for (k, v) in self.flat_stats(family_totals, torrents_created, swarm_bytes, version) {
            s.push_str(&k);
            s.push('=');
            s.push_str(&v);
            s.push('\n');
        }
        s
    }

    /// Wide CSV of the per-second samples for GET /api/timeseries.csv —
    /// one row per second, one column per metric (logging/TSDB friendly).
    pub fn timeseries_csv(&self, seconds: u64) -> String {
        const HEADER: &str = "t,requests,bytes_rx,bytes_tx,udp4_requests,udp6_requests,http_requests,udp4_bytes_rx,udp6_bytes_rx,http_bytes_rx,udp4_bytes_tx,udp6_bytes_tx,http_bytes_tx,udp4_blocked,udp6_blocked,http_blocked,torrents,peers,seeders,leechers,peers_added,peers_removed,rss_bytes,swarm_bytes,cpu_percent\n";
        let now_ms = self.started.elapsed().as_millis() as u64;
        let cutoff = now_ms.saturating_sub(seconds.saturating_mul(1000));
        let mut s = String::with_capacity(64 * 1024);
        s.push_str(HEADER);
        self.with_samples(|q| {
            for smp in q.iter().filter(|x| x.ts_ms >= cutoff) {
                s.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.1}\n",
                    smp.ts_ms / 1000,
                    smp.requests,
                    smp.bytes_rx,
                    smp.bytes_tx,
                    smp.udp4_requests,
                    smp.udp6_requests,
                    smp.http_requests,
                    smp.udp4_bytes_rx,
                    smp.udp6_bytes_rx,
                    smp.http_bytes_rx,
                    smp.udp4_bytes_tx,
                    smp.udp6_bytes_tx,
                    smp.http_bytes_tx,
                    smp.udp4_blocked,
                    smp.udp6_blocked,
                    smp.http_blocked,
                    smp.torrents,
                    smp.peers,
                    smp.seeders,
                    smp.leechers,
                    smp.peers_added,
                    smp.peers_removed,
                    smp.rss_bytes,
                    smp.swarm_bytes,
                    smp.cpu_percent_x10 as f64 / 10.0,
                ));
            }
        });
        s
    }

    /// Prometheus text exposition format for /metrics.
    /// `family_totals` = per-IP-family (torrents, peers, seeders, leechers);
    /// `swarm_bytes` = estimated swarm-store memory.
    pub fn prometheus_text(
        &self,
        family_totals: FamilyTotals,
        torrents_created: u64,
        swarm_bytes: u64,
        version: &str,
    ) -> String {
        let uptime = self.started.elapsed().as_secs();
        let ((t4, p4, s4, l4), (t6, p6, s6, l6)) = family_totals;
        let (torrents, peers, seeders, leechers) =
            (t4 + t6, p4 + p6, s4 + s6, l4 + l6);
        let rates = self.compute_rates();
        let mut s = String::with_capacity(8192);
        s.push_str("# HELP tsunami_info Tracker build info\n# TYPE tsunami_info gauge\ntsunami_info{version=\"");
        s.push_str(version);
        s.push_str("\"} 1\n");
        s.push_str("# HELP tsunami_uptime_seconds Tracker uptime in seconds\n# TYPE tsunami_uptime_seconds gauge\n");
        s.push_str(&format!("tsunami_uptime_seconds {uptime}\n"));
        s.push_str("# HELP tsunami_peers Active peers\n# TYPE tsunami_peers gauge\n");
        s.push_str(&format!("tsunami_peers {peers}\n"));
        s.push_str("# HELP tsunami_torrents Active torrents\n# TYPE tsunami_torrents gauge\n");
        s.push_str(&format!("tsunami_torrents {torrents}\n"));
        s.push_str("# HELP tsunami_seeders Active seeders\n# TYPE tsunami_seeders gauge\n");
        s.push_str(&format!("tsunami_seeders {seeders}\n"));
        s.push_str("# HELP tsunami_leechers Active leechers\n# TYPE tsunami_leechers gauge\n");
        s.push_str(&format!("tsunami_leechers {leechers}\n"));
        s.push_str("# HELP tsunami_peers_added_total Peers added\n# TYPE tsunami_peers_added_total counter\n");
        s.push_str(&format!("tsunami_peers_added_total {}\n", self.peers_added.load(Ordering::Relaxed)));
        s.push_str("# HELP tsunami_peers_removed_total Peers removed\n# TYPE tsunami_peers_removed_total counter\n");
        s.push_str(&format!("tsunami_peers_removed_total {}\n", self.peers_removed.load(Ordering::Relaxed)));
        s.push_str("# HELP tsunami_peers_joined_per_second Peer join rate\n# TYPE tsunami_peers_joined_per_second gauge\n");
        s.push_str(&format!("tsunami_peers_joined_per_second {}\n", rates.peers_added_per_sec));
        s.push_str("# HELP tsunami_peers_left_per_second Peer leave rate\n# TYPE tsunami_peers_left_per_second gauge\n");
        s.push_str(&format!("tsunami_peers_left_per_second {}\n", rates.peers_removed_per_sec));
        s.push_str("# HELP tsunami_torrents_created_total Torrents created\n# TYPE tsunami_torrents_created_total counter\n");
        s.push_str(&format!("tsunami_torrents_created_total {torrents_created}\n"));
        s.push_str("# HELP tsunami_requests_per_second Requests per second\n# TYPE tsunami_requests_per_second gauge\n");
        s.push_str(&format!("tsunami_requests_per_second {}\n", rates.requests_per_sec));
        s.push_str("# HELP tsunami_bytes_rx_per_second Bytes received per second\n# TYPE tsunami_bytes_rx_per_second gauge\n");
        s.push_str(&format!("tsunami_bytes_rx_per_second {}\n", rates.bytes_rx_per_sec));
        s.push_str("# HELP tsunami_bytes_tx_per_second Bytes sent per second\n# TYPE tsunami_bytes_tx_per_second gauge\n");
        s.push_str(&format!("tsunami_bytes_tx_per_second {}\n", rates.bytes_tx_per_sec));
        // Per-protocol rates.
        for (name, r) in [
            ("udp_ipv4", rates.udp4),
            ("udp_ipv6", rates.udp6),
            ("http", rates.http),
        ] {
            for (mname, v) in [
                ("requests_per_second", r.requests_per_sec),
                ("bytes_rx_per_second", r.bytes_rx_per_sec),
                ("bytes_tx_per_second", r.bytes_tx_per_sec),
                ("announces_per_second", r.announces_per_sec),
                ("connects_per_second", r.connects_per_sec),
                ("scrapes_per_second", r.scrapes_per_sec),
                ("errors_per_second", r.errors_per_sec),
            ] {
                s.push_str(&format!(
                    "# HELP tsunami_{name}_{mname} {mname}\n# TYPE tsunami_{name}_{mname} gauge\ntsunami_{name}_{mname} {v}\n"
                ));
            }
        }
        // Per-family swarm gauges.
        for (fam, ft_, fp, fs, fl) in [
            ("ipv4", t4, p4, s4, l4),
            ("ipv6", t6, p6, s6, l6),
        ] {
            for (mname, v) in [
                ("torrents", ft_),
                ("peers", fp),
                ("seeders", fs),
                ("leechers", fl),
            ] {
                s.push_str(&format!(
                    "# HELP tsunami_{mname}_{fam} {mname} ({fam})\n# TYPE tsunami_{mname}_{fam} gauge\ntsunami_{mname}_{fam} {v}\n"
                ));
            }
        }
        s.push_str("# HELP tsunami_http_connections Active HTTP connections\n# TYPE tsunami_http_connections gauge\n");
        s.push_str(&format!("tsunami_http_connections {}\n", self.http_connections.load(Ordering::Relaxed)));
        s.push_str("# HELP tsunami_cqe_overflow_total io_uring completions dropped on CQ overflow\n# TYPE tsunami_cqe_overflow_total counter\n");
        s.push_str(&format!("tsunami_cqe_overflow_total {}\n", self.cqe_overflow.load(Ordering::Relaxed)));
        // System gauges.
        s.push_str("# HELP tsunami_memory_rss_bytes Process resident set size\n# TYPE tsunami_memory_rss_bytes gauge\n");
        s.push_str(&format!("tsunami_memory_rss_bytes {}\n", self.rss_bytes.load(Ordering::Relaxed)));
        s.push_str("# HELP tsunami_memory_swarm_bytes Estimated swarm-store bytes\n# TYPE tsunami_memory_swarm_bytes gauge\n");
        s.push_str(&format!("tsunami_memory_swarm_bytes {swarm_bytes}\n"));
        s.push_str("# HELP tsunami_cpu_percent CPU utilisation percent\n# TYPE tsunami_cpu_percent gauge\n");
        s.push_str(&format!("tsunami_cpu_percent {}\n", self.cpu_percent_x10.load(Ordering::Relaxed) as f64 / 10.0));
        for (name, p, family) in [
            ("udp_ipv4", &self.udp_ipv4, "4"),
            ("udp_ipv6", &self.udp_ipv6, "6"),
        ] {
            let _ = name;
            proto_prom(&mut s, "udp", family, p);
        }
        proto_prom(&mut s, "http", "", &self.http);
        s
    }

    fn total_requests(&self) -> u64 {
        self.udp_ipv4.requests.load(Ordering::Relaxed)
            + self.udp_ipv6.requests.load(Ordering::Relaxed)
            + self.http.requests.load(Ordering::Relaxed)
    }
    fn total_bytes_rx(&self) -> u64 {
        self.udp_ipv4.bytes_rx.load(Ordering::Relaxed)
            + self.udp_ipv6.bytes_rx.load(Ordering::Relaxed)
            + self.http.bytes_rx.load(Ordering::Relaxed)
    }
    fn total_bytes_tx(&self) -> u64 {
        self.udp_ipv4.bytes_tx.load(Ordering::Relaxed)
            + self.udp_ipv6.bytes_tx.load(Ordering::Relaxed)
            + self.http.bytes_tx.load(Ordering::Relaxed)
    }
}

fn proto_rate_json(r: &ProtoRate) -> serde_json::Value {
    serde_json::json!({
        "requests_per_sec": r.requests_per_sec,
        "bytes_rx_per_sec": r.bytes_rx_per_sec,
        "bytes_tx_per_sec": r.bytes_tx_per_sec,
        "announces_per_sec": r.announces_per_sec,
        "connects_per_sec": r.connects_per_sec,
        "scrapes_per_sec": r.scrapes_per_sec,
        "errors_per_sec": r.errors_per_sec,
        "blocked_per_sec": r.blocked_per_sec,
    })
}

fn proto_json(p: &ProtoStats) -> serde_json::Value {
    serde_json::json!({
        "requests": p.requests.load(Ordering::Relaxed),
        "connects": p.connects.load(Ordering::Relaxed),
        "announces": p.announces.load(Ordering::Relaxed),
        "scrapes": p.scrapes.load(Ordering::Relaxed),
        "errors": p.errors.load(Ordering::Relaxed),
        "blocked": p.blocked.load(Ordering::Relaxed),
        "bytes_rx": p.bytes_rx.load(Ordering::Relaxed),
        "bytes_tx": p.bytes_tx.load(Ordering::Relaxed),
        "dropped": p.dropped.load(Ordering::Relaxed),
        "rate_limited": p.rate_limited.load(Ordering::Relaxed),
        "ev_started": p.ev_started.load(Ordering::Relaxed),
        "ev_completed": p.ev_completed.load(Ordering::Relaxed),
        "ev_stopped": p.ev_stopped.load(Ordering::Relaxed),
    })
}

fn proto_prom(s: &mut String, proto: &str, ipver: &str, p: &ProtoStats) {
    let lbl = if ipver.is_empty() {
        String::new()
    } else {
        format!("{{ip_version=\"{ipver}\"}}")
    };
    macro_rules! m {
        ($name:literal, $help:literal, $v:expr, $ty:literal) => {{
            s.push_str(&format!(
                "# HELP tsunami_{proto}_{} {}\n# TYPE tsunami_{proto}_{} {}\ntsunami_{proto}_{}{} {}\n",
                $name, $help, $name, $ty, $name, lbl, $v
            ));
        }};
    }
    m!("requests_total", "Requests", p.requests.load(Ordering::Relaxed), "counter");
    m!("connects_total", "Connect requests", p.connects.load(Ordering::Relaxed), "counter");
    m!("announces_total", "Announce requests", p.announces.load(Ordering::Relaxed), "counter");
    m!("scrapes_total", "Scrape requests", p.scrapes.load(Ordering::Relaxed), "counter");
    m!("errors_total", "Errors", p.errors.load(Ordering::Relaxed), "counter");
    m!("blocked_total", "Requests blocked by abuse filters", p.blocked.load(Ordering::Relaxed), "counter");
    m!("dropped_total", "Dropped responses", p.dropped.load(Ordering::Relaxed), "counter");
    m!("rate_limited_total", "Requests shed by rate limiter", p.rate_limited.load(Ordering::Relaxed), "counter");
    m!("ev_started_total", "Announce started events", p.ev_started.load(Ordering::Relaxed), "counter");
    m!("ev_completed_total", "Announce completed events", p.ev_completed.load(Ordering::Relaxed), "counter");
    m!("ev_stopped_total", "Announce stopped events", p.ev_stopped.load(Ordering::Relaxed), "counter");
    m!("bytes_rx_total", "Bytes received", p.bytes_rx.load(Ordering::Relaxed), "counter");
    m!("bytes_tx_total", "Bytes sent", p.bytes_tx.load(Ordering::Relaxed), "counter");
}

// Serialize helper used by write_json_to
pub fn to_json_string(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
}

// ---------------- system probing (Linux /proc) ----------------

/// Clock ticks per second (USER_HZ) for converting /proc jiffies to seconds.
pub fn clock_ticks() -> u64 {
    // SAFETY: sysconf is always safe to call.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

/// Process resident set size in bytes, from /proc/self/status.
pub fn read_rss_bytes() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // "VmRSS:    12345 kB"
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            return kb.saturating_mul(1024);
        }
    }
    0
}

/// Total process CPU time (utime + stime) in jiffies, from /proc/self/stat.
/// Field parsing skips the parenthesised comm which may contain spaces.
pub fn read_cpu_jiffies() -> u64 {
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    // Fields after the closing ')' of comm: state(3) ppid(4) ... utime(14) stime(15).
    let Some(close) = stat.rfind(')') else {
        return 0;
    };
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // fields[0] = state (field 3). utime is field 14 => index 14-3 = 11.
    // stime is field 15 => index 12.
    let utime: u64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0);
    let stime: u64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0);
    utime.saturating_add(stime)
}
