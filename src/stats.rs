//! Global statistics: atomics updated by workers, JSON snapshot for the
//! HTTP stats API and optional file export.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default)]
pub struct ProtoStats {
    pub requests: AtomicU64,
    pub connects: AtomicU64,
    pub announces: AtomicU64,
    pub scrapes: AtomicU64,
    pub errors: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub dropped: AtomicU64,   // responses dropped (no send buffer)
    pub rate_limited: AtomicU64, // requests shed by the rate limiter
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
    }
}

/// Striping for client stats to reduce lock contention.
const CLIENT_STRIPES: usize = 64;

/// BEP 20 client signature = first 8 bytes of peer_id.
pub type ClientKey = [u8; 8];

pub struct ClientStats {
    stripes: Vec<Mutex<HashMap<ClientKey, u64>>>,
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            stripes: (0..CLIENT_STRIPES).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Record an announce for a peer client, keyed by the 8-byte client
    /// signature at the start of peer_id.
    #[inline]
    pub fn record(&self, peer_id: &[u8; 20]) {
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
    pub client_stats: ClientStats,
    /// Ring of per-second cumulative-counter samples feeding windowed rates.
    /// Fed by a dedicated sampler thread so every consumer (/api/stats,
    /// /metrics, the maintenance log) sees the SAME window regardless of
    /// poll timing.
    rate_samples: Mutex<VecDeque<RateSample>>,
}

/// One point-in-time cumulative-counter reading (milliseconds since start).
#[derive(Clone, Copy)]
struct RateSample {
    ts_ms: u64,
    requests: u64,
    bytes_rx: u64,
    bytes_tx: u64,
}

/// How often the sampler thread records a point (drives ring density).
pub const RATE_SAMPLE_MS: u64 = 1_000;
/// How long the ring retains samples.
const RATE_RING_MS: u64 = 120_000;
/// Trailing window over which per-second rates are computed.
const RATE_WINDOW_MS: u64 = 10_000;

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
            client_stats: ClientStats::new(),
            rate_samples: Mutex::new(VecDeque::with_capacity(
                (RATE_RING_MS / RATE_SAMPLE_MS) as usize + 2,
            )),
        })
    }

    /// Record the current cumulative counters into the rate ring. Called by
    /// the sampler thread once per RATE_SAMPLE_MS; also safe to call more
    /// often (it just adds denser samples).
    pub fn push_rate_sample(&self) {
        let ts_ms = self.started.elapsed().as_millis() as u64;
        let sample = RateSample {
            ts_ms,
            requests: self.total_requests(),
            bytes_rx: self.total_bytes_rx(),
            bytes_tx: self.total_bytes_tx(),
        };
        let mut q = self.rate_samples.lock().unwrap();
        q.push_back(sample);
        // Evict samples older than the ring horizon (and enforce a hard cap).
        while let Some(&front) = q.front() {
            if ts_ms.saturating_sub(front.ts_ms) > RATE_RING_MS || q.len() > 256 {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// JSON-serializable snapshot for /api/stats.
    /// `torrents_created` is the store's cumulative counter.
    pub fn snapshot_json(
        &self,
        store_totals: (u64, u64, u64, u64),
        torrents_created: u64,
        version: &str,
    ) -> serde_json::Value {
        let uptime = self.started.elapsed().as_secs();
        let (torrents, peers, seeders, leechers) = store_totals;
        let (req_rate, rx_rate, tx_rate) = self.compute_rates();

        let clients = self.client_stats.top(20);
        let client_list: Vec<serde_json::Value> = clients
            .iter()
            .map(|&(k, c)| {
                let name = String::from_utf8_lossy(&k).trim_matches('\0').to_string();
                serde_json::json!({ "client": name, "announces": c })
            })
            .collect();

        serde_json::json!({
            "version": version,
            "uptime_seconds": uptime,
            "rates": {
                "requests_per_sec": req_rate,
                "bytes_rx_per_sec": rx_rate,
                "bytes_tx_per_sec": tx_rate,
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
                "peers_added_total": self.peers_added.load(Ordering::Relaxed),
                "peers_removed_total": self.peers_removed.load(Ordering::Relaxed),
                "torrents_created_total": torrents_created,
            },
            "http_connections": self.http_connections.load(Ordering::Relaxed),
            "top_clients": client_list,
        })
    }

    /// Per-second rates over a fixed trailing window (requests, rx B/s,
    /// tx B/s). Read-only: the rate is (now - sample@window-ago) / window,
    /// so every consumer sees the same value regardless of poll order.
    fn compute_rates(&self) -> (u64, u64, u64) {
        let now_ms = self.started.elapsed().as_millis() as u64;
        let cur_req = self.total_requests();
        let cur_rx = self.total_bytes_rx();
        let cur_tx = self.total_bytes_tx();

        let q = self.rate_samples.lock().unwrap();
        // Newest sample at or before the window start is the rate baseline.
        let target = now_ms.saturating_sub(RATE_WINDOW_MS);
        let base = q
            .iter()
            .rev()
            .find(|s| s.ts_ms <= target)
            .or_else(|| q.front());

        let (dt_ms, b_req, b_rx, b_tx) = match base {
            Some(b) => (
                now_ms.saturating_sub(b.ts_ms).max(1),
                b.requests,
                b.bytes_rx,
                b.bytes_tx,
            ),
            // No samples yet (first second after boot): rate since start.
            None => (now_ms.max(1), 0, 0, 0),
        };
        let dt = dt_ms as f64 / 1000.0;
        (
            ((cur_req.saturating_sub(b_req)) as f64 / dt) as u64,
            ((cur_rx.saturating_sub(b_rx)) as f64 / dt) as u64,
            ((cur_tx.saturating_sub(b_tx)) as f64 / dt) as u64,
        )
    }

    /// Prometheus text exposition format for /metrics.
    /// `store_totals` = (torrents, peers, seeders, leechers).
    pub fn prometheus_text(
        &self,
        store_totals: (u64, u64, u64, u64),
        torrents_created: u64,
        version: &str,
    ) -> String {
        let uptime = self.started.elapsed().as_secs();
        let (torrents, peers, seeders, leechers) = store_totals;
        let (req_rate, rx_rate, tx_rate) = self.compute_rates();
        let mut s = String::with_capacity(4096);
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
        s.push_str("# HELP tsunami_torrents_created_total Torrents created\n# TYPE tsunami_torrents_created_total counter\n");
        s.push_str(&format!("tsunami_torrents_created_total {torrents_created}\n"));
        s.push_str("# HELP tsunami_requests_per_second Requests per second\n# TYPE tsunami_requests_per_second gauge\n");
        s.push_str(&format!("tsunami_requests_per_second {req_rate}\n"));
        s.push_str("# HELP tsunami_bytes_rx_per_second Bytes received per second\n# TYPE tsunami_bytes_rx_per_second gauge\n");
        s.push_str(&format!("tsunami_bytes_rx_per_second {rx_rate}\n"));
        s.push_str("# HELP tsunami_bytes_tx_per_second Bytes sent per second\n# TYPE tsunami_bytes_tx_per_second gauge\n");
        s.push_str(&format!("tsunami_bytes_tx_per_second {tx_rate}\n"));
        s.push_str("# HELP tsunami_http_connections Active HTTP connections\n# TYPE tsunami_http_connections gauge\n");
        s.push_str(&format!("tsunami_http_connections {}\n", self.http_connections.load(Ordering::Relaxed)));
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

fn proto_json(p: &ProtoStats) -> serde_json::Value {
    serde_json::json!({
        "requests": p.requests.load(Ordering::Relaxed),
        "connects": p.connects.load(Ordering::Relaxed),
        "announces": p.announces.load(Ordering::Relaxed),
        "scrapes": p.scrapes.load(Ordering::Relaxed),
        "errors": p.errors.load(Ordering::Relaxed),
        "bytes_rx": p.bytes_rx.load(Ordering::Relaxed),
        "bytes_tx": p.bytes_tx.load(Ordering::Relaxed),
        "dropped": p.dropped.load(Ordering::Relaxed),
        "rate_limited": p.rate_limited.load(Ordering::Relaxed),
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
    m!("dropped_total", "Dropped responses", p.dropped.load(Ordering::Relaxed), "counter");
    m!("rate_limited_total", "Requests shed by rate limiter", p.rate_limited.load(Ordering::Relaxed), "counter");
    m!("bytes_rx_total", "Bytes received", p.bytes_rx.load(Ordering::Relaxed), "counter");
    m!("bytes_tx_total", "Bytes sent", p.bytes_tx.load(Ordering::Relaxed), "counter");
}

// Serialize helper used by write_json_to
pub fn to_json_string(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
}
