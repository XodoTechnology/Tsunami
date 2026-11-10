//! TOML configuration for Tsunami.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub network: NetworkConfig,
    pub protocol: ProtocolConfig,
    pub http: HttpConfig,
    pub cleaning: CleaningConfig,
    pub statistics: StatisticsConfig,
    pub access_list: AccessListConfig,
    pub scrape_export: ScrapeExportConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub use_ipv4: bool,
    pub use_ipv6: bool,
    /// UDP bind addresses (one per family).
    pub bind_ipv4: SocketAddr,
    pub bind_ipv6: SocketAddr,
    /// UDP socket receive buffer bytes (0 = OS default).
    pub socket_recv_buffer: usize,
    /// io_uring ring entries per socket worker (power of two).
    pub ring_size: u32,
    /// Socket worker threads. 0 = number of online CPUs.
    pub socket_workers: usize,
    /// RX backend: "io_uring" (default) or "af_packet" (kernel packet ring,
    /// lower overhead; parses L2/L3/L4 in userspace).
    pub rx_backend: String,
    /// Shards per IP family for the swarm store (power of two).
    pub swarm_shards: usize,
    /// Optional: bind additional UDP sockets? (not implemented; kept for parity)
    #[serde(skip)]
    pub _reserved: (),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProtocolConfig {
    /// Announce interval we tell peers (seconds).
    pub peer_announce_interval: i32,
    /// Drop peers that haven't announced for this long (seconds).
    pub max_peer_age: u32,
    /// Max peers returned per announce.
    pub max_response_peers: usize,
    /// Max info hashes per UDP scrape.
    pub max_scrape_torrents: usize,
    /// Connection-id validity window (seconds).
    pub max_connection_age: u64,
    /// Store peer_id per peer (enables HTTP compact=0 peer_id echo +
    /// per-peer client detail). Costs ~30 bytes/peer extra memory.
    pub store_peer_id: bool,
    /// Count announces per peer client for /api/stats client breakdown.
    pub client_stats: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub enable: bool,
    pub bind: SocketAddr,
    pub threads: usize,
    /// Max request body / header bytes.
    pub max_request_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CleaningConfig {
    /// Seconds between cleaning passes.
    pub interval: u64,
    /// Cleaner threads (each handles a strided subset of shards).
    pub threads: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StatisticsConfig {
    /// Print a stats summary to the log this often (seconds). 0 = disabled.
    pub log_interval: u64,
    /// Write a JSON stats snapshot to this path every log_interval.
    /// Empty = disabled.
    pub write_json_to: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessListConfig {
    /// "off" | "allow" | "deny"
    pub mode: String,
    /// Path to file with hex info hashes (40 chars), one per line, '#' comments.
    pub file: PathBuf,
    /// Reload on SIGHUP.
    pub reload_on_sighup: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ScrapeExportConfig {
    pub enable: bool,
    /// Write full scrape (infohash seeders leechers per line) this often
    /// (in cleaning cycles). 0 = every cycle.
    pub every_cycles: usize,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// log crate level filter: error|warn|info|debug|trace
    pub level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            protocol: ProtocolConfig::default(),
            http: HttpConfig::default(),
            cleaning: CleaningConfig::default(),
            statistics: StatisticsConfig::default(),
            access_list: AccessListConfig::default(),
            scrape_export: ScrapeExportConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            use_ipv4: true,
            use_ipv6: true,
            bind_ipv4: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3000),
            bind_ipv6: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 3000),
            socket_recv_buffer: 8_000_000,
            ring_size: 512,
            socket_workers: 0,
            rx_backend: "io_uring".to_string(),
            swarm_shards: 64,
            _reserved: (),
        }
    }
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            peer_announce_interval: 900,
            max_peer_age: 1800,
            max_response_peers: 50,
            max_scrape_torrents: 70,
            max_connection_age: 4 * 3600,
            store_peer_id: false,
            client_stats: true,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enable: true,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            threads: 4,
            max_request_bytes: 256 * 1024,
        }
    }
}

impl Default for CleaningConfig {
    fn default() -> Self {
        Self {
            interval: 60,
            threads: 2,
        }
    }
}

impl Default for StatisticsConfig {
    fn default() -> Self {
        Self {
            log_interval: 60,
            write_json_to: PathBuf::new(),
        }
    }
}

impl Default for AccessListConfig {
    fn default() -> Self {
        Self {
            mode: "off".into(),
            file: PathBuf::from("access_list.txt"),
            reload_on_sighup: true,
        }
    }
}

impl Default for ScrapeExportConfig {
    fn default() -> Self {
        Self {
            enable: false,
            every_cycles: 10,
            path: PathBuf::from("scrape_export.txt"),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>) -> anyhow::Result<Self> {
        match path {
            Some(p) => {
                let text = std::fs::read_to_string(p)
                    .map_err(|e| anyhow::anyhow!("read config {}: {}", p, e))?;
                let cfg: Config = toml::from_str(&text)
                    .map_err(|e| anyhow::anyhow!("parse config {}: {}", p, e))?;
                Ok(cfg)
            }
            None => {
                // try tsunami.toml then default
                if std::path::Path::new("tsunami.toml").exists() {
                    Self::load(Some("tsunami.toml"))
                } else {
                    Ok(Config::default())
                }
            }
        }
    }
}
