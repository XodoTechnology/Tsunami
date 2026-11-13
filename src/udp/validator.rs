//! Stateless connection-id creation/validation (anti-amplification).
//!
//! connection_id = [unix_secs u32][truncated keyed-BLAKE3 hash u32] as i64.
//! The hash covers the timestamp + client IP, so ids can't be forged for
//! other IPs and expire after `max_age` seconds.
//!
//! Timestamps are wall-clock (unix epoch), not monotonic-since-boot, so ids
//! stay valid across restarts — provided the keyed hash secret is persisted
//! (`conn_key_path`). With an ephemeral key, every restart invalidates all
//! outstanding ids and clients must re-handshake (a thundering-herd of
//! connect requests proportional to swarm size).

use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use constant_time_eq::constant_time_eq;

const CACHE_SLOTS: usize = 64;

#[derive(Clone, Copy)]
struct CacheEntry {
    ip: IpAddr,
    conn_id: i64,
}

pub struct Validator {
    key: [u8; 32],
    max_age_secs: u64,
    /// Direct-mapped per-worker cache of recently verified `(ip, conn_id)`
    /// pairs. Only populated after a full constant-time BLAKE3 check passes,
    /// avoiding repeated BLAKE3 evaluations when a client or CGNAT IP sends
    /// bursts of announces with the same valid connection_id.
    cache: [CacheEntry; CACHE_SLOTS],
}

impl Validator {
    /// `key_path` empty => ephemeral random key (ids die on restart).
    /// Non-empty => load 32-byte key from disk, generating + persisting one
    /// on first run so conn_ids survive restarts.
    pub fn new(max_age_secs: u64, key_path: &str) -> Self {
        let key = load_or_create_key(key_path);
        Self {
            key,
            max_age_secs,
            cache: [CacheEntry {
                ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                conn_id: 0,
            }; CACHE_SLOTS],
        }
    }

    /// Cheap per-worker clone sharing the same key.
    pub fn for_worker(&self) -> Self {
        Self {
            key: self.key,
            max_age_secs: self.max_age_secs,
            cache: self.cache,
        }
    }

    #[inline]
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[inline]
    fn cache_slot(ip: &IpAddr, conn_id: i64) -> usize {
        let ip_bits = match ip {
            IpAddr::V4(v4) => u32::from(*v4) as u64,
            IpAddr::V6(v6) => {
                let o = v6.octets();
                u64::from_ne_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]])
                    ^ u64::from_ne_bytes([o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]])
            }
        };
        let x = (ip_bits ^ (conn_id as u64)).wrapping_mul(0x9E3779B97F4A7C15);
        ((x >> 58) as usize) & (CACHE_SLOTS - 1)
    }

    pub fn create(&mut self, ip: IpAddr) -> i64 {
        let ts = self.now_secs() as u32;
        self.create_at(ip, ts)
    }

    #[inline]
    pub fn create_at(&mut self, ip: IpAddr, ts: u32) -> i64 {
        let hash = self.hash(ts, ip);
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&ts.to_be_bytes());
        b[4..].copy_from_slice(&hash);
        let conn_id = i64::from_be_bytes(b);
        if conn_id != 0 {
            self.cache[Self::cache_slot(&ip, conn_id)] = CacheEntry { ip, conn_id };
        }
        conn_id
    }

    pub fn valid(&mut self, ip: IpAddr, connection_id: i64) -> bool {
        let now = self.now_secs() as u32;
        self.valid_at(ip, connection_id, now)
    }

    #[inline]
    pub fn valid_at(&mut self, ip: IpAddr, connection_id: i64, now_secs: u32) -> bool {
        let b = connection_id.to_be_bytes();
        let ts = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let now = now_secs as u64;
        let client_ts = ts as u64;
        // Reject expired / uninitialized (conn_id == 0) / far-future timestamps
        // before running BLAKE3.
        if client_ts + self.max_age_secs <= now || client_ts > now.saturating_add(60) {
            return false;
        }
        let slot = Self::cache_slot(&ip, connection_id);
        let entry = &self.cache[slot];
        if entry.conn_id == connection_id && entry.ip == ip && connection_id != 0 {
            return true;
        }
        let expected = self.hash(ts, ip);
        if !constant_time_eq(&b[4..8], &expected) {
            return false;
        }
        if connection_id != 0 {
            self.cache[slot] = CacheEntry {
                ip,
                conn_id: connection_id,
            };
        }
        true
    }

    #[inline]
    fn hash(&self, ts: u32, ip: IpAddr) -> [u8; 4] {
        let h = match ip {
            IpAddr::V4(v4) => {
                let mut buf = [0u8; 8];
                buf[..4].copy_from_slice(&ts.to_be_bytes());
                buf[4..8].copy_from_slice(&v4.octets());
                blake3::keyed_hash(&self.key, &buf)
            }
            IpAddr::V6(v6) => {
                let mut buf = [0u8; 20];
                buf[..4].copy_from_slice(&ts.to_be_bytes());
                buf[4..20].copy_from_slice(&v6.octets());
                blake3::keyed_hash(&self.key, &buf)
            }
        };
        let bytes = h.as_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3]]
    }
}

fn load_or_create_key(path: &str) -> [u8; 32] {
    if path.is_empty() {
        let mut key = [0u8; 32];
        let _ = getrandom::fill(&mut key);
        return key;
    }
    let p = Path::new(path);
    if let Ok(bytes) = std::fs::read(p) {
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return key;
        }
        log::warn!("conn key {} has wrong size ({}), regenerating", path, bytes.len());
    }
    let mut key = [0u8; 32];
    let _ = getrandom::fill(&mut key);
    // Best-effort persist; failure only means ids won't survive restarts.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(p)
        {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(&key) {
                    log::warn!("conn key write to {} failed: {e}", path);
                } else {
                    log::info!("conn key persisted to {}", path);
                }
            }
            Err(e) => log::warn!("conn key create {} failed: {e}", path),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(p, key);
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_persists_across_instances() {
        let dir = std::env::temp_dir().join(format!("tsv-key-{}", std::process::id()));
        let path = dir.to_string_lossy().to_string();
        let mut v1 = Validator::new(3600, &path);
        assert!(std::path::Path::new(&path).exists());
        let v2 = Validator::new(3600, &path);
        assert_eq!(v1.key, v2.key, "key must reload from disk");
        // conn_id minted by v1 validates under v2 (same key, wall clock)
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let id = v1.create(ip);
        let mut v2m = v2;
        assert!(v2m.valid(ip, id));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_path_is_ephemeral() {
        let a = Validator::new(3600, "");
        let b = Validator::new(3600, "");
        assert_ne!(a.key, b.key);
    }
}
