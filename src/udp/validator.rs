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

pub struct Validator {
    key: [u8; 32],
    hasher: blake3::Hasher,
    max_age_secs: u64,
}

impl Validator {
    /// `key_path` empty => ephemeral random key (ids die on restart).
    /// Non-empty => load 32-byte key from disk, generating + persisting one
    /// on first run so conn_ids survive restarts.
    pub fn new(max_age_secs: u64, key_path: &str) -> Self {
        let key = load_or_create_key(key_path);
        let hasher = blake3::Hasher::new_keyed(&key);
        Self {
            key,
            hasher,
            max_age_secs,
        }
    }

    /// Cheap per-worker clone sharing the same key.
    pub fn for_worker(&self) -> Self {
        Self {
            key: self.key,
            hasher: blake3::Hasher::new_keyed(&self.key),
            max_age_secs: self.max_age_secs,
        }
    }

    #[inline]
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn create(&mut self, ip: IpAddr) -> i64 {
        let ts = self.now_secs() as u32;
        let hash = self.hash(ts, ip);
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&ts.to_be_bytes());
        b[4..].copy_from_slice(&hash);
        i64::from_be_bytes(b)
    }

    pub fn valid(&mut self, ip: IpAddr, connection_id: i64) -> bool {
        let b = connection_id.to_be_bytes();
        let ts = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let expected = self.hash(ts, ip);
        if !constant_time_eq(&b[4..8], &expected) {
            return false;
        }
        let now = self.now_secs();
        let client_ts = ts as u64;
        let not_expired = client_ts + self.max_age_secs > now;
        let not_far_future = client_ts <= now.saturating_add(60);
        not_expired && not_far_future
    }

    fn hash(&mut self, ts: u32, ip: IpAddr) -> [u8; 4] {
        self.hasher.reset();
        self.hasher.update(&ts.to_be_bytes());
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
