//! Info-hash access list: allow/deny modes backed by a hex file,
//! hot-reloadable on SIGHUP.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Off,
    Allow,
    Deny,
}

pub struct AccessList {
    mode: Mode,
    path: PathBuf,
    set: Arc<arc_swap::ArcSwap<HashSet<[u8; 20]>>>,
    loaded_count: AtomicU64,
}

impl AccessList {
    pub fn new(mode: &str, path: PathBuf) -> Self {
        let mode = match mode.to_ascii_lowercase().as_str() {
            "allow" | "whitelist" | "white" => Mode::Allow,
            "deny" | "blacklist" | "black" => Mode::Deny,
            _ => Mode::Off,
        };
        Self {
            mode,
            path,
            set: Arc::new(arc_swap::ArcSwap::from_pointee(HashSet::new())),
            loaded_count: AtomicU64::new(0),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Load (or reload) the access list file. Returns number of entries.
    pub fn reload(&self) -> anyhow::Result<usize> {
        if self.mode == Mode::Off {
            return Ok(0);
        }
        let text = std::fs::read_to_string(&self.path).map_err(|e| {
            anyhow::anyhow!("access list read {}: {}", self.path.display(), e)
        })?;
        let mut set = HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // accept 40-hex infohash, optionally with "infohash" prefixes
            let hex = line
                .strip_prefix("infohash:")
                .or_else(|| line.strip_prefix("ih:"))
                .unwrap_or(line);
            if let Some(hash) = parse_infohash_hex(hex) {
                set.insert(hash);
            } else {
                log::warn!("access list: skipping unparseable line: {}", line);
            }
        }
        let n = set.len();
        self.set.store(Arc::new(set));
        self.loaded_count.store(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    /// Check whether an info hash is allowed.
    #[inline]
    pub fn allows(&self, info_hash: &[u8; 20]) -> bool {
        match self.mode {
            Mode::Off => true,
            Mode::Allow => self.set.load().contains(info_hash),
            Mode::Deny => !self.set.load().contains(info_hash),
        }
    }

    pub fn loaded_count(&self) -> u64 {
        self.loaded_count.load(Ordering::Relaxed)
    }
}

/// Parse a 40-char hex string into [u8;20].
pub fn parse_infohash_hex(s: &str) -> Option<[u8; 20]> {
    let s = s.trim();
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    let bytes = s.as_bytes();
    for i in 0..20 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Format an infohash as hex (for API responses).
pub fn infohash_hex(h: &[u8; 20]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(40);
    for &b in h.iter() {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
