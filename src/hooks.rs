//! Optional event hooks: POSTs JSON batches to a configured HTTP endpoint
//! whenever peers send `started`/`completed`/`stopped`/`paused` announces.
//! Aimed at private-tracker integrations (invite systems, ratio tracking).
//!
//! Disabled by default (`protocol.event_hook_url` empty). When enabled, a
//! bounded queue decouples the hot announce path from HTTP delivery — events
//! are dropped (and counted) if the queue fills.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::OnceLock;
use std::time::Duration;

static SENDER: OnceLock<SyncSender<String>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
static DELIVERED: AtomicU64 = AtomicU64::new(0);

/// Initialize the hook pipeline. No-op when `url` is empty. Only plain
/// `http://` URLs are supported (no TLS) — hooks are for internal use.
pub fn init(url: &str, capacity: usize) {
    if url.is_empty() {
        return;
    }
    let Some((hostport, path)) = parse_url(url) else {
        log::warn!("event_hook_url invalid (want http://host[:port]/path): {url}");
        return;
    };
    let (tx, rx) = sync_channel::<String>(capacity.max(64));
    if SENDER.set(tx).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("event-hooks".into())
        .spawn(move || worker(rx, hostport, path))
        .expect("spawn event-hooks thread");
    log::info!("event hooks enabled -> {url}");
}

/// Queue one event payload for delivery. Non-blocking; drops when the queue
/// is full so the announce path is never stalled by hook delivery.
pub fn emit(payload: String) {
    if let Some(tx) = SENDER.get() {
        if tx.try_send(payload).is_err() {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Queue one announce-lifecycle event for delivery. No-op for `None`
/// events or when hooks are disabled.
pub fn announce_event(
    event: crate::swarm::AnnounceEvent,
    info_hash: &[u8; 20],
    ip: std::net::IpAddr,
    port: u16,
    peer_id: &[u8; 20],
    left: i64,
    ts: u32,
) {
    use crate::swarm::AnnounceEvent as E;
    let name = match event {
        E::Started => "started",
        E::Completed => "completed",
        E::Stopped => "stopped",
        E::Paused => "paused",
        E::None => return,
    };
    emit(format!(
        "{{\"event\":\"{name}\",\"info_hash\":\"{}\",\"peer_ip\":\"{ip}\",\"port\":{port},\"peer_id\":\"{}\",\"left\":{left},\"ts\":{ts}}}",
        crate::access::infohash_hex(info_hash),
        crate::access::infohash_hex(peer_id),
    ));
}

/// I2P announce-lifecycle event. Same shape as `announce_event` but the
/// peer identity is an I2P Destination (`peer_dest`) rather than an IP.
pub fn announce_event_i2p(
    event: crate::swarm::AnnounceEvent,
    info_hash: &[u8; 20],
    destination: &str,
    port: u16,
    peer_id: &[u8; 20],
    left: i64,
    ts: u32,
) {
    use crate::swarm::AnnounceEvent as E;
    let name = match event {
        E::Started => "started",
        E::Completed => "completed",
        E::Stopped => "stopped",
        E::Paused => "paused",
        E::None => return,
    };
    emit(format!(
        "{{\"event\":\"{name}\",\"info_hash\":\"{}\",\"peer_dest\":\"{}\",\"port\":{port},\"peer_id\":\"{}\",\"left\":{left},\"ts\":{ts}}}",
        crate::access::infohash_hex(info_hash),
        destination,
        crate::access::infohash_hex(peer_id),
    ));
}

pub fn dropped_total() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

pub fn delivered_total() -> u64 {
    DELIVERED.load(Ordering::Relaxed)
}

fn parse_url(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("http://")?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if hostport.is_empty() {
        return None;
    }
    Some((hostport.to_string(), path.to_string()))
}

fn worker(rx: std::sync::mpsc::Receiver<String>, hostport: String, path: String) {
    while let Ok(first) = rx.recv() {
        // Batch whatever is already queued (up to 63 more) into one POST.
        let mut batch = String::with_capacity(first.len() * 8 + 2);
        batch.push('[');
        batch.push_str(&first);
        for _ in 0..63 {
            match rx.try_recv() {
                Ok(ev) => {
                    batch.push(',');
                    batch.push_str(&ev);
                }
                Err(_) => break,
            }
        }
        batch.push(']');
        post(&hostport, &path, &batch);
        DELIVERED.fetch_add(1, Ordering::Relaxed);
    }
}

fn post(hostport: &str, path: &str, body: &str) {
    let addrs: Vec<_> = match hostport.to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => return,
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addrs[0], Duration::from_secs(5)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(req.as_bytes()).is_err() {
        return;
    }
    // Drain the response so the peer sees a clean close; ignore contents.
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf);
}
