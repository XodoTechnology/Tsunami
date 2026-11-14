//! WebSocket tracker endpoint (`ws://`) for WebTorrent-style clients.
//!
//! The WebSocket tracker protocol carries standard BEP-15 binary tracker
//! messages (connect / announce / scrape) inside WebSocket binary frames.
//! Each connection runs on its own thread and maps onto the same swarm
//! store as UDP and HTTP.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use sha1::{Digest, Sha1};

use crate::access::AccessList;
use crate::config::Config;
use crate::protocol::{self, ParseFailure, ParseResult, ParsedRequest};
use crate::stats::Stats;
use crate::swarm::{self, InfoHash, PeerEndpoint, Rng, Store};
use crate::udp::validator::Validator;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_WS_MESSAGE: usize = 256 * 1024;

// ---------------- handshake helpers ----------------

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for c in data.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((*c.get(1).unwrap_or(&0) as u32) << 8)
            | (*c.get(2).unwrap_or(&0) as u32);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn ws_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    b64_encode(&h.finalize())
}

/// Case-insensitive HTTP header lookup on raw header bytes.
fn header<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

/// True if the raw HTTP head is a WebSocket upgrade request.
pub fn is_websocket_upgrade(head: &[u8]) -> bool {
    header(head, "upgrade")
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
        && header(head, "sec-websocket-key").is_some()
}

// ---------------- frame codec ----------------

/// Read one WebSocket frame. Returns (fin, opcode, payload).
/// Client->server frames are masked per RFC 6455 and are unmasked here.
fn read_frame(stream: &mut TcpStream) -> Result<(bool, u8, Vec<u8>)> {
    let mut h = [0u8; 2];
    stream.read_exact(&mut h)?;
    let fin = h[0] & 0x80 != 0;
    let opcode = h[0] & 0x0F;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7F) as u64;
    if len == 126 {
        let mut b = [0u8; 2];
        stream.read_exact(&mut b)?;
        len = u16::from_be_bytes(b) as u64;
    } else if len == 127 {
        let mut b = [0u8; 8];
        stream.read_exact(&mut b)?;
        len = u64::from_be_bytes(b);
    }
    if len > MAX_WS_MESSAGE as u64 {
        return Err(anyhow!("ws frame too large: {len}"));
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        stream.read_exact(&mut m)?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload)?;
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }
    Ok((fin, opcode, payload))
}

/// Write one unmasked server->client frame.
fn write_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) -> Result<()> {
    let mut hdr = [0u8; 10];
    hdr[0] = 0x80 | opcode;
    let n = payload.len();
    let hlen = if n < 126 {
        hdr[1] = n as u8;
        2
    } else if n <= 0xFFFF {
        hdr[1] = 126;
        hdr[2..4].copy_from_slice(&(n as u16).to_be_bytes());
        4
    } else {
        hdr[1] = 127;
        hdr[2..10].copy_from_slice(&(n as u64).to_be_bytes());
        10
    };
    stream.write_all(&hdr[..hlen])?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

// ---------------- session ----------------

/// Perform the handshake on `stream` and move the connection to a
/// dedicated thread. Called from the HTTP handler; frees the HTTP thread.
pub fn handle_upgrade(
    mut stream: TcpStream,
    head: &[u8],
    peer: SocketAddr,
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
    validator: Validator,
) -> Result<()> {
    let key = header(head, "sec-websocket-key").context("missing sec-websocket-key")?;
    let accept = ws_accept(key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    stats.http_connections.fetch_add(1, Ordering::Relaxed);
    std::thread::Builder::new()
        .name("ws-client".into())
        .spawn(move || {
            let r = ws_session(stream, peer, &config, &store, &stats, &access_list, validator);
            stats.http_connections.fetch_sub(1, Ordering::Relaxed);
            if let Err(e) = r {
                log::debug!("ws session ended: {e}");
            }
        })
        .context("spawn ws session")?;
    Ok(())
}

fn ws_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: &Config,
    store: &Store,
    stats: &Stats,
    access_list: &AccessList,
    mut validator: Validator,
) -> Result<()> {
    // Idle timeout = connection-id lifetime: a client may legitimately wait a
    // full announce interval between messages, so don't reap it early. Dead
    // conns are still reaped within max_connection_age.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(
        config.protocol.max_connection_age.max(60),
    )));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_nodelay(true);
    let ip = peer.ip();
    let mut rng = Rng::new();
    let mut scratch: Vec<PeerEndpoint> = Vec::with_capacity(256);
    let mut cur: Vec<u8> = Vec::with_capacity(2048);
    let mut in_frag = false;
    let max_msgs = config.http.websocket_msgs_per_sec;
    let mut win_start = std::time::Instant::now();
    let mut win_msgs: u32 = 0;

    loop {
        let (fin, opcode, payload) = read_frame(&mut stream)?;
        match opcode {
            0x8 => {
                // close
                let _ = write_frame(&mut stream, 0x8, &payload);
                return Ok(());
            }
            0x9 => {
                // ping -> pong
                write_frame(&mut stream, 0xA, &payload)?;
                continue;
            }
            0xA => continue, // pong
            0x1 | 0x2 => {
                if fin {
                    cur.clear();
                    cur.extend_from_slice(&payload);
                } else {
                    cur.clear();
                    cur.extend_from_slice(&payload);
                    in_frag = true;
                    continue;
                }
            }
            0x0 => {
                if !in_frag {
                    continue;
                }
                cur.extend_from_slice(&payload);
                if cur.len() > MAX_WS_MESSAGE {
                    return Err(anyhow!("ws fragmented message too large"));
                }
                if !fin {
                    continue;
                }
                in_frag = false;
            }
            _ => continue,
        }
        if max_msgs > 0 {
            if win_start.elapsed() >= Duration::from_secs(1) {
                win_start = std::time::Instant::now();
                win_msgs = 0;
            }
            win_msgs += 1;
            if win_msgs > max_msgs {
                return Err(anyhow!("websocket message rate limit exceeded"));
            }
        }
        if let Some(resp) = dispatch(
            &cur, ip, peer, config, store, stats, access_list, &mut validator, &mut rng,
            &mut scratch,
        ) {
            write_frame(&mut stream, 0x2, &resp)?;
        }
    }
}

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Dispatch one BEP-15 binary message; returns the binary response payload.
/// Shared by the WebSocket session and the HTTP `/bep15` endpoint.
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch(
    payload: &[u8],
    ip: IpAddr,
    peer: SocketAddr,
    config: &Config,
    store: &Store,
    stats: &Stats,
    access_list: &AccessList,
    validator: &mut Validator,
    rng: &mut Rng,
    scratch: &mut Vec<PeerEndpoint>,
) -> Option<Vec<u8>> {
    stats.http.requests.fetch_add(1, Ordering::Relaxed);
    stats.http.bytes_rx.fetch_add(payload.len() as u64, Ordering::Relaxed);
    let out = match protocol::parse_request(payload, config.protocol.max_scrape_torrents) {
        ParseResult::Ok(ParsedRequest::Connect { transaction_id }) => {
            stats.http.connects.fetch_add(1, Ordering::Relaxed);
            let conn_id = validator.create(ip);
            let mut b = vec![0u8; 16];
            let n = protocol::write_connect_response(&mut b, transaction_id, conn_id);
            b.truncate(n);
            b
        }
        ParseResult::Ok(ParsedRequest::Announce(req)) => {
            // Abuse filters run before conn_id validation.
            if protocol::synthetic_peer_id(&req.peer_id) {
                stats.http.blocked.fetch_add(1, Ordering::Relaxed);
                return Some(err_resp(req.transaction_id, "invalid peer_id"));
            }
            if !validator.valid(ip, req.connection_id) {
                return None;
            }
            let info_hash: InfoHash = req.info_hash;
            if !access_list.allows(&info_hash) {
                stats.http.errors.fetch_add(1, Ordering::Relaxed);
                return Some(err_resp(req.transaction_id, "info hash not allowed"));
            }
            stats.http.announces.fetch_add(1, Ordering::Relaxed);
            // WS clients may not have a UDP port; fall back to the TCP
            // remote port so the peer key stays unique per connection.
            let port = if req.port == 0 { peer.port() } else { req.port };
            let event = swarm::AnnounceEvent::from_wire(req.event as i32);
            match event {
                swarm::AnnounceEvent::Started => {
                    stats.http.ev_started.fetch_add(1, Ordering::Relaxed);
                }
                swarm::AnnounceEvent::Completed => {
                    stats.http.ev_completed.fetch_add(1, Ordering::Relaxed);
                }
                swarm::AnnounceEvent::Stopped => {
                    stats.http.ev_stopped.fetch_add(1, Ordering::Relaxed);
                }
                swarm::AnnounceEvent::Paused | swarm::AnnounceEvent::None => {}
            }
            let now = unix_now();
            // Optional client-supplied IP becomes the swarm address only when
            // allow_client_ip is on; `ip` stays authoritative for conn_id.
            let announce_ip = if config.protocol.allow_client_ip {
                protocol::request_ip(&req.ip_field, ip)
            } else {
                ip
            };
            match store.announce(
                &info_hash,
                announce_ip,
                port,
                req.peer_id,
                req.left,
                event,
                req.numwant,
                now,
                rng,
                scratch,
            ) {
                Some((interval, seeders, leechers, added, removed)) => {
                    if added {
                        stats.peers_added.fetch_add(1, Ordering::Relaxed);
                    }
                    if removed {
                        stats.peers_removed.fetch_add(1, Ordering::Relaxed);
                    }
                    crate::hooks::announce_event(
                        event, &info_hash, announce_ip, port, &req.peer_id, req.left, now,
                    );
                    let mut b = vec![0u8; 64 + scratch.len() * 18];
                    let mut o = protocol::write_announce_header(
                        &mut b, req.transaction_id, interval, leechers as i32, seeders as i32,
                    );
                    for p in scratch.iter() {
                        match p.ip {
                            IpAddr::V4(v4) => o += protocol::put_peer_v4(&mut b, o, v4, p.port),
                            IpAddr::V6(v6) => o += protocol::put_peer_v6(&mut b, o, v6, p.port),
                        }
                    }
                    b.truncate(o);
                    b
                }
                None => {
                    stats.http.errors.fetch_add(1, Ordering::Relaxed);
                    return Some(err_resp(req.transaction_id, "announce failed"));
                }
            }
        }
        ParseResult::Ok(ParsedRequest::Scrape {
            connection_id,
            transaction_id,
            hashes,
        }) => {
            if !validator.valid(ip, connection_id) {
                return None;
            }
            stats.http.scrapes.fetch_add(1, Ordering::Relaxed);
            let count = hashes.len().min(config.protocol.max_scrape_torrents);
            let stats_v = store.scrape(&hashes[..count]);
            let mut triples: Vec<(i32, i32, i32)> = Vec::with_capacity(count);
            for &(s, _c, l, _d) in stats_v.iter() {
                triples.push((s as i32, 0, l as i32));
            }
            let mut b = vec![0u8; 8 + triples.len() * 12];
            let n = protocol::write_scrape_response(&mut b, transaction_id, &triples);
            b.truncate(n);
            b
        }
        ParseResult::Err(ParseFailure::Sendable {
            connection_id,
            transaction_id,
            message,
        }) => {
            if !validator.valid(ip, connection_id) {
                return None;
            }
            stats.http.errors.fetch_add(1, Ordering::Relaxed);
            err_resp(transaction_id, message)
        }
        ParseResult::Err(ParseFailure::Drop) => return None,
    };
    stats.http.bytes_tx.fetch_add(out.len() as u64, Ordering::Relaxed);
    Some(out)
}

fn err_resp(transaction_id: i32, message: &str) -> Vec<u8> {
    let mut b = vec![0u8; 32 + message.len()];
    let n = protocol::write_error_response(&mut b, transaction_id, message);
    b.truncate(n);
    b
}
