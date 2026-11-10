//! HTTP plane: BEP 3/BEP 12 tracker endpoints (announce + scrape) and a
//! JSON stats API for the website.
//!
//! Blocking threaded server with SO_REUSEPORT listeners — one thread per
//! config.http.threads. Announce/scrape share the same swarm store as UDP.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};

use crate::access::AccessList;
use crate::bencode::Encoder;
use crate::config::Config;
use crate::stats::Stats;
use crate::swarm::{AnnounceEvent as SwarmEvent, InfoHash, PeerEndpoint, Rng, Store};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn run_http(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
) -> anyhow::Result<Vec<std::thread::JoinHandle<()>>> {
    let threads = config.http.threads.max(1);
    let max_req = config.http.max_request_bytes.max(1024);
    let mut handles = Vec::new();
    for i in 0..threads {
        let store = store.clone();
        let stats = stats.clone();
        let access_list = access_list.clone();
        let config = config.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("http-{i:02}"))
                .spawn(move || {
                    if let Err(e) = http_thread(config, store, stats, access_list, max_req) {
                        log::error!("http thread {i} died: {e:#}");
                    }
                })
                .context("spawn http thread")?,
        );
    }
    Ok(handles)
}

fn create_listener(bind: SocketAddr) -> anyhow::Result<TcpListener> {
    let sock = Socket::new(Domain::for_address(bind), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.bind(&bind.into())?;
    sock.listen(1024)?;
    Ok(sock.into())
}

fn http_thread(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
    max_req: usize,
) -> anyhow::Result<()> {
    let listener = create_listener(config.http.bind)?;
    let mut rng = Rng::new();
    let mut scratch: Vec<PeerEndpoint> = Vec::with_capacity(256);
    let validator = crate::udp::validator::Validator::new(config.protocol.max_connection_age);
    loop {
        match listener.accept() {
            Ok((stream, _peer)) => {
                stats.http_connections.fetch_add(1, Ordering::Relaxed);
                let res = handle_conn(
                    stream,
                    _peer,
                    &config,
                    &store,
                    &stats,
                    &access_list,
                    &mut rng,
                    &mut scratch,
                    max_req,
                    &validator,
                );
                stats.http_connections.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = res {
                    log::debug!("http conn error: {e}");
                }
            }
            Err(e) => {
                log::error!("http accept: {e}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
}

type Response = (u16, &'static str, Vec<u8>);

fn handle_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: &Config,
    store: &Arc<Store>,
    stats: &Arc<Stats>,
    access_list: &Arc<AccessList>,
    rng: &mut Rng,
    scratch: &mut Vec<PeerEndpoint>,
    max_req: usize,
    validator: &crate::udp::validator::Validator,
) -> anyhow::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut buf = Vec::with_capacity(8192);

    // read until end of headers
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() >= max_req {
            return write_response(&mut stream, 431, "text/plain", b"request too large");
        }
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(())
            }
            Err(e) => return Err(e.into()),
        }
    };

    let head = &buf[..header_end];
    if crate::ws::is_websocket_upgrade(head) {
        return crate::ws::handle_upgrade(
            stream,
            head,
            peer,
            config.clone(),
            store.clone(),
            stats.clone(),
            access_list.clone(),
            validator.for_worker(),
        );
    }
    let req = match parse_head(head) {
        Some(r) => r,
        None => return write_response(&mut stream, 400, "text/plain", b"bad request"),
    };

    let (status, ctype, body) = route(
        &req, peer, config, store, stats, access_list, rng, scratch,
    );
    let head_len = head.len() as u64;
    let tx_len = body.len() as u64 + 160;
    stats.http.requests.fetch_add(1, Ordering::Relaxed);
    stats.http.bytes_rx.fetch_add(head_len, Ordering::Relaxed);
    stats.http.bytes_tx.fetch_add(tx_len, Ordering::Relaxed);
    write_response(&mut stream, status, ctype, &body)
}

#[allow(clippy::too_many_arguments)]
fn route(
    req: &Request,
    peer: SocketAddr,
    _config: &Config,
    store: &Arc<Store>,
    stats: &Arc<Stats>,
    access_list: &Arc<AccessList>,
    rng: &mut Rng,
    scratch: &mut Vec<PeerEndpoint>,
) -> Response {
    if req.method != "GET" && req.method != "HEAD" {
        return (405, "text/plain", b"method not allowed".to_vec());
    }
    let head_only = req.method == "HEAD";
    let resp = match req.path {
        "/announce" => announce_http(req.query, peer.ip(), store, stats, access_list, rng, scratch),
        "/scrape" => scrape_http(req.query, store),
        "/api/stats" => (
            200,
            "application/json",
            stats
                .snapshot_json(store.totals(), store.torrents_created_total(), VERSION)
                .to_string()
                .into_bytes(),
        ),
        "/metrics" => (
            200,
            "text/plain; version=0.0.4",
            stats
                .prometheus_text(store.totals(), store.torrents_created_total(), VERSION)
                .into_bytes(),
        ),
        "/api/torrents" => api_torrents(req.query, store),
        "/api/clients" => api_clients(req.query, stats),
        "/" => (
            200,
            "text/plain",
            format!("Tsunami tracker v{VERSION}\n").into_bytes(),
        ),
        _ => {
            if let Some(hex) = req.path.strip_prefix("/api/torrent/") {
                api_torrent(hex, req.query, store)
            } else {
                (404, "text/plain", b"not found".to_vec())
            }
        }
    };
    if head_only {
        (resp.0, resp.1, Vec::new())
    } else {
        resp
    }
}

// ---------------- HTTP parsing helpers ----------------

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_head(head: &[u8]) -> Option<Request<'_>> {
    let line_end = find_subslice(head, b"\r\n")?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    // split path?query
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };
    Some(Request {
        method,
        path,
        query,
    })
}

/// Percent-decode (no '+'->space; binary-safe for info_hash/peer_id).
fn pct_decode(input: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse query string into map of decoded key -> decoded value.
/// Keys are matched case-insensitively-insensitive: tracker params are
/// lowercase already; we keep raw bytes keys.
fn parse_query(query: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::with_capacity(16);
    let mut k = Vec::new();
    let mut v = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (ks, vs) = match pair.find('=') {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, ""),
        };
        pct_decode(ks.as_bytes(), &mut k);
        pct_decode(vs.as_bytes(), &mut v);
        out.push((k.clone(), v.clone()));
    }
    out
}

struct QueryParams(Vec<(Vec<u8>, Vec<u8>)>);
impl QueryParams {
    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
    }
    fn get_str(&self, key: &[u8]) -> Option<&str> {
        self.get(key).and_then(|v| std::str::from_utf8(v).ok())
    }
    fn get_i64(&self, key: &[u8]) -> Option<i64> {
        self.get_str(key)?.parse().ok()
    }
    fn get_u16(&self, key: &[u8]) -> Option<u16> {
        self.get_str(key)?.parse().ok()
    }
}
impl From<Vec<(Vec<u8>, Vec<u8>)>> for QueryParams {
    fn from(v: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        QueryParams(v)
    }
}

fn as_20(v: &[u8]) -> Option<[u8; 20]> {
    if v.len() == 20 {
        let mut a = [0u8; 20];
        a.copy_from_slice(v);
        Some(a)
    } else {
        None
    }
}

// ---------------- BEP 3 announce ----------------

fn announce_http(
    query: &str,
    src_ip: IpAddr,
    store: &Arc<Store>,
    stats: &Arc<Stats>,
    access_list: &Arc<AccessList>,
    rng: &mut Rng,
    scratch: &mut Vec<PeerEndpoint>,
) -> Response {
    let params: QueryParams = parse_query(query).into();
    let Some(info_hash) = params.get(b"info_hash").and_then(as_20) else {
        return (400, "text/plain", b"missing info_hash".to_vec());
    };
    let port = params.get_u16(b"port").unwrap_or(0);
    if port == 0 {
        return (400, "text/plain", b"missing port".to_vec());
    }
    let peer_id = params.get(b"peer_id").and_then(as_20).unwrap_or([0u8; 20]);
    let left = params.get_i64(b"left").unwrap_or(-1);
    let event = match params.get_str(b"event").unwrap_or("") {
        "started" => SwarmEvent::Started,
        "completed" => SwarmEvent::Completed,
        "stopped" => SwarmEvent::Stopped,
        _ => SwarmEvent::None,
    };
    let numwant = params.get_i64(b"numwant").unwrap_or(-1) as i32;
    let compact = params.get_i64(b"compact").unwrap_or(1) != 0;

    if !access_list.allows(&info_hash) {
        return (403, "text/plain", b"info hash not allowed".to_vec());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    stats.http.announces.fetch_add(1, Ordering::Relaxed);
    if store.store_peer_id {
        stats.client_stats.record(&peer_id);
    }

    match store.announce(
        &info_hash,
        src_ip,
        port,
        peer_id,
        left,
        event,
        numwant,
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
            // Bep 3 keys emitted in sorted order: complete, incomplete,
            // interval, min interval, peers[, peers6].
            let mut enc = Encoder::new();
            enc.dict_begin();
            enc.dict_int(b"complete", seeders as i64);
            enc.dict_int(b"incomplete", leechers as i64);
            enc.dict_int(b"interval", interval as i64);
            enc.dict_int(b"min interval", interval as i64);
            if compact {
                let mut peers_v4: Vec<u8> = Vec::with_capacity(scratch.len() * 6);
                let mut peers_v6: Vec<u8> = Vec::with_capacity(scratch.len() * 18);
                for p in scratch.iter() {
                    match p.ip {
                        IpAddr::V4(v4) => {
                            peers_v4.extend_from_slice(&v4.octets());
                            peers_v4.extend_from_slice(&p.port.to_be_bytes());
                        }
                        IpAddr::V6(v6) => {
                            peers_v6.extend_from_slice(&v6.octets());
                            peers_v6.extend_from_slice(&p.port.to_be_bytes());
                        }
                    }
                }
                enc.dict_bytes(b"peers", &peers_v4);
                if !peers_v6.is_empty() {
                    enc.dict_bytes(b"peers6", &peers_v6);
                }
            } else {
                enc.dict_raw(b"peers", &build_peer_list(scratch, store, &info_hash));
            }
            enc.dict_end();
            (200, "text/plain", enc.into_vec())
        }
        None => (400, "text/plain", b"announce failed".to_vec()),
    }
}

fn build_peer_list(
    peers: &[PeerEndpoint],
    store: &Arc<Store>,
    info_hash: &InfoHash,
) -> Vec<u8> {
    let mut list = Encoder::new();
    list.list_begin();
    for p in peers {
        let mut d = Encoder::new();
        d.dict_begin();
        d.dict_int(b"port", p.port as i64);
        let ipstr = p.ip.to_string();
        d.dict_bytes(b"ip", ipstr.as_bytes());
        if store.store_peer_id {
            if let Some(pid) = store.peer_id_for(info_hash, &p.ip, p.port) {
                d.dict_bytes(b"peer id", &pid);
            }
        }
        d.dict_end();
        list.list_raw(&d.into_vec());
    }
    list.list_end();
    list.into_vec()
}

// ---------------- BEP 12 scrape ----------------

fn scrape_http(query: &str, store: &Arc<Store>) -> Response {
    let params: QueryParams = parse_query(query).into();
    let mut hashes: Vec<InfoHash> = Vec::new();
    // collect all info_hash params (repeated key)
    for (k, v) in params.0.iter() {
        if k == b"info_hash" {
            if let Some(h) = as_20(v) {
                hashes.push(h);
            }
        }
    }
    if hashes.is_empty() {
        return (400, "text/plain", b"missing info_hash".to_vec());
    }
    let stats = store.scrape(&hashes);
    let mut enc = Encoder::new();
    enc.dict_begin();
    enc.dict_raw(b"files", &{
        let mut f = Encoder::new();
        f.dict_begin();
        for (h, &(s, _c, l)) in hashes.iter().zip(stats.iter()) {
            let mut d = Encoder::new();
            d.dict_begin();
            d.dict_int(b"complete", s as i64);
            d.dict_int(b"downloaded", 0);
            d.dict_int(b"incomplete", l as i64);
            d.dict_end();
            f.dict_raw(h, &d.into_vec());
        }
        f.dict_end();
        f.into_vec()
    });
    enc.dict_end();
    (200, "text/plain", enc.into_vec())
}

// ---------------- JSON APIs ----------------

fn api_torrents(query: &str, store: &Arc<Store>) -> Response {
    let params: QueryParams = parse_query(query).into();
    let limit = params
        .get_i64(b"limit")
        .unwrap_or(100)
        .clamp(1, 1000) as usize;
    let offset = params.get_i64(b"offset").unwrap_or(0).max(0) as usize;
    let mut all: Vec<(InfoHash, u32, u32)> = Vec::new();
    store.for_each_torrent(|h, s, l| all.push((*h, s, l)));
    // sort by total peers desc for a useful top-N
    all.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
    let total = all.len();
    let page: Vec<serde_json::Value> = all
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|(h, s, l)| {
            serde_json::json!({
                "info_hash": crate::access::infohash_hex(&h),
                "seeders": s,
                "leechers": l,
                "peers": s + l,
            })
        })
        .collect();
    (
        200,
        "application/json",
        serde_json::json!({ "total": total, "torrents": page }).to_string().into_bytes(),
    )
}

fn api_torrent(hex: &str, query: &str, store: &Arc<Store>) -> Response {
    let Some(hash) = crate::access::parse_infohash_hex(hex) else {
        return (400, "text/plain", b"bad info hash".to_vec());
    };
    let params: QueryParams = parse_query(query).into();
    let limit = params.get_i64(b"limit").unwrap_or(200).clamp(1, 5000) as usize;
    let Some((seeders, leechers, peers)) = store.torrent_detail(&hash, limit) else {
        return (404, "application/json", br#"{"error":"torrent not found"}"#.to_vec());
    };
    let peer_list: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            let mut o = serde_json::json!({ "ip": p.ip.to_string(), "port": p.port });
            if let Some(pid) = store.peer_id_for(&hash, &p.ip, p.port) {
                o["peer_id"] = serde_json::json!(String::from_utf8_lossy(&pid).trim_matches('\0').to_string());
            }
            o
        })
        .collect();
    (
        200,
        "application/json",
        serde_json::json!({
            "info_hash": crate::access::infohash_hex(&hash),
            "seeders": seeders,
            "leechers": leechers,
            "peers": peer_list,
        })
        .to_string()
        .into_bytes(),
    )
}

fn api_clients(query: &str, stats: &Arc<Stats>) -> Response {
    let params: QueryParams = parse_query(query).into();
    let n = params.get_i64(b"n").unwrap_or(50).clamp(1, 500) as usize;
    let clients: Vec<serde_json::Value> = stats
        .client_stats
        .top(n)
        .iter()
        .map(|&(k, c)| {
            let name = String::from_utf8_lossy(&k).trim_matches('\0').to_string();
            serde_json::json!({ "client": name, "announces": c })
        })
        .collect();
    (200, "application/json", serde_json::json!({ "clients": clients }).to_string().into_bytes())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> anyhow::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}
