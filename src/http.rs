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

/// Self-contained HTML stats dashboard (no external assets/CDN).
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

pub fn run_http(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
) -> anyhow::Result<Vec<std::thread::JoinHandle<()>>> {
    let threads = config.http.threads.max(1);
    let max_req = config.http.max_request_bytes.max(1024);
    // One shared validator key across all HTTP threads so BEP-15 connection
    // ids issued on one thread validate on another (SO_REUSEPORT spreads conns).
    let validator = Arc::new(crate::udp::validator::Validator::new(
        config.protocol.max_connection_age,
        &config.protocol.conn_key_path,
    ));
    let mut handles = Vec::new();
    for i in 0..threads {
        let store = store.clone();
        let stats = stats.clone();
        let access_list = access_list.clone();
        let config = config.clone();
        let validator = validator.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("http-{i:02}"))
                .spawn(move || {
                    if let Err(e) = http_thread(config, store, stats, access_list, max_req, validator) {
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
    validator: Arc<crate::udp::validator::Validator>,
) -> anyhow::Result<()> {
    let listener = create_listener(config.http.bind)?;
    let mut rng = Rng::new();
    let mut scratch: Vec<PeerEndpoint> = Vec::with_capacity(256);
    // Cheap clone sharing the parent key + start instant.
    let validator = validator.for_worker();
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
    // The direct TCP peer is authoritative for admin allowlisting — the
    // forwarded client IP (below) is for peer identity and could be spoofed
    // if proxy_ip_header is misconfigured, so it must NOT gate admin access.
    let conn_ip = peer.ip();
    // When a trusted proxy header is configured, the real client IP comes
    // from it rather than the TCP peer — applies to WebSocket, /bep15 and
    // every HTTP route uniformly.
    let peer = match forwarded_client_ip(head, &config.http.proxy_ip_header) {
        Some(ip) => SocketAddr::new(ip, peer.port()),
        None => peer,
    };
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

    // Raw BEP-15 over HTTP: POST /bep15 with the same binary payload a UDP
    // client would send; response is the same binary reply. Lets UDP-protocol
    // tooling work over HTTP(S).
    if req.method == "POST" && (req.path == "/bep15" || req.path == "/udp") {
        let clen = content_length(head).unwrap_or(0);
        if clen > max_req {
            return write_response(&mut stream, 413, "text/plain", b"body too large");
        }
        let mut body = buf[header_end..].to_vec();
        while body.len() < clen {
            let mut chunk = [0u8; 8192];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(())
                }
                Err(e) => return Err(e.into()),
            }
        }
        body.truncate(clen);
        let mut v = validator.for_worker();
        let resp = crate::ws::dispatch(
            &body,
            peer.ip(),
            peer,
            config,
            store,
            stats,
            access_list,
            &mut v,
            rng,
            scratch,
        );
        // dispatch() already accounts requests/bytes_rx/bytes_tx + proto counters.
        return match resp {
            Some(bytes) => {
                write_response(&mut stream, 200, "application/octet-stream", &bytes)
            }
            None => write_response(&mut stream, 204, "application/octet-stream", b""),
        };
    }

    // Admin/stats routes may require auth or an IP allowlist. Public tracker
    // endpoints (/announce, /scrape, /bep15, WebSocket) are never gated.
    if is_admin_path(req.path) && admin_protected(&config.http) {
        if let Some(code) = admin_gate(head, conn_ip, &config.http) {
            return write_admin_denied(&mut stream, code);
        }
    }

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
    config: &Config,
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
        p if p == "/announce" || p.starts_with("/announce/") => announce_http(
            req.query,
            peer.ip(),
            config.protocol.allow_client_ip,
            store,
            stats,
            access_list,
            &config.passkeys.keys,
            p.strip_prefix("/announce/").filter(|s| !s.is_empty()),
            rng,
            scratch,
        ),
        "/scrape" => scrape_http(req.query, store, config.http.full_scrape),
        "/api/stats" => (
            200,
            "application/json",
            stats
                .snapshot_json(
                    store.totals_by_family(),
                    store.torrents_created_total(),
                    store.memory_estimate_bytes(),
                    VERSION,
                )
                .to_string()
                .into_bytes(),
        ),
        "/api/timeseries" => api_timeseries(req.query, stats),
        "/api/timeseries.csv" => api_timeseries_csv(req.query, stats),
        "/api/stats.csv" => (
            200,
            "text/csv; charset=utf-8",
            stats
                .stats_csv(
                    store.totals_by_family(),
                    store.torrents_created_total(),
                    store.memory_estimate_bytes(),
                    VERSION,
                )
                .into_bytes(),
        ),
        "/api/stats.txt" => (
            200,
            "text/plain; charset=utf-8",
            stats
                .stats_txt(
                    store.totals_by_family(),
                    store.torrents_created_total(),
                    store.memory_estimate_bytes(),
                    VERSION,
                )
                .into_bytes(),
        ),
        "/metrics" => (
            200,
            "text/plain; version=0.0.4",
            stats
                .prometheus_text(
                    store.totals_by_family(),
                    store.torrents_created_total(),
                    store.memory_estimate_bytes(),
                    VERSION,
                )
                .into_bytes(),
        ),
        "/api/torrents" => api_torrents(req.query, store),
        "/api/clients" => api_clients(req.query, stats),
        "/" | "/dashboard" => {
            if config.http.dashboard {
                (
                    200,
                    "text/html; charset=utf-8",
                    DASHBOARD_HTML.as_bytes().to_vec(),
                )
            } else if req.path == "/" {
                (
                    200,
                    "text/plain",
                    format!("Tsunami tracker v{VERSION}\n").into_bytes(),
                )
            } else {
                (404, "text/plain", b"not found".to_vec())
            }
        }
        _ => {
            if let Some(hex) = req.path.strip_prefix("/api/torrent/") {
                api_torrent(hex, req.query, store, config.http.mask_peer_ips)
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

/// Resolve the real client IP from a trusted proxy header (e.g.
/// "X-Forwarded-For", "X-Real-IP"). Returns the first address of the first
/// matching header, or None when the header is absent/unparseable so the
/// caller falls back to the TCP peer address.
fn forwarded_client_ip(head: &[u8], header_name: &str) -> Option<IpAddr> {
    if header_name.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case(header_name) {
            continue;
        }
        // X-Forwarded-For is a comma list; the leftmost entry is the client.
        let first = v.split(',').next()?.trim();
        return first.parse::<IpAddr>().ok();
    }
    None
}

/// Extract `Content-Length: N` from raw request headers (case-insensitive).
fn content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().ok();
            }
        }
    }
    None
}

// ---------------- admin auth ----------------

/// Paths that expose operational data and may be gated.
fn is_admin_path(path: &str) -> bool {
    path == "/" || path == "/dashboard" || path == "/metrics" || path.starts_with("/api/")
}

/// Whether any admin protection is configured (user or allowlist).
fn admin_protected(cfg: &crate::config::HttpConfig) -> bool {
    !cfg.admin_user.is_empty() || !cfg.admin_allowlist.is_empty()
}

/// Returns None when the request may proceed, or Some(status) to reject.
/// Allowlisted IPs bypass password auth; other clients need valid Basic
/// credentials when `admin_user` is set. With only an allowlist configured,
/// non-listed IPs get 403.
fn admin_gate(head: &[u8], ip: IpAddr, cfg: &crate::config::HttpConfig) -> Option<u16> {
    if ip_in_allowlist(ip, &cfg.admin_allowlist) {
        return None;
    }
    if !cfg.admin_user.is_empty() {
        return if basic_auth_ok(head, cfg) { None } else { Some(401) };
    }
    if cfg.admin_allowlist.is_empty() {
        None
    } else {
        Some(403)
    }
}

fn ip_in_allowlist(ip: IpAddr, list: &[String]) -> bool {
    list.iter().any(|e| cidr_match(e.trim(), ip))
}

/// Match an IP against "addr", "addr/prefix" (IPv4 /0-32, IPv6 /0-128).
fn cidr_match(entry: &str, ip: IpAddr) -> bool {
    let (addr_s, prefix) = match entry.split_once('/') {
        Some((a, p)) => match p.parse::<u32>() {
            Ok(n) => (a, Some(n)),
            Err(_) => return false,
        },
        None => (entry, None),
    };
    let Ok(net) = addr_s.parse::<IpAddr>() else {
        return false;
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let p = prefix.unwrap_or(32);
            if p > 32 {
                return false;
            }
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let p = prefix.unwrap_or(128);
            if p > 128 {
                return false;
            }
            v6_prefix_eq(&n.octets(), &i.octets(), p as usize)
        }
        _ => false,
    }
}

fn v6_prefix_eq(a: &[u8; 16], b: &[u8; 16], bits: usize) -> bool {
    let full = bits / 8;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Validate an `Authorization: Basic base64(user:pass)` header against the
/// configured admin credentials (constant-time compare).
fn basic_auth_ok(head: &[u8], cfg: &crate::config::HttpConfig) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("authorization") {
            continue;
        }
        let v = v.trim();
        let mut parts = v.splitn(2, ' ');
        let (scheme, token) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if !scheme.eq_ignore_ascii_case("basic") || token.is_empty() {
            continue;
        }
        let Some(decoded) = b64_decode(token.as_bytes()) else {
            return false;
        };
        let Ok(creds) = std::str::from_utf8(&decoded) else {
            return false;
        };
        let Some((user, pass)) = creds.split_once(':') else {
            return false;
        };
        return constant_time_eq::constant_time_eq(user.as_bytes(), cfg.admin_user.as_bytes())
            && constant_time_eq::constant_time_eq(pass.as_bytes(), cfg.admin_password.as_bytes());
    }
    false
}

/// Minimal standard-alphabet base64 decoder (handles padding + whitespace).
/// Returns None on malformed input.
fn b64_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some((b - b'A') as u32),
            b'a'..=b'z' => Some((b - b'a' + 26) as u32),
            b'0'..=b'9' => Some((b - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut sextets: Vec<u32> = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            b'=' => break, // padding terminates the data
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => sextets.push(val(b)?),
        }
    }
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for chunk in sextets.chunks(4) {
        let n = chunk.len();
        if n < 2 {
            return None; // a lone sextet can't encode a byte
        }
        let triple = (chunk[0] << 18)
            | (chunk[1] << 12)
            | (if n > 2 { chunk[2] } else { 0 } << 6)
            | if n > 3 { chunk[3] } else { 0 };
        out.push((triple >> 16) as u8);
        if n > 2 {
            out.push((triple >> 8) as u8);
        }
        if n > 3 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

/// Write a 401 (with WWW-Authenticate) or 403 rejection for admin routes.
fn write_admin_denied(stream: &mut TcpStream, code: u16) -> anyhow::Result<()> {
    let (reason, body, extra) = match code {
        401 => (
            "Unauthorized",
            &b"authentication required"[..],
            "WWW-Authenticate: Basic realm=\"tsunami\"\r\n",
        ),
        _ => ("Forbidden", &b"forbidden"[..], ""),
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
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
    allow_client_ip: bool,
    store: &Arc<Store>,
    stats: &Arc<Stats>,
    access_list: &Arc<AccessList>,
    passkeys: &std::collections::HashMap<String, Vec<String>>,
    passkey: Option<&str>,
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
        "paused" => SwarmEvent::Paused,
        _ => SwarmEvent::None,
    };
    let numwant = params.get_i64(b"numwant").unwrap_or(-1) as i32;
    let compact = params.get_i64(b"compact").unwrap_or(1) != 0;
    // Optional client-supplied IP (BEP-3 `ip=`) becomes the swarm address
    // only when allow_client_ip is on; the connection IP stays authoritative
    // for access checks and stats.
    let announce_ip = if allow_client_ip {
        params
            .get_str(b"ip")
            .and_then(|s| s.parse::<IpAddr>().ok())
            .unwrap_or(src_ip)
    } else {
        src_ip
    };

    // Optional private-tracker passkey from `/announce/<passkey>`: the key
    // must exist, and when it carries a hash allowlist it must cover this
    // info_hash. A valid passkey satisfies the access list for that torrent.
    let mut passkey_ok = false;
    if let Some(pk) = passkey {
        match passkeys.get(pk) {
            Some(allowed) => {
                if allowed.is_empty() {
                    passkey_ok = true;
                } else {
                    let ih = crate::access::infohash_hex(&info_hash);
                    passkey_ok = allowed.iter().any(|h| h.eq_ignore_ascii_case(&ih));
                }
                if !passkey_ok {
                    return (403, "text/plain", b"info hash not allowed for passkey".to_vec());
                }
            }
            None => return (403, "text/plain", b"invalid passkey".to_vec()),
        }
    }
    if !passkey_ok && !access_list.allows(&info_hash) {
        return (403, "text/plain", b"info hash not allowed".to_vec());
    }
    if crate::protocol::synthetic_peer_id(&peer_id) {
        stats.http.blocked.fetch_add(1, Ordering::Relaxed);
        return (400, "text/plain", b"invalid peer_id".to_vec());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);

    stats.http.announces.fetch_add(1, Ordering::Relaxed);
    match event {
        SwarmEvent::Started => {
            stats.http.ev_started.fetch_add(1, Ordering::Relaxed);
        }
        SwarmEvent::Completed => {
            stats.http.ev_completed.fetch_add(1, Ordering::Relaxed);
        }
        SwarmEvent::Stopped => {
            stats.http.ev_stopped.fetch_add(1, Ordering::Relaxed);
        }
        SwarmEvent::Paused | SwarmEvent::None => {}
    }
    if store.store_peer_id {
        stats.client_stats.record(&peer_id);
    }

    match store.announce(
        &info_hash,
        announce_ip,
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
            crate::hooks::announce_event(
                event, &info_hash, announce_ip, port, &peer_id, left, now,
            );
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

fn scrape_http(query: &str, store: &Arc<Store>, full_scrape: bool) -> Response {
    let params: QueryParams = parse_query(query).into();
    // collect all info_hash params (repeated key)
    let mut hashes: Vec<InfoHash> = Vec::new();
    for (k, v) in params.0.iter() {
        if k == b"info_hash" {
            if let Some(h) = as_20(v) {
                hashes.push(h);
            }
        }
    }
    // (info_hash, complete/seeders, incomplete/leechers, downloaders) rows
    let mut rows: Vec<(InfoHash, i64, i64, i64)> = Vec::new();
    if hashes.is_empty() {
        if !full_scrape {
            return (400, "text/plain", b"missing info_hash".to_vec());
        }
        // BEP-12 "full scrape": every tracked torrent.
        for (h, s, l, d) in store.all_scrape() {
            rows.push((h, s as i64, l as i64, d as i64));
        }
    } else {
        let stats = store.scrape(&hashes);
        for (h, &(s, _c, l, d)) in hashes.iter().zip(stats.iter()) {
            rows.push((*h, s as i64, l as i64, d as i64));
        }
    }
    let mut enc = Encoder::new();
    enc.dict_begin();
    enc.dict_raw(b"files", &{
        let mut f = Encoder::new();
        f.dict_begin();
        for (h, s, l, d) in &rows {
            let mut d_enc = Encoder::new();
            d_enc.dict_begin();
            d_enc.dict_int(b"complete", *s);
            d_enc.dict_int(b"downloaded", 0);
            d_enc.dict_int(b"downloaders", *d);
            d_enc.dict_int(b"incomplete", *l);
            d_enc.dict_end();
            f.dict_raw(h, &d_enc.into_vec());
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
    // Same counting semantics as iterating both family stores.
    let total = store.totals().0 as usize;

    // Bounded min-heap of the top offset+limit torrents by peer count.
    // Avoids materializing and sorting every torrent per request; the heap
    // is capped so absurd offsets can't force a giant allocation.
    let want = offset.saturating_add(limit).min(200_000);
    if offset >= want || total == 0 {
        return (
            200,
            "application/json",
            serde_json::json!({ "total": total, "torrents": [] })
                .to_string()
                .into_bytes(),
        );
    }
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut heap: BinaryHeap<Reverse<(u64, InfoHash, u32, u32)>> =
        BinaryHeap::with_capacity(want + 1);
    store.for_each_torrent(|h, s, l| {
        let peers = s as u64 + l as u64;
        let item = Reverse((peers, *h, s, l));
        if heap.len() < want {
            heap.push(item);
        } else if let Some(&Reverse((top_peers, _, _, _))) = heap.peek() {
            if peers > top_peers {
                heap.pop();
                heap.push(item);
            }
        }
    });
    let mut top: Vec<(InfoHash, u32, u32)> = heap
        .into_iter()
        .map(|Reverse((_, h, s, l))| (h, s, l))
        .collect();
    top.sort_by(|a, b| (b.1 + b.2).cmp(&(a.1 + a.2)));
    let page: Vec<serde_json::Value> = top
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

/// Privacy mask for peer IPs in stats APIs: keep the first and last
/// components visible, mask the middle. IPv4 `a.b.c.d` -> `a.xxx.xxx.d`;
/// IPv6 -> first two hextets + `xxxx` placeholders + last hextet
/// (`2001:db8:xxxx:xxxx::1` style).
fn mask_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.xxx.xxx.{}", o[0], o[3])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:xxxx:xxxx::{:x}", s[0], s[1], s[7])
        }
    }
}

fn api_torrent(hex: &str, query: &str, store: &Arc<Store>, mask_ips: bool) -> Response {
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
        .map(|(p, seeder)| {
            let mut o = serde_json::json!({
                "ip": if mask_ips { mask_ip(&p.ip) } else { p.ip.to_string() },
                "port": p.port,
                "seeder": seeder,
            });
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
            "ip_masked": mask_ips,
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
            serde_json::json!({ "client": crate::peerid::client_name(&k), "announces": c })
        })
        .collect();
    (200, "application/json", serde_json::json!({ "clients": clients }).to_string().into_bytes())
}

/// GET /api/timeseries?seconds=N — per-second samples for dashboard graphs.
fn api_timeseries(query: &str, stats: &Arc<Stats>) -> Response {
    let params: QueryParams = parse_query(query).into();
    let seconds = params.get_i64(b"seconds").unwrap_or(300).clamp(10, 3600) as u64;
    (
        200,
        "application/json",
        stats.timeseries_json(seconds).to_string().into_bytes(),
    )
}

/// GET /api/timeseries.csv?seconds=N — wide CSV of the same samples,
/// for log pipelines / spreadsheets / TSDB import.
fn api_timeseries_csv(query: &str, stats: &Arc<Stats>) -> Response {
    let params: QueryParams = parse_query(query).into();
    let seconds = params.get_i64(b"seconds").unwrap_or(300).clamp(10, 3600) as u64;
    (
        200,
        "text/csv; charset=utf-8",
        stats.timeseries_csv(seconds).into_bytes(),
    )
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
        204 => "No Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
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

#[cfg(test)]
mod tests {
    use super::mask_ip;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn mask_ipv4_keeps_first_and_last() {
        assert_eq!(
            mask_ip(&IpAddr::from_str("203.0.113.11").unwrap()),
            "203.xxx.xxx.11"
        );
        assert_eq!(
            mask_ip(&IpAddr::from_str("127.0.0.1").unwrap()),
            "127.xxx.xxx.1"
        );
        assert_eq!(
            mask_ip(&IpAddr::from_str("10.0.0.0").unwrap()),
            "10.xxx.xxx.0"
        );
    }

    #[test]
    fn mask_ipv6_keeps_first_two_and_last() {
        assert_eq!(
            mask_ip(&IpAddr::from_str("2001:db8:1:2:3:4:5:6").unwrap()),
            "2001:db8:xxxx:xxxx::6"
        );
        assert_eq!(
            mask_ip(&IpAddr::from_str("2000:3000:aaaa:bbbb:cccc:dddd:eeee:1234").unwrap()),
            "2000:3000:xxxx:xxxx::1234"
        );
        assert_eq!(
            mask_ip(&IpAddr::from_str("::1").unwrap()),
            "0:0:xxxx:xxxx::1"
        );
    }
}
