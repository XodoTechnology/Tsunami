//! UDP load generator for Tsunami.
//!
//! Simulates N peers: each opens a UDP socket, performs a BEP 15 connect,
//! then announces in a tight loop. Reports aggregate pps / response stats.
//!
//! usage: tsunami-loadgen --target 127.0.0.1:6881 --peers 4096 [--seconds 30]
//!        [--numwant 50] [--seeders 0.2] [--threads 8] [--srcips 10.0.0.1,10.0.0.2]

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng as _;
use tsunami::protocol::PROTOCOL_IDENTIFIER;

struct Args {
    target: SocketAddr,
    peers: usize,
    seconds: u64,
    numwant: i32,
    seeder_frac: f64,
    threads: usize,
    rate: u64, // max announces/sec, 0 = unlimited
    info_hash: [u8; 20],
    torrents: usize,
    once: bool, // register each peer with a single announce, then idle
    srcips: Vec<String>, // source IPs to bind sockets to (round-robin); empty = auto
}

fn parse_args() -> Args {
    let mut a = Args {
        target: "127.0.0.1:6881".parse().unwrap(),
        peers: 1024,
        seconds: 30,
        numwant: 50,
        seeder_frac: 0.0,
        threads: 8,
        rate: 0,
        info_hash: [0x42; 20],
        torrents: 1,
        once: false,
        srcips: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        if k == "--once" {
            a.once = true;
            continue;
        }
        let v = it.next().unwrap_or_default();
        match k.as_str() {
            "--target" => a.target = v.parse().unwrap(),
            "--peers" => a.peers = v.parse().unwrap(),
            "--seconds" => a.seconds = v.parse().unwrap(),
            "--numwant" => a.numwant = v.parse().unwrap(),
            "--seeders" => a.seeder_frac = v.parse().unwrap(),
            "--threads" => a.threads = v.parse().unwrap(),
            "--rate" => a.rate = v.parse().unwrap(),
            "--torrents" => a.torrents = v.parse().unwrap(),
            "--hash" => {
                if v.len() == 40 {
                    for i in 0..20 {
                        a.info_hash[i] = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16).unwrap();
                    }
                }
            }
            "--srcips" => {
                a.srcips = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            }
            _ => {}
        }
    }
    a
}

fn be32(v: i32) -> [u8; 4] {
    v.to_be_bytes()
}
fn be64(v: i64) -> [u8; 8] {
    v.to_be_bytes()
}

fn connect_pkt(txid: i32) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..8].copy_from_slice(&PROTOCOL_IDENTIFIER.to_be_bytes());
    p[8..12].copy_from_slice(&be32(0));
    p[12..16].copy_from_slice(&be32(txid));
    p
}

fn announce_pkt(
    conn_id: i64,
    txid: i32,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
    left: i64,
    event: i32,
    numwant: i32,
) -> [u8; 98] {
    let mut p = [0u8; 98];
    p[0..8].copy_from_slice(&conn_id.to_be_bytes());
    p[8..12].copy_from_slice(&be32(1));
    p[12..16].copy_from_slice(&be32(txid));
    p[16..36].copy_from_slice(info_hash);
    p[36..56].copy_from_slice(peer_id);
    // downloaded 56..64, left 64..72, uploaded 72..80
    p[64..72].copy_from_slice(&be64(left));
    p[80..84].copy_from_slice(&be32(event));
    p[88..92].copy_from_slice(&be32(0)); // key
    p[92..96].copy_from_slice(&be32(numwant));
    p[96..98].copy_from_slice(&port.to_be_bytes());
    p
}

fn parse_conn_id(resp: &[u8]) -> Option<i64> {
    if resp.len() >= 16 {
        Some(i64::from_be_bytes(resp[8..16].try_into().unwrap()))
    } else {
        None
    }
}

fn main() {
    let args = Arc::new(parse_args());
    let sent = Arc::new(AtomicU64::new(0));
    let recv = Arc::new(AtomicU64::new(0));
    let errs = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(args.seconds);

    let mut handles = Vec::new();
    for t in 0..args.threads {
        let args = args.clone();
        let sent = sent.clone();
        let recv = recv.clone();
        let errs = errs.clone();
        handles.push(std::thread::spawn(move || {
            worker(t, args, sent, recv, errs, deadline);
        }));
    }

    // reporter
    let mut last = (0u64, 0u64);
    let start = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let s = sent.load(Ordering::Relaxed);
        let r = recv.load(Ordering::Relaxed);
        let e = errs.load(Ordering::Relaxed);
        let dt = start.elapsed().as_secs_f64();
        println!(
            "[{:>5.1}s] sent={:>10} ({:>9.0}/s) recv={:>10} ({:>9.0}/s) err={} loss={:.1}%",
            dt,
            s,
            s as f64 / dt,
            r,
            r as f64 / dt,
            e,
            if s > 0 { (1.0 - r as f64 / s as f64) * 100.0 } else { 0.0 },
        );
        last = (s, r);
    }
    for h in handles {
        let _ = h.join();
    }
    let _ = last;
}

fn worker(
    tid: usize,
    args: Arc<Args>,
    sent: Arc<AtomicU64>,
    recv: Arc<AtomicU64>,
    errs: Arc<AtomicU64>,
    deadline: Instant,
) {
    let per_thread = args.peers / args.threads.max(1);
    let mut rng = rand::rng();
    let mut sockets: Vec<UdpSocket> = Vec::with_capacity(per_thread);
    let mut peer_ids: Vec<[u8; 20]> = Vec::with_capacity(per_thread);
    let mut conn_ids: Vec<i64> = Vec::with_capacity(per_thread);
    let mut txid = (tid as i32) * 1_000_000;

    // bind sockets — with --srcips, round-robin across them so peers get
    // distinct (ip,port) tuples and each IP keeps its own ~64k port space.
    // Without it, bind 0.0.0.0 and let the kernel pick the route's source.
    for i in 0..per_thread {
        let gidx = tid * per_thread + i;
        let bind_str = if args.srcips.is_empty() {
            "0.0.0.0:0".to_string()
        } else {
            format!("{}:0", args.srcips[gidx % args.srcips.len()])
        };
        let sock = match UdpSocket::bind(&bind_str) {
            Ok(s) => s,
            Err(_) => break,
        };
        let _ = sock.set_nonblocking(true);
        let _ = sock.connect(args.target);
        let local_port = sock.local_addr().unwrap().port();
        let mut pid = [0u8; 20];
        pid[..8].copy_from_slice(b"-TS0001-");
        pid[8..12].copy_from_slice(&(tid as u32 * 100_000 + i as u32).to_be_bytes());
        peer_ids.push(pid);
        sockets.push(sock);
        conn_ids.push(0);
        let _ = local_port;
    }
    let n = sockets.len();
    if n == 0 {
        return;
    }

    // connect phase
    let mut buf = [0u8; 2048];
    for round in 0..3 {
        for (i, sock) in sockets.iter().enumerate() {
            txid += 1;
            let pkt = connect_pkt(txid);
            let _ = sock.send(&pkt);
            sent.fetch_add(1, Ordering::Relaxed);
            // try immediate recv
            if let Ok(m) = sock.recv(&mut buf) {
                if let Some(cid) = parse_conn_id(&buf[..m]) {
                    conn_ids[i] = cid;
                }
            }
        }
        // drain
        let until = Instant::now() + Duration::from_millis(200);
        while Instant::now() < until {
            let mut got = false;
            for (i, sock) in sockets.iter().enumerate() {
                if let Ok(m) = sock.recv(&mut buf) {
                    got = true;
                    recv.fetch_add(1, Ordering::Relaxed);
                    if let Some(cid) = parse_conn_id(&buf[..m]) {
                        conn_ids[i] = cid;
                    }
                }
            }
            if !got {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        if conn_ids.iter().filter(|&&c| c != 0).count() > n / 2 || round == 2 {
            break;
        }
    }
    let connected = conn_ids.iter().filter(|&&c| c != 0).count();
    eprintln!("[t{tid}] {connected}/{n} connected");

    if args.once {
        // one announce per peer (event=started), paced, then idle-drain
        let mut buf2 = [0u8; 2048];
        for i in 0..n {
            if conn_ids[i] == 0 { continue; }
            let mut h = args.info_hash;
            if args.torrents > 1 {
                let t = (i % args.torrents) as u32;
                h[0..4].copy_from_slice(&t.to_be_bytes());
            }
            txid += 1;
            let is_seeder = rng.random::<f64>() < args.seeder_frac;
            let pkt = announce_pkt(
                conn_ids[i], txid, &h, &peer_ids[i],
                sockets[i].local_addr().map(|a| a.port()).unwrap_or(0),
                if is_seeder { 0 } else { 1_000_000 }, 2, args.numwant,
            );
            let _ = sockets[i].send(&pkt);
            sent.fetch_add(1, Ordering::Relaxed);
            while let Ok(m) = sockets[i].recv(&mut buf2) {
                let _ = m; recv.fetch_add(1, Ordering::Relaxed);
            }
        }
        while Instant::now() < deadline {
            let mut got = false;
            for s in sockets.iter() {
                while let Ok(m) = s.recv(&mut buf2) {
                    let _ = m; recv.fetch_add(1, Ordering::Relaxed); got = true;
                }
            }
            if !got { std::thread::sleep(Duration::from_millis(20)); }
        }
        return;
    }

    // announce loop
    let mut idx = 0usize;
    let mut since_pace = 0u32;
    let mut pace_tick = Instant::now();
    // per-thread share of the global rate cap
    let thread_rate = if args.rate > 0 {
        (args.rate / args.threads.max(1) as u64).max(1)
    } else {
        0
    };
    while Instant::now() < deadline {
        let sock = &sockets[idx % n];
        let cid = conn_ids[idx % n];
        let pid = peer_ids[idx % n];
        let is_seeder = rng.random::<f64>() < args.seeder_frac;
        let left = if is_seeder { 0 } else { 1_000_000 };
        let event = if idx < n { 2 } else { 0 }; // started for first pass
        let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let mut h = args.info_hash;
        if args.torrents > 1 {
            let t = ((idx % n) % args.torrents) as u32;
            h[0..4].copy_from_slice(&t.to_be_bytes());
        }
        txid += 1;
        let pkt = announce_pkt(
            cid,
            txid,
            &h,
            &pid,
            local_port,
            left,
            event,
            args.numwant,
        );
        match sock.send(&pkt) {
            Ok(_) => {
                sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                errs.fetch_add(1, Ordering::Relaxed);
            }
        }
        idx += 1;
        since_pace += 1;

        // drain this socket's responses every 64 sends — a recv() syscall
        // per announce was the send-rate bottleneck; buffers hold the backlog
        if idx % 64 == 0 {
            while let Ok(m) = sock.recv(&mut buf) {
                let _ = m;
                recv.fetch_add(1, Ordering::Relaxed);
            }
        }

        // rate pacing: every 256 announces, budget thread_rate's share of
        // wall time for the whole batch (work + sleep), no catch-up bursts
        if thread_rate > 0 && since_pace >= 256 {
            since_pace = 0;
            let target = Duration::from_secs_f64(256.0 / thread_rate as f64);
            pace_tick += target;
            let now = Instant::now();
            if pace_tick > now {
                std::thread::sleep(pace_tick - now);
            } else {
                pace_tick = now;
            }
        }

        // opportunistic recv drain every 64 sends
        if idx % 64 == 0 {
            for s in sockets.iter() {
                while let Ok(m) = s.recv(&mut buf) {
                    recv.fetch_add(1, Ordering::Relaxed);
                    let _ = m;
                }
            }
        }
    }
}
