//! Measure Store memory per peer.
use std::net::IpAddr;
use std::sync::Arc;
use tsunami::swarm::{AnnounceEvent, Rng, Store};

fn rss_mb() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    for l in s.lines() {
        if l.starts_with("VmRSS") {
            return l
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse::<f64>()
                .unwrap()
                / 1024.0;
        }
    }
    0.0
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000);
    let store = Arc::new(Store::new(
        64,
        false,
        1800,
        0,
        2700,
        50,
    ));
    let mut rng = Rng::new();
    let mut out = Vec::new();
    let hash = [0x42u8; 20];
    let pid = [0u8; 20];

    let base = rss_mb();
    let t0 = std::time::Instant::now();
    // UPDATE-heavy mode: N unique peers, then M total announces cycling
    let unique: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(n);
    let mut ips: Vec<IpAddr> = Vec::with_capacity(unique);
    for i in 0..unique {
        ips.push(IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            (i >> 16) as u8,
            (i >> 8) as u8,
            (i & 0xff) as u8,
        )));
    }
    for i in 0..n {
        let j = i % unique;
        let ip = ips[j];
        let port = (1024 + j % 59000) as u16;
        store.announce(
            &hash,
            ip,
            port,
            pid,
            1_000_000,
            AnnounceEvent::None,
            40,
            1000,
            &mut rng,
            &mut out,
        );
        if i % 200_000 == 0 && i > 0 {
            println!("{i}: rss={:.1}MB ({:.1} B/peer)", rss_mb(), (rss_mb() - base) * 1e6 / i as f64);
        }
    }
    let el = t0.elapsed();
    let rss = rss_mb();
    println!(
        "DONE n={n} rss={rss:.1}MB base={base:.1}MB delta={:.1}MB ({:.1} B/peer) in {:?} ({:.0} announces/s)",
        rss - base,
        (rss - base) * 1e6 / n as f64,
        el,
        n as f64 / el.as_secs_f64()
    );
    let totals = store.totals();
    println!("totals: {:?}", totals);
}
