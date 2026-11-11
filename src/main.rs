//! Tsunami tracker entry point.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tsunami::access::AccessList;
use tsunami::config::Config;
use tsunami::stats::{to_json_string, Stats};
use tsunami::swarm::Store;
use tsunami::{http, rx_packet, udp};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> anyhow::Result<()> {
    // -c <path> | --config <path>
    let mut args = std::env::args().skip(1);
    let mut config_path: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config_path = args.next(),
            "-V" | "--version" => {
                println!("tsunami {VERSION}");
                return Ok(());
            }
            "-h" | "--help" => {
                println!("usage: tsunami [-c config.toml]");
                return Ok(());
            }
            _ => {}
        }
    }

    let config = Config::load(config_path.as_deref())?;
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&config.logging.level))
        .init();

    log::info!("tsunami v{VERSION} starting");

    let stats = Stats::new();
    stats
        .client_stats
        .set_ignore_prefixes(config.protocol.client_stats_ignore.clone());
    let shards = config.network.swarm_shards.max(1).next_power_of_two();
    let store = Arc::new(Store::new(
        shards,
        config.protocol.store_peer_id,
        config.protocol.peer_announce_interval,
        config.protocol.max_peer_age,
        config.protocol.max_response_peers,
    ));
    spawn_rate_sampler(&stats, &store);

    // Restore peer state from a previous snapshot (if enabled + file exists).
    // Done before workers bind so restored peers are live immediately.
    if config.snapshot.enable {
        restore_snapshot(&store, &config.snapshot.path);
    }

    let access_list = Arc::new(AccessList::new(
        &config.access_list.mode,
        config.access_list.file.clone(),
    ));
    if access_list.mode() != tsunami::access::Mode::Off {
        match access_list.reload() {
            Ok(n) => log::info!("access list: {} entries loaded", n),
            Err(e) => log::error!("access list load failed: {e:#}"),
        }
    }

    // UDP workers — io_uring backend (default) or AF_PACKET ring backend
    let n_udp = if config.network.socket_workers == 0 {
        std::thread::available_parallelism().map(Into::into).unwrap_or(1)
    } else {
        config.network.socket_workers
    };
    let _udp_handles = match config.network.rx_backend.as_str() {
        "af_packet" => {
            log::info!("RX backend: af_packet ({n_udp} workers)");
            rx_packet::run_packet_workers(
                config.clone(),
                store.clone(),
                stats.clone(),
                access_list.clone(),
            )?
        }
        "io_uring" => udp::run_workers(
            config.clone(),
            store.clone(),
            stats.clone(),
            access_list.clone(),
        )?,
        other => {
            log::warn!("unknown rx_backend '{other}'; falling back to io_uring");
            udp::run_workers(
                config.clone(),
                store.clone(),
                stats.clone(),
                access_list.clone(),
            )?
        }
    };

    // HTTP plane
    if config.http.enable {
        let _http_handles = http::run_http(
            config.clone(),
            store.clone(),
            stats.clone(),
            access_list.clone(),
        )?;
        log::info!("http listening on {}", config.http.bind);
    }

    // Cleaner threads — each owns a strided subset of shards.
    spawn_cleaners(&config, &store, &stats);

    // Maintenance thread: periodic stats logging + scrape export.
    spawn_maintenance(&config, &store, &stats);

    // Snapshot thread: periodic peer-state dump (if enabled).
    if config.snapshot.enable {
        spawn_snapshotter(&config, &store);
    }

    // SIGINT/SIGTERM -> final snapshot (if enabled) then exit.
    spawn_shutdown_handler(&config, &store);

    // SIGHUP -> reload access list (only if enabled in config)
    if config.access_list.reload_on_sighup {
        let access_list = access_list.clone();
        signal_hook::iterator::Signals::new([signal_hook::consts::SIGHUP])
            .map(|mut sigs| {
                std::thread::spawn(move || {
                    for _ in sigs.forever() {
                        match access_list.reload() {
                            Ok(n) => log::info!("access list reloaded: {n} entries"),
                            Err(e) => log::error!("access list reload failed: {e:#}"),
                        }
                    }
                })
            })
            .ok();
    }

    log::info!("tsunami ready");

    // Park forever; worker threads never return.
    loop {
        std::thread::park();
    }
}

fn spawn_cleaners(config: &Config, store: &Arc<Store>, stats: &Arc<Stats>) {
    let interval = Duration::from_secs(config.cleaning.interval.max(1));
    let nthreads = config.cleaning.threads.max(1);
    let num_shards = config.network.swarm_shards.max(1).next_power_of_two();

    // export path shared across threads via Arc
    let export_path = config.scrape_export.path.clone();
    let export_every = config.scrape_export.every_cycles;
    let export_enable = config.scrape_export.enable;

    for tid in 0..nthreads {
        let store = store.clone();
        let stats = stats.clone();
        let indices: Vec<usize> = (tid..num_shards).step_by(nthreads).collect();
        let export_path = export_path.clone();
        std::thread::Builder::new()
            .name(format!("cleaner-{tid:02}"))
            .spawn(move || {
                let mut cycle_local = 0usize;
                loop {
                    std::thread::sleep(interval);
                    let now = store_now_secs();
                    let (peers_removed, torrents_removed) = store.clean_shards(&indices, now);
                    if peers_removed > 0 {
                        stats
                            .peers_removed
                            .fetch_add(peers_removed, Ordering::Relaxed);
                    }
                    if tid == 0 {
                        cycle_local += 1;
                        if export_enable
                            && (export_every == 0 || cycle_local % export_every == 0)
                        {
                            if let Err(e) = write_scrape_export(&store, &export_path) {
                                log::warn!("scrape export failed: {e:#}");
                            }
                        }
                    }
                    let _ = torrents_removed;
                }
            })
            .expect("spawn cleaner");
    }
}

fn store_now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn write_scrape_export(store: &Store, path: &std::path::Path) -> anyhow::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&tmp)?);
    store.for_each_torrent(|hash, seeders, leechers| {
        let _ = writeln!(
            f,
            "{} {} {}",
            tsunami::access::infohash_hex(hash),
            seeders,
            leechers
        );
    });
    f.flush()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Feeds the stats rate ring once per second so windowed rates, the
/// dashboard time series, and system gauges are independent of who/when
/// stats endpoints are polled.
fn spawn_rate_sampler(stats: &Arc<Stats>, store: &Arc<Store>) {
    let stats = stats.clone();
    let store = store.clone();
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1)
        .max(1);
    let ticks = tsunami::stats::clock_ticks();
    let mut prev_jiffies = tsunami::stats::read_cpu_jiffies();
    let mut prev_instant = std::time::Instant::now();
    std::thread::Builder::new()
        .name("rate-sampler".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(tsunami::stats::RATE_SAMPLE_MS));
            // CPU% = process jiffies consumed / (wall jiffies * cores), as
            // percent*10. Measures fraction of total machine capacity used.
            let now = std::time::Instant::now();
            let jiffies = tsunami::stats::read_cpu_jiffies();
            let elapsed = now.duration_since(prev_instant).as_secs_f64().max(0.001);
            let cpu_secs = jiffies.saturating_sub(prev_jiffies) as f64 / ticks as f64;
            let cpu_percent_x10 =
                (cpu_secs / (elapsed * num_cpus as f64) * 1000.0).min(1000.0) as u64;
            prev_jiffies = jiffies;
            prev_instant = now;

            let (torrents, peers, seeders, leechers) = store.totals();
            let gauges = tsunami::stats::GaugeInput {
                torrents,
                peers,
                seeders,
                leechers,
                rss_bytes: tsunami::stats::read_rss_bytes(),
                swarm_bytes: store.memory_estimate_bytes(),
                cpu_percent_x10,
            };
            stats.push_rate_sample(&gauges);
        })
        .expect("spawn rate sampler");
}

fn spawn_maintenance(config: &Config, store: &Arc<Store>, stats: &Arc<Stats>) {
    let interval = Duration::from_secs(config.statistics.log_interval.max(1));
    let write_json_to = config.statistics.write_json_to.clone();
    let store = store.clone();
    let stats = stats.clone();
    std::thread::Builder::new()
        .name("maintenance".into())
        .spawn(move || {
            loop {
                std::thread::sleep(interval);
                let ft = store.totals_by_family();
                let totals = (
                    ft.0 .0 + ft.1 .0,
                    ft.0 .1 + ft.1 .1,
                    ft.0 .2 + ft.1 .2,
                    ft.0 .3 + ft.1 .3,
                );
                let created = store.torrents_created_total();
                let snap = stats.snapshot_json(
                    ft,
                    created,
                    store.memory_estimate_bytes(),
                    VERSION,
                );
                let s = to_json_string(&snap);
                // one-line summary for logs
                log::info!(
                    "stats: torrents={} peers={} seeders={} leechers={} req_rate={} rx_Bps={} tx_Bps={}",
                    totals.0,
                    totals.1,
                    totals.2,
                    totals.3,
                    snap["rates"]["requests_per_sec"],
                    snap["rates"]["bytes_rx_per_sec"],
                    snap["rates"]["bytes_tx_per_sec"],
                );
                if !write_json_to.as_os_str().is_empty() {
                    let tmp = write_json_to.with_extension("tmp");
                    if std::fs::write(&tmp, &s).is_ok() {
                        let _ = std::fs::rename(&tmp, &write_json_to);
                    }
                }
            }
        })
        .expect("spawn maintenance");
}

// ---------------- peer-state snapshot ----------------

/// Load a snapshot file into the store if it exists. Logs the outcome.
fn restore_snapshot(store: &Store, path: &std::path::Path) {
    if !path.exists() {
        log::info!("snapshot: no file at {}, starting empty", path.display());
        return;
    }
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("snapshot: cannot open {}: {e}", path.display());
            return;
        }
    };
    let mut r = std::io::BufReader::with_capacity(1 << 20, f);
    match store.load_snapshot(&mut r) {
        Ok((torrents, peers)) => {
            log::info!(
                "snapshot: restored {} torrents / {} peers from {}",
                torrents,
                peers,
                path.display()
            );
        }
        Err(e) => log::warn!("snapshot: load failed ({}): {e}", path.display()),
    }
}

/// Write the snapshot atomically: serialize to <path>.tmp then rename.
fn write_snapshot_file(store: &Store, path: &std::path::Path) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let f = std::fs::File::create(&tmp)?;
        let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
        store.write_snapshot(&mut w)?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Periodically dump peer state. interval_secs == 0 disables periodic dumps
/// (shutdown snapshot still happens via the signal handler).
fn spawn_snapshotter(config: &Config, store: &Arc<Store>) {
    let interval = Duration::from_secs(config.snapshot.interval_secs);
    let path = config.snapshot.path.clone();
    let store = store.clone();
    std::thread::Builder::new()
        .name("snapshotter".into())
        .spawn(move || {
            if interval.is_zero() {
                return; // shutdown-only snapshots
            }
            loop {
                std::thread::sleep(interval);
                match write_snapshot_file(&store, &path) {
                    Ok(()) => {
                        let t = store.totals();
                        log::info!(
                            "snapshot: wrote {} ({} torrents, {} peers)",
                            path.display(),
                            t.0,
                            t.1
                        );
                    }
                    Err(e) => log::warn!("snapshot: write failed: {e:#}"),
                }
            }
        })
        .expect("spawn snapshotter");
}

/// SIGINT/SIGTERM -> best-effort final snapshot, then exit.
fn spawn_shutdown_handler(config: &Config, store: &Arc<Store>) {
    let path = config.snapshot.path.clone();
    let enabled = config.snapshot.enable;
    let store = store.clone();
    signal_hook::iterator::Signals::new([signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM])
        .map(|mut sigs| {
            std::thread::spawn(move || {
                for sig in sigs.forever() {
                    log::info!("received signal {sig}, shutting down");
                    if enabled {
                        match write_snapshot_file(&store, &path) {
                            Ok(()) => log::info!("snapshot: final dump written to {}", path.display()),
                            Err(e) => log::warn!("snapshot: final dump failed: {e:#}"),
                        }
                    }
                    std::process::exit(0);
                }
            })
        })
        .ok();
}
