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
    let shards = config.network.swarm_shards.max(1).next_power_of_two();
    let store = Arc::new(Store::new(
        shards,
        config.protocol.store_peer_id,
        config.protocol.peer_announce_interval,
        config.protocol.max_peer_age,
        config.protocol.max_response_peers,
    ));
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
    let _udp_handles = if config.network.rx_backend == "af_packet" {
        log::info!("RX backend: af_packet ({} workers)", config.network.socket_workers.max(1));
        rx_packet::run_packet_workers(
            config.clone(),
            store.clone(),
            stats.clone(),
            access_list.clone(),
        )?
    } else {
        udp::run_workers(
            config.clone(),
            store.clone(),
            stats.clone(),
            access_list.clone(),
        )?
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

    // SIGHUP -> reload access list
    {
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
                let totals = store.totals();
                let created = store.torrents_created_total();
                let snap = stats.snapshot_json(totals, created, VERSION);
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
