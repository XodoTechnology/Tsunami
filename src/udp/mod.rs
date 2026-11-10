//! io_uring UDP socket workers.
//!
//! Each worker owns an IoUring, one provided-buffer ring for RX (multishot
//! recvmsg), a pool of send buffers, and SO_REUSEPORT sockets. Requests are
//! processed in-thread against the shared swarm store — the hot path does
//! no per-packet heap allocation.

pub mod buf_ring;
pub mod send_buffers;
pub mod validator;

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use io_uring::opcode::RecvMsgMulti;
use io_uring::types::Fixed;
use io_uring::IoUring;
use socket2::{Domain, Protocol, Socket, Type};

use crate::access::AccessList;
use crate::config::Config;
use crate::protocol::{self, ParseFailure, ParseResult, ParsedRequest};
use crate::stats::{ProtoStats, Stats};
use crate::swarm::{AnnounceEvent, InfoHash, PeerEndpoint, Rng, Store};

use self::buf_ring::BufRing;
use self::send_buffers::SendBuffers;
use self::validator::Validator;

const REQUEST_BUF_LEN: usize = 2048;
const USER_DATA_RECV_V4: u64 = u64::MAX;
const USER_DATA_RECV_V6: u64 = u64::MAX - 1;
const PENDING_SEND_MAX: usize = 8192;

/// Per-worker local counters, flushed to the shared atomics once per loop
/// iteration — avoids cacheline contention between workers.
#[derive(Default)]
struct LocalStats {
    requests: u64,
    connects: u64,
    announces: u64,
    scrapes: u64,
    errors: u64,
    bytes_rx: u64,
    bytes_tx: u64,
    dropped: u64,
    rate_limited: u64,
    peers_added: u64,
    peers_removed: u64,
}

impl LocalStats {
    fn flush_into(&mut self, g: &ProtoStats, stats: &Stats) {
        g.requests.fetch_add(self.requests, Ordering::Relaxed);
        g.connects.fetch_add(self.connects, Ordering::Relaxed);
        g.announces.fetch_add(self.announces, Ordering::Relaxed);
        g.scrapes.fetch_add(self.scrapes, Ordering::Relaxed);
        g.errors.fetch_add(self.errors, Ordering::Relaxed);
        g.bytes_rx.fetch_add(self.bytes_rx, Ordering::Relaxed);
        g.bytes_tx.fetch_add(self.bytes_tx, Ordering::Relaxed);
        g.dropped.fetch_add(self.dropped, Ordering::Relaxed);
        g.rate_limited
            .fetch_add(self.rate_limited, Ordering::Relaxed);
        stats
            .peers_added
            .fetch_add(self.peers_added, Ordering::Relaxed);
        stats
            .peers_removed
            .fetch_add(self.peers_removed, Ordering::Relaxed);
        *self = Self::default();
    }
}

/// Persistent msghdr used by RecvMsgOut::parse to locate the sockaddr that
/// recvmsg wrote next to the payload in the provided buffer.
/// The pointed-to allocations are never freed (worker-lifetime).
struct RecvHelper {
    msghdr: *const libc::msghdr,
    is_v4: bool,
}

impl RecvHelper {
    fn new(is_v4: bool) -> Self {
        let (name, namelen) = if is_v4 {
            (
                Box::into_raw(Box::new(libc::sockaddr_in {
                    sin_family: 0,
                    sin_port: 0,
                    sin_addr: libc::in_addr { s_addr: 0 },
                    sin_zero: [0; 8],
                })) as *mut libc::c_void,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        } else {
            (
                Box::into_raw(Box::new(libc::sockaddr_in6 {
                    sin6_family: 0,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                    sin6_scope_id: 0,
                })) as *mut libc::c_void,
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        };
        // Safety: plain C struct, zeroed then fields set explicitly.
        let msghdr = Box::into_raw(Box::new(unsafe {
            let mut h = std::mem::MaybeUninit::<libc::msghdr>::zeroed().assume_init();
            h.msg_name = name;
            h.msg_namelen = namelen;
            h
        }));
        Self {
            msghdr,
            is_v4,
        }
    }

    /// Parse a filled recv buffer into (source addr, payload).
    ///
    /// Provided-buffer recvmsg layout (verified empirically):
    ///   [0..16)   io_uring_recvmsg_out header: namelen, controllen,
    ///             payloadlen, flags (all u32 LE... actually native endian)
    ///   [16..)    sockaddr (namelen bytes) + control (controllen) + payload
    ///
    /// The kernel writes the header in native endianness; x86/arm are LE.
    /// Returned payload borrows `buf`, not `self`.
    fn parse<'a>(&self, buf: &'a [u8]) -> Option<(SocketAddr, &'a [u8])> {
        if buf.len() < 16 {
            return None;
        }
        let rd32 = |o: usize| u32::from_ne_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let namelen = rd32(0) as usize;
        let controllen = rd32(4) as usize;
        let payloadlen = rd32(8) as usize;
        let msg_flags = rd32(12);
        if (msg_flags as i32) & libc::MSG_TRUNC != 0 {
            return None; // packet didn't fit the provided buffer
        }
        let name_off = 16;
        let pay_off = name_off + namelen + controllen;
        if pay_off + payloadlen > buf.len() {
            return None;
        }
        let name = &buf[name_off..name_off + namelen];
        let addr = if self.is_v4 {
            if name.len() < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // Safety: name is the sockaddr_in the kernel wrote; it is
            // aligned because buf is 4096-aligned and name_off=16.
            let sa = unsafe { *(name.as_ptr() as *const libc::sockaddr_in) };
            if sa.sin_port == 0 {
                return None;
            }
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))),
                u16::from_be(sa.sin_port),
            )
        } else {
            if name.len() < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            let sa = unsafe { *(name.as_ptr() as *const libc::sockaddr_in6) };
            if sa.sin6_port == 0 {
                return None;
            }
            SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)),
                u16::from_be(sa.sin6_port),
            )
        };
        Some((addr, &buf[pay_off..pay_off + payloadlen]))
    }
}

pub struct Worker {
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
    validator: Validator,
    rng: Rng,
    now_unix: u32, // cached UNIX-epoch seconds, refreshed once per loop iter
    buf_ring: BufRing,
    send_buffers: SendBuffers,
    recv_v4: Option<RecvHelper>,
    recv_v6: Option<RecvHelper>,
    recv_sqe_v4: Option<io_uring::squeue::Entry>,
    recv_sqe_v6: Option<io_uring::squeue::Entry>,
    pending_entries: VecDeque<io_uring::squeue::Entry>,
    peer_scratch: Vec<PeerEndpoint>,
    scrape_scratch: Vec<(i32, i32, i32)>,
    local_v4: LocalStats,
    local_v6: LocalStats,
    rl: crate::ratelimit::RateLimiter,
    _sockets: Vec<socket2::Socket>,
}

impl Worker {
    #[inline]
    fn now(&self) -> u32 {
        self.now_unix
    }

    #[inline]
    fn local_mut(&mut self, is_v4_sock: bool) -> &mut LocalStats {
        if is_v4_sock {
            &mut self.local_v4
        } else {
            &mut self.local_v6
        }
    }

    /// Serialize a response into a pooled send buffer and queue its SQE.
    /// Associated function (not a method) so `writer` can borrow other
    /// worker fields disjointly. Returns false if no buffer was available.
    fn emit_response<F>(
        send_buffers: &mut SendBuffers,
        pending: &mut VecDeque<io_uring::squeue::Entry>,
        addr: SocketAddr,
        writer: F,
    ) -> bool
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let idx = match send_buffers.alloc() {
            Some(i) => i,
            None => return false,
        };
        let n = writer(send_buffers.bytes_mut(idx));
        send_buffers.set_len(idx, n);
        let entry = send_buffers.entry_for(idx, addr);
        if pending.len() >= PENDING_SEND_MAX {
            unsafe { send_buffers.mark_free(idx) };
            return false;
        }
        pending.push_back(entry);
        true
    }

    /// Convenience wrapper used by paths that don't need field borrows.
    fn emit_simple<F>(&mut self, addr: SocketAddr, is_v4_sock: bool, writer: F)
    where
        F: FnOnce(&mut [u8]) -> usize,
    {
        let ok = Self::emit_response(&mut self.send_buffers, &mut self.pending_entries, addr, writer);
        if !ok {
            self.local_mut(is_v4_sock).dropped += 1;
        }
    }

    fn handle_cqe(&mut self, cqe: io_uring::cqueue::Entry, rearm: &mut Vec<io_uring::squeue::Entry>) {
        let ud = cqe.user_data();
        if ud == USER_DATA_RECV_V4 || ud == USER_DATA_RECV_V6 {
            let is_v4 = ud == USER_DATA_RECV_V4;
            self.handle_recv_cqe(&cqe, is_v4);
            if !io_uring::cqueue::more(cqe.flags()) {
                let sqe = if is_v4 {
                    self.recv_sqe_v4.clone()
                } else {
                    self.recv_sqe_v6.clone()
                };
                if let Some(s) = sqe {
                    rearm.push(s);
                }
            }
        } else {
            // sendmsg completion: user_data = buffer index | SEND_V6 flag
            let is_v6 = ud & send_buffers::SEND_V6 != 0;
            let idx = (ud & !send_buffers::SEND_V6) as usize;
            let res = cqe.result();
            if res < 0 {
                log::error!("sendmsg failed: {}", std::io::Error::from_raw_os_error(-res));
            }
            unsafe { self.send_buffers.mark_free(idx) };
            if res > 0 {
                // L3+L4 header overhead: IPv4=20+8, IPv6=40+8.
                let hdr = if is_v6 { 48u64 } else { 28u64 };
                self.local_mut(!is_v6).bytes_tx += res as u64 + hdr;
            }
        }
    }

    fn handle_recv_cqe(&mut self, cqe: &io_uring::cqueue::Entry, is_v4_sock: bool) {
        let res = cqe.result();
        if res < 0 {
            if -res == libc::ENOBUFS {
                log::warn!("recvmsg: provided buffers exhausted");
            } else {
                log::warn!("recvmsg failed: {}", std::io::Error::from_raw_os_error(-res));
            }
            return;
        }
        let buf = match unsafe { self.buf_ring.get_buf(res as u32, cqe.flags()) } {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(e) => {
                log::error!("get_buf: {e}");
                return;
            }
        };

        let helper = if is_v4_sock {
            self.recv_v4.as_ref().unwrap()
        } else {
            self.recv_v6.as_ref().unwrap()
        };

        let Some((addr, payload)) = helper.parse(buf.as_slice()) else {
            return;
        };

        let payload_len = payload.len();
        let local = self.local_mut(is_v4_sock);
        local.requests += 1;
        local.bytes_rx += payload_len as u64 + if is_v4_sock { 28 } else { 48 };

        self.dispatch(addr, payload, is_v4_sock);
        // buf dropped here -> bid recycled into the ring
    }

    fn dispatch(&mut self, addr: SocketAddr, payload: &[u8], is_v4_sock: bool) {
        let ip = addr.ip();
        match protocol::parse_request(payload, self.config.protocol.max_scrape_torrents) {
            ParseResult::Ok(ParsedRequest::Connect { transaction_id }) => {
                self.local_mut(is_v4_sock).connects += 1;
                let conn_id = self.validator.create(ip);
                self.emit_simple(addr, is_v4_sock, move |b| {
                    protocol::write_connect_response(b, transaction_id, conn_id)
                });
            }
            ParseResult::Ok(ParsedRequest::Announce(req)) => {
                if !self.validator.valid(ip, req.connection_id) {
                    return;
                }
                if req.port == 0 {
                    self.local_mut(is_v4_sock).errors += 1;
                    self.emit_simple(addr, is_v4_sock, move |b| {
                        protocol::write_error_response(b, req.transaction_id, "port can't be 0")
                    });
                    return;
                }
                let info_hash: InfoHash = req.info_hash;
                if !self.access_list.allows(&info_hash) {
                    self.local_mut(is_v4_sock).errors += 1;
                    self.emit_simple(addr, is_v4_sock, move |b| {
                        protocol::write_error_response(b, req.transaction_id, "info hash not allowed")
                    });
                    return;
                }
                if !self.rl.allow_announce() {
                    self.local_mut(is_v4_sock).rate_limited += 1;
                    return;
                }
                self.local_mut(is_v4_sock).announces += 1;
                if self.config.protocol.client_stats {
                    self.stats.client_stats.record(&req.peer_id);
                }
                let event = AnnounceEvent::from_wire(req.event as i32);
                let now = self.now();
                let txid = req.transaction_id;
                let (ip, port, peer_id, left, numwant) =
                    (ip, req.port, req.peer_id, req.left, req.numwant);
                // Optional client-supplied IP becomes the swarm address only
                // when allow_client_ip is on; `ip` stays authoritative for
                // conn_id validation.
                let announce_ip = if self.config.protocol.allow_client_ip {
                    protocol::request_ip(&req.ip_field, ip)
                } else {
                    ip
                };
                let res = self.store.announce(
                    &info_hash,
                    announce_ip,
                    port,
                    peer_id,
                    left,
                    event,
                    numwant,
                    now,
                    &mut self.rng,
                    &mut self.peer_scratch,
                );
                match res {
                    Some((interval, seeders, leechers, added, removed)) => {
                        if added {
                            self.local_mut(is_v4_sock).peers_added += 1;
                        }
                        if removed {
                            self.local_mut(is_v4_sock).peers_removed += 1;
                        }
                        let peers = &self.peer_scratch;
                        let ok = Self::emit_response(
                            &mut self.send_buffers,
                            &mut self.pending_entries,
                            addr,
                            move |b| {
                                let mut o = protocol::write_announce_header(
                                    b, txid, interval, leechers as i32, seeders as i32,
                                );
                                for p in peers.iter() {
                                    match p.ip {
                                        IpAddr::V4(v4) => {
                                            o += protocol::put_peer_v4(b, o, v4, p.port)
                                        }
                                        IpAddr::V6(v6) => {
                                            o += protocol::put_peer_v6(b, o, v6, p.port)
                                        }
                                    }
                                }
                                o
                            },
                        );
                        if !ok {
                            self.local_mut(is_v4_sock).dropped += 1;
                        }
                    }
                    None => {
                        self.local_mut(is_v4_sock).errors += 1;
                    }
                }
            }
            ParseResult::Ok(ParsedRequest::Scrape {
                connection_id,
                transaction_id,
                hashes,
            }) => {
                if !self.validator.valid(ip, connection_id) {
                    return;
                }
                if !self.rl.allow_scrape() {
                    self.local_mut(is_v4_sock).rate_limited += 1;
                    return;
                }
                self.local_mut(is_v4_sock).scrapes += 1;
                let count = hashes.len().min(self.config.protocol.max_scrape_torrents);
                let stats = self.store.scrape(&hashes[..count]);
                self.scrape_scratch.clear();
                self.scrape_scratch
                    .extend(stats.iter().map(|&(s, _c, l)| (s as i32, 0, l as i32)));
                let scratch = &self.scrape_scratch;
                let ok = Self::emit_response(
                    &mut self.send_buffers,
                    &mut self.pending_entries,
                    addr,
                    move |b| protocol::write_scrape_response(b, transaction_id, scratch),
                );
                if !ok {
                    self.local_mut(is_v4_sock).dropped += 1;
                }
            }
            ParseResult::Err(ParseFailure::Sendable {
                connection_id,
                transaction_id,
                message,
            }) => {
                if self.validator.valid(ip, connection_id) {
                    self.local_mut(is_v4_sock).errors += 1;
                    self.emit_simple(addr, is_v4_sock, move |b| {
                        protocol::write_error_response(b, transaction_id, message)
                    });
                }
            }
            ParseResult::Err(ParseFailure::Drop) => {}
        }
    }

    fn run_inner(&mut self, ring: &mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>) {
        let mut rearm: Vec<io_uring::squeue::Entry> = Vec::new();
        loop {
            {
                let mut sq = ring.submission();
                let mut space = sq.capacity().saturating_sub(sq.len());
                while space > 0 {
                    match self.pending_entries.pop_front() {
                        Some(e) => {
                            // Safety: single-threaded submission queue.
                            if unsafe { sq.push(&e) }.is_err() {
                                self.pending_entries.push_front(e);
                                break;
                            }
                            space -= 1;
                        }
                        None => break,
                    }
                }
                for e in rearm.drain(..) {
                    let _ = unsafe { sq.push(&e) };
                }
            }

            if ring.submitter().submit_and_wait(1).is_err() {
                log::error!("io_uring submit failed");
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }

            for cqe in ring.completion() {
                self.handle_cqe(cqe, &mut rearm);
            }

            let stats_v4 = &self.stats;
            self.local_v4.flush_into(&stats_v4.udp_ipv4, stats_v4);
            self.local_v6.flush_into(&stats_v4.udp_ipv6, stats_v4);
            self.send_buffers.reset_likely_next();
            // refresh the shared-clock timestamp once per iteration
            self.now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
        }
    }
}

fn create_socket(
    bind: SocketAddr,
    recv_buf: usize,
    only_v6: bool,
) -> anyhow::Result<socket2::Socket> {
    let is_v4 = bind.is_ipv4();
    let sock = Socket::new(
        if is_v4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    if recv_buf > 0 {
        sock.set_recv_buffer_size(recv_buf)?;
    }
    if !is_v4 && only_v6 {
        sock.set_only_v6(true)?;
    }
    sock.bind(&bind.into())?;
    Ok(sock)
}

/// Spawn `n` UDP socket workers (one io_uring + SO_REUSEPORT sockets each).
pub fn run_workers(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
) -> anyhow::Result<Vec<std::thread::JoinHandle<()>>> {
    let num_workers = if config.network.socket_workers == 0 {
        std::thread::available_parallelism()
            .map(Into::into)
            .unwrap_or(1)
    } else {
        config.network.socket_workers
    };
    let validator = Validator::new(config.protocol.max_connection_age);
    let mut handles = Vec::new();

    for i in 0..num_workers {
        let config = config.clone();
        let store = store.clone();
        let stats = stats.clone();
        let access_list = access_list.clone();
        let validator = validator.for_worker();
        handles.push(
            std::thread::Builder::new()
                .name(format!("udp-worker-{i:02}"))
                .spawn(move || {
                    if let Err(e) = worker_main(config, store, stats, access_list, validator) {
                        log::error!("udp worker {i} died: {e:#}");
                    }
                })
                .context("spawn udp worker")?,
        );
    }
    Ok(handles)
}

fn worker_main(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
    validator: Validator,
) -> anyhow::Result<()> {
    let ring_entries = config.network.ring_size.max(64).next_power_of_two() as usize;
    let send_capacity = ring_entries;

    let sock_v4 = if config.network.use_ipv4 {
        Some(create_socket(
            config.network.bind_ipv4,
            config.network.socket_recv_buffer,
            config.network.use_ipv6,
        )?)
    } else {
        None
    };
    let sock_v6 = if config.network.use_ipv6 {
        Some(create_socket(config.network.bind_ipv6, config.network.socket_recv_buffer, true)?)
    } else {
        None
    };

    let mut ring: IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry> = IoUring::builder()
        .setup_coop_taskrun()
        .setup_single_issuer()
        .setup_submit_all()
        .build(ring_entries as u32)?;

    ring.submitter().register_files(&[
        sock_v4.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1),
        sock_v6.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1),
    ])?;

    let buf_ring = BufRing::new(0, ring_entries as u16, REQUEST_BUF_LEN)?;
    // Safety: buf_ring memory is owned by this worker and outlives the ring.
    unsafe { buf_ring.register(&ring.submitter()) }?;

    let recv_v4 = sock_v4.as_ref().map(|_| RecvHelper::new(true));
    let recv_v6 = sock_v6.as_ref().map(|_| RecvHelper::new(false));

    let recv_sqe_v4 = recv_v4.as_ref().map(|h| {
        RecvMsgMulti::new(Fixed(0), h.msghdr, buf_ring.bgid())
            .build()
            .user_data(USER_DATA_RECV_V4)
    });
    let recv_sqe_v6 = recv_v6.as_ref().map(|h| {
        RecvMsgMulti::new(Fixed(1), h.msghdr, buf_ring.bgid())
            .build()
            .user_data(USER_DATA_RECV_V6)
    });

    let rl = crate::ratelimit::RateLimiter::new(
        config.ratelimit.announce_per_sec,
        config.ratelimit.scrape_per_sec,
        config.ratelimit.burst,
    );

    let mut worker = Worker {
        config,
        store,
        stats,
        access_list,
        validator,
        rng: Rng::new(),
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0),
        buf_ring,
        send_buffers: SendBuffers::new(send_capacity),
        recv_v4,
        recv_v6,
        recv_sqe_v4,
        recv_sqe_v6,
        pending_entries: VecDeque::new(),
        peer_scratch: Vec::with_capacity(256),
        scrape_scratch: Vec::with_capacity(128),
        local_v4: LocalStats::default(),
        local_v6: LocalStats::default(),
        rl,
        _sockets: sock_v4
            .into_iter()
            .chain(sock_v6.into_iter())
            .collect(),
    };

    // Prime the multishot recv SQEs.
    {
        let mut sq = ring.submission();
        if let Some(e) = &worker.recv_sqe_v4 {
            unsafe { sq.push(e)? };
        }
        if let Some(e) = &worker.recv_sqe_v6 {
            unsafe { sq.push(e)? };
        }
    }
    ring.submitter().submit()?;

    worker.run_inner(&mut ring);
    Ok(())
}
