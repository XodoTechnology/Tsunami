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
use std::time::{Duration, Instant};

use anyhow::Context;
use io_uring::opcode::{AsyncCancel2, RecvMsgMulti};
use io_uring::types::{CancelBuilder, Fixed};
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
const USER_DATA_CANCEL_V4: u64 = u64::MAX - 2;
const USER_DATA_CANCEL_V6: u64 = u64::MAX - 3;
const PENDING_SEND_MAX: usize = 8192;
/// How long to wait for recv multishots to report termination during a
/// buffer-ring rebuild before resubmitting cancels (guards against a
/// terminal CQE being lost to a further overflow).
const RECV_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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
    blocked: u64,
    peers_added: u64,
    peers_removed: u64,
    ev_started: u64,
    ev_completed: u64,
    ev_stopped: u64,
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
        g.blocked.fetch_add(self.blocked, Ordering::Relaxed);
        stats
            .peers_added
            .fetch_add(self.peers_added, Ordering::Relaxed);
        stats
            .peers_removed
            .fetch_add(self.peers_removed, Ordering::Relaxed);
        g.ev_started.fetch_add(self.ev_started, Ordering::Relaxed);
        g.ev_completed
            .fetch_add(self.ev_completed, Ordering::Relaxed);
        g.ev_stopped.fetch_add(self.ev_stopped, Ordering::Relaxed);
        *self = Self::default();
    }
}

#[derive(Default)]
struct LocalClientStats {
    entries: [(crate::stats::ClientKey, u32); 8],
    len: usize,
}

impl LocalClientStats {
    #[inline]
    fn record(&mut self, peer_id: &[u8; 20], cs: &crate::stats::ClientStats) {
        if cs.is_ignored(peer_id) {
            return;
        }
        let mut key = [0u8; 8];
        key.copy_from_slice(&peer_id[..8]);
        for i in 0..self.len {
            if self.entries[i].0 == key {
                self.entries[i].1 += 1;
                return;
            }
        }
        if self.len == self.entries.len() {
            self.flush_into(cs);
        }
        self.entries[self.len] = (key, 1);
        self.len += 1;
    }

    #[inline]
    fn flush_into(&mut self, cs: &crate::stats::ClientStats) {
        for i in 0..self.len {
            let (k, c) = self.entries[i];
            cs.add_batch(k, c as u64);
        }
        self.len = 0;
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
            let sa = unsafe { (name.as_ptr() as *const libc::sockaddr_in).read_unaligned() };
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
            let sa = unsafe { (name.as_ptr() as *const libc::sockaddr_in6).read_unaligned() };
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
    local_clients: LocalClientStats,
    rl: crate::ratelimit::RateLimiter,
    ip_limiter: Arc<crate::ratelimit::IpConnectLimiter>,
    // --- provided-buffer-ring overflow recovery ---
    /// Whether each family's multishot recvmsg is currently armed.
    recv_live_v4: bool,
    recv_live_v6: bool,
    /// Recovery in progress: recvs cancelled, waiting for terminal CQEs.
    recv_draining: bool,
    /// bit0 = v4, bit1 = v6 — recvs still awaiting a terminal CQE.
    drain_mask: u8,
    drain_since: Instant,
    /// Kernel-dropped CQEs observed since last flush (unflushed delta).
    cqe_overflow_pending: u64,
    last_cq_overflow: u32,
    /// Provided-buffer ring geometry, retained so a rebuild matches the
    /// original allocation (bgid + entry count + buffer length).
    buf_ring_entries: u16,
    rx_buf_len: usize,
    _sockets: Vec<socket2::Socket>,
}

impl Worker {
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

    #[inline]
    fn handle_send_cqe(&mut self, cqe: io_uring::cqueue::Entry) {
        let ud = cqe.user_data();
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

    fn handle_cqe(&mut self, cqe: io_uring::cqueue::Entry, rearm: &mut Vec<io_uring::squeue::Entry>) {
        let ud = cqe.user_data();
        if ud == USER_DATA_RECV_V4 || ud == USER_DATA_RECV_V6 {
            let is_v4 = ud == USER_DATA_RECV_V4;
            self.handle_recv_cqe(&cqe, is_v4);
            if !io_uring::cqueue::more(cqe.flags()) {
                // The multishot recv terminated (error or our cancel).
                let live = if is_v4 {
                    &mut self.recv_live_v4
                } else {
                    &mut self.recv_live_v6
                };
                *live = false;
                if self.recv_draining {
                    // Terminal CQE observed: this family's recv is drained.
                    self.drain_mask &= if is_v4 { !1 } else { !2 };
                } else if let Some(s) = if is_v4 {
                    self.recv_sqe_v4.clone()
                } else {
                    self.recv_sqe_v6.clone()
                } {
                    rearm.push(s);
                    *live = true;
                }
            }
        } else if ud == USER_DATA_CANCEL_V4 || ud == USER_DATA_CANCEL_V6 {
            // AsyncCancel completion. -ENOENT means nothing was armed to
            // cancel, i.e. that family's recv had already terminated.
            if self.recv_draining && cqe.result() == -libc::ENOENT {
                self.drain_mask &= if ud == USER_DATA_CANCEL_V4 { !1 } else { !2 };
            }
        } else {
            self.handle_send_cqe(cqe);
        }
    }

    fn handle_recv_cqe(&mut self, cqe: &io_uring::cqueue::Entry, is_v4_sock: bool) {
        let res = cqe.result();
        if res < 0 {
            if -res == libc::ENOBUFS {
                log::warn!("recvmsg: provided buffers exhausted");
            } else if -res != libc::ECANCELED {
                // ECANCELED is expected while rebuilding the buffer ring.
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
        let now = self.now_unix;
        match protocol::parse_request(payload, self.config.protocol.max_scrape_torrents) {
            ParseResult::Ok(ParsedRequest::Connect { transaction_id }) => {
                if !self.ip_limiter.allow(ip) {
                    self.local_mut(is_v4_sock).rate_limited += 1;
                    return;
                }
                self.local_mut(is_v4_sock).connects += 1;
                let conn_id = self.validator.create_at(ip, now);
                self.emit_simple(addr, is_v4_sock, move |b| {
                    protocol::write_connect_response(b, transaction_id, conn_id)
                });
            }
            ParseResult::Ok(ParsedRequest::Announce(req)) => {
                // Abuse filters run before conn_id validation: rejected
                // traffic skips the connection-table lookup entirely.
                if protocol::synthetic_peer_id(&req.peer_id) {
                    // Abuse signature: count it, but don't spend a send on a
                    // response — no spec client can produce an all-digit id.
                    self.local_mut(is_v4_sock).blocked += 1;
                    return;
                }
                if !self.validator.valid_at(ip, req.connection_id, now) {
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
                    self.local_clients
                        .record(&req.peer_id, &self.stats.client_stats);
                }
                let event = AnnounceEvent::from_wire(req.event as i32);
                match event {
                    AnnounceEvent::Started => self.local_mut(is_v4_sock).ev_started += 1,
                    AnnounceEvent::Completed => self.local_mut(is_v4_sock).ev_completed += 1,
                    AnnounceEvent::Stopped => self.local_mut(is_v4_sock).ev_stopped += 1,
                    AnnounceEvent::Paused | AnnounceEvent::None => {}
                }
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
                        crate::hooks::announce_event(
                            event, &info_hash, announce_ip, port, &peer_id, left, now,
                        );
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
                if !self.validator.valid_at(ip, connection_id, now) {
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
                    .extend(stats.iter().map(|&(s, _c, l, _d)| (s as i32, 0, l as i32)));
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
                if self.validator.valid_at(ip, connection_id, now) {
                    self.local_mut(is_v4_sock).errors += 1;
                    self.emit_simple(addr, is_v4_sock, move |b| {
                        protocol::write_error_response(b, transaction_id, message)
                    });
                }
            }
            ParseResult::Err(ParseFailure::Drop) => {}
        }
    }

    /// Build an AsyncCancel SQE targeting one family's recv multishot.
    fn cancel_sqe(is_v4: bool) -> io_uring::squeue::Entry {
        if is_v4 {
            AsyncCancel2::new(CancelBuilder::user_data(USER_DATA_RECV_V4))
                .build()
                .user_data(USER_DATA_CANCEL_V4)
        } else {
            AsyncCancel2::new(CancelBuilder::user_data(USER_DATA_RECV_V6))
                .build()
                .user_data(USER_DATA_CANCEL_V6)
        }
    }

    /// Check the kernel CQ-overflow counter. New drops mean recvmsg CQEs were
    /// lost, leaking provided-buffer ids — begin draining the multishots so
    /// the ring can be rebuilt. Also maintains the drain (retries cancels if
    /// a terminal CQE was itself lost to a further overflow).
    fn poll_overflow(
        &mut self,
        ring: &mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>,
        rearm: &mut Vec<io_uring::squeue::Entry>,
    ) {
        let ov = ring.completion().overflow();
        if ov != self.last_cq_overflow {
            let lost = ov.wrapping_sub(self.last_cq_overflow);
            self.last_cq_overflow = ov;
            self.cqe_overflow_pending += lost as u64;
            if !self.recv_draining {
                // rearm only ever holds recv resubmit SQEs; drop them so a
                // resubmit can't race the cancels — recvs are resubmitted
                // fresh after the rebuild regardless.
                rearm.clear();
                self.recv_draining = true;
                self.drain_mask = 0;
                self.drain_since = Instant::now();
                log::warn!(
                    "udp worker: io_uring completion queue overflow \
                     ({lost} completions lost); rebuilding RX buffer ring"
                );
                if self.recv_live_v4 {
                    self.drain_mask |= 1;
                    rearm.push(Self::cancel_sqe(true));
                }
                if self.recv_live_v6 {
                    self.drain_mask |= 2;
                    rearm.push(Self::cancel_sqe(false));
                }
            }
        }
        // Drain maintenance: if terminal CQEs were lost to further overflow,
        // resubmit the (idempotent) cancels periodically until they land.
        if self.recv_draining
            && self.drain_mask != 0
            && self.drain_since.elapsed() > RECV_DRAIN_TIMEOUT
        {
            self.drain_since = Instant::now();
            if self.recv_live_v4 {
                rearm.push(Self::cancel_sqe(true));
            }
            if self.recv_live_v6 {
                rearm.push(Self::cancel_sqe(false));
            }
            log::warn!("udp worker: RX ring rebuild drain timed out; retrying cancel");
        }
    }

    /// Once every recv multishot has reported termination, swap in a freshly
    /// registered provided-buffer ring (kernel head/tail reset) and resubmit
    /// the recv SQEs. Retried each iteration until it succeeds.
    fn maybe_finish_rebuild(
        &mut self,
        ring: &mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>,
    ) {
        if !self.recv_draining || self.drain_mask != 0 {
            return;
        }
        let bgid = self.buf_ring.bgid();
        let entries = self.buf_ring_entries;
        // Detach the leaked ring, then register a fresh one under the same
        // bgid. With all recvs terminated there are no armed references to
        // bgid, so this is safe; the old allocation is freed via Rc once its
        // last RecvBuf drains.
        if let Err(e) = ring.submitter().unregister_buf_ring(bgid) {
            log::warn!("unregister_buf_ring({bgid}): {e}");
        }
        let new_ring = match BufRing::new(bgid, entries, self.rx_buf_len) {
            Ok(r) => r,
            Err(e) => {
                log::error!("RX ring rebuild alloc failed: {e}");
                return; // stay draining; retried next iteration
            }
        };
        // Safety: new_ring is owned by this worker and outlives registration.
        if let Err(e) = unsafe { new_ring.register(&ring.submitter()) } {
            log::error!("RX ring rebuild register failed: {e}");
            return;
        }
        self.buf_ring = new_ring;
        // Resubmit the recv multishots onto the fresh ring.
        {
            let mut sq = ring.submission();
            if let Some(e) = &self.recv_sqe_v4 {
                if unsafe { sq.push(e) }.is_err() {
                    log::error!("rebuild: SQ full submitting recv v4");
                }
            }
            if let Some(e) = &self.recv_sqe_v6 {
                if unsafe { sq.push(e) }.is_err() {
                    log::error!("rebuild: SQ full submitting recv v6");
                }
            }
        }
        if let Err(e) = ring.submitter().submit() {
            log::error!("rebuild submit failed: {e}");
        }
        self.recv_draining = false;
        self.recv_live_v4 = self.recv_sqe_v4.is_some();
        self.recv_live_v6 = self.recv_sqe_v6.is_some();
        log::info!("udp worker: RX buffer ring rebuilt after CQ overflow");
    }

    fn run_inner(&mut self, ring: &mut IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry>) {
        let mut rearm: Vec<io_uring::squeue::Entry> = Vec::new();
        let mut recv_cqes: Vec<io_uring::cqueue::Entry> = Vec::with_capacity(1024);
        // Debug/testing hook: force one RX-ring rebuild through the real
        // cancel->drain->re-register path (off unless TSUNAMI_DEBUG_REBUILD set).
        if std::env::var_os("TSUNAMI_DEBUG_REBUILD").is_some() {
            self.recv_draining = true;
            self.drain_mask = 0;
            self.drain_since = Instant::now();
            if self.recv_live_v4 {
                self.drain_mask |= 1;
                rearm.push(Self::cancel_sqe(true));
            }
            if self.recv_live_v6 {
                self.drain_mask |= 2;
                rearm.push(Self::cancel_sqe(false));
            }
            log::warn!("TSUNAMI_DEBUG_REBUILD: forcing RX buffer-ring rebuild");
        }
        loop {
            loop {
                {
                    let mut sq = ring.submission();
                    // Control-plane SQEs (recv resubmits, ring-rebuild cancels)
                    // go first: a SQ full of pending sends must never starve
                    // them, or the recv multishot is silently lost forever.
                    let mut retry = Vec::new();
                    for e in rearm.drain(..) {
                        if unsafe { sq.push(&e) }.is_err() {
                            retry.push(e);
                        }
                    }
                    rearm = retry;
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
                }
                // If a flood batch generated more responses than fit in a
                // single SQ, flush the full SQ immediately and reclaim
                // completed send buffers before queuing the remainder.
                if self.pending_entries.is_empty() {
                    break;
                }
                if ring.submitter().submit().is_err() {
                    break;
                }
                for cqe in ring.completion() {
                    if cqe.user_data() < USER_DATA_CANCEL_V6 {
                        self.handle_send_cqe(cqe);
                    } else {
                        recv_cqes.push(cqe);
                    }
                }
                self.poll_overflow(ring, &mut rearm);
            }

            let wait_nr = if recv_cqes.is_empty() { 1 } else { 0 };
            if ring.submitter().submit_and_wait(wait_nr).is_err() {
                log::error!("io_uring submit failed");
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }

            // Refresh cached UNIX timestamp on wakeup before dispatching CQEs.
            self.now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);

            // Reclaim completed send buffers first so incoming requests in
            // this batch reuse cache-hot buffers from the LIFO free list
            // instead of allocating new buffers or dropping responses.
            for cqe in ring.completion() {
                if cqe.user_data() < USER_DATA_CANCEL_V6 {
                    self.handle_send_cqe(cqe);
                } else {
                    recv_cqes.push(cqe);
                }
            }

            for cqe in recv_cqes.drain(..) {
                self.handle_cqe(cqe, &mut rearm);
            }

            // Provided-buffer-ring overflow detection + recovery.
            self.poll_overflow(ring, &mut rearm);
            self.maybe_finish_rebuild(ring);
            let stats_v4 = &self.stats;
            self.local_v4.flush_into(&stats_v4.udp_ipv4, stats_v4);
            self.local_v6.flush_into(&stats_v4.udp_ipv6, stats_v4);
            if self.config.protocol.client_stats {
                self.local_clients.flush_into(&stats_v4.client_stats);
            }
            if self.cqe_overflow_pending > 0 {
                stats_v4
                    .cqe_overflow
                    .fetch_add(self.cqe_overflow_pending, Ordering::Relaxed);
                self.cqe_overflow_pending = 0;
            }
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
    // Response buffers are fixed-size; peer/scrape writers index raw slices
    // and would panic on overflow. Fail fast at startup if config outgrows
    // the worst-case serialized response.
    let need = (64 + config.protocol.max_response_peers * 18)
        .max(32 + config.protocol.max_scrape_torrents * 12);
    assert!(
        need <= send_buffers::RESPONSE_BUF_LEN,
        "response buffers too small: need {need}B, have {}B — \
         lower max_response_peers/max_scrape_torrents",
        send_buffers::RESPONSE_BUF_LEN
    );
    let validator = Validator::new(
        config.protocol.max_connection_age,
        &config.protocol.conn_key_path,
    );
    let ip_limiter = crate::ratelimit::IpConnectLimiter::new(
        config.ratelimit.connect_per_sec_per_ip,
        config.ratelimit.connect_burst_secs,
    );
    let mut handles = Vec::new();

    for i in 0..num_workers {
        let config = config.clone();
        let store = store.clone();
        let stats = stats.clone();
        let access_list = access_list.clone();
        let validator = validator.for_worker();
        let ip_limiter = ip_limiter.clone();
        handles.push(
            std::thread::Builder::new()
                .name(format!("udp-worker-{i:02}"))
                .spawn(move || {
                    if let Err(e) =
                        worker_main(config, store, stats, access_list, validator, ip_limiter)
                    {
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
    ip_limiter: Arc<crate::ratelimit::IpConnectLimiter>,
) -> anyhow::Result<()> {
    let ring_entries = config.network.ring_size.max(64).next_power_of_two() as usize;
    // Larger CQ headroom so completion bursts don't overflow the ring and
    // drop recvmsg CQEs (which would leak provided-buffer ids). CQEs are
    // ~16B, so a big CQ is cheap insurance. TSUNAMI_CQ_SIZE overrides (pow2).
    let cq_entries = std::env::var("TSUNAMI_CQ_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n >= 64)
        .map(|n| n.next_power_of_two())
        .unwrap_or_else(|| (ring_entries.saturating_mul(16)).clamp(16384, 65536));
    // Provided RX buffers are recycled immediately after each datagram is
    // dispatched; 512..1024 entries per worker keeps the entire RX ring hot
    // in L3 cache and cuts per-worker RSS while absorbing wakeup bursts.
    let buf_ring_entries = ring_entries.clamp(512, 1024).next_power_of_two() as u16;
    let rx_buf_len = (64 + config.protocol.max_scrape_torrents * 20)
        .clamp(512, REQUEST_BUF_LEN)
        .next_multiple_of(64);
    // SendBuffers grows lazily on demand up to PENDING_SEND_MAX, so idle/sustain
    // workers only allocate their active working set (~32 buffers) while flood
    // bursts never drop responses due to pool exhaustion.
    let send_capacity = ring_entries.max(2048).min(PENDING_SEND_MAX);

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
        .setup_cqsize(cq_entries as u32)
        .build(ring_entries as u32)?;

    ring.submitter().register_files(&[
        sock_v4.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1),
        sock_v6.as_ref().map(|s| s.as_raw_fd()).unwrap_or(-1),
    ])?;

    let buf_ring = BufRing::new(0, buf_ring_entries, rx_buf_len)?;
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

    let live_v4 = recv_sqe_v4.is_some();
    let live_v6 = recv_sqe_v6.is_some();
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
        local_clients: LocalClientStats::default(),
        rl,
        ip_limiter,
        recv_live_v4: live_v4,
        recv_live_v6: live_v6,
        recv_draining: false,
        drain_mask: 0,
        drain_since: Instant::now(),
        cqe_overflow_pending: 0,
        last_cq_overflow: 0,
        buf_ring_entries,
        rx_buf_len,
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
