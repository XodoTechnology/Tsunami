//! AF_PACKET receive backend: kernel packet-mmap ring (TPACKET_V1) for
//! lower-overhead UDP ingest than per-packet recvmsg.
//!
//! Each worker owns one packet socket per IP family (RX ring) plus a UDP
//! socket bound to the tracker port used only for sending responses.
//! Frames are parsed L2->L3->L4 in userspace; only UDP datagrams destined
//! to our port are dispatched.
//!
//! Works on any NIC (including virtio), unlike AF_XDP which needs
//! driver-level XDP support. RX is the usual bottleneck under flood;
//! TX stays on ordinary UDP sockets.

use std::ffi::CString;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};

use crate::access::AccessList;
use crate::config::Config;
use crate::protocol::{self, ParseFailure, ParseResult, ParsedRequest};
use crate::stats::Stats;
use crate::swarm::{self, InfoHash, PeerEndpoint, Rng, Store};
use crate::udp::validator::Validator;

// ---- AF_PACKET / TPACKET constants (linux/if_packet.h, linux/if_ether.h) ----
const AF_PACKET: i32 = 17;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const SOL_PACKET: i32 = 263;
const PACKET_VERSION: i32 = 10;
const PACKET_RX_RING: i32 = 5;
const PACKET_FANOUT: i32 = 18;
const FANOUT_HASH: u16 = 1;
const TPACKET_V1: i32 = 0;
const TP_STATUS_USER: u32 = 0x1; // (1 << 0)
const TP_STATUS_KERNEL: u32 = 0x0; // kernel-owned/free — NOT 2!

const BLOCK_SIZE: usize = 65536; // must be multiple of frame size
const FRAME_SIZE: usize = 2048; // covers max UDP payload + L2/L3/L4
// Frames per ring: kept small enough that a full status scan stays in L3.
// 2048 frames * 2KiB = 4MiB per ring; env override for tuning.
fn frame_nr() -> usize {
    std::env::var("TSUNAMI_PKT_FRAMES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2048)
}
fn ring_consts() -> (usize, usize) {
    let nr = frame_nr();
    (nr, nr * FRAME_SIZE / BLOCK_SIZE)
}

#[repr(C)]
struct TpacketReq {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
}

#[repr(C)]
struct SockaddrLl {
    sll_family: u16,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[repr(C)]
struct PacketFanout {
    id: u16,
    typ: u16,
    flags: u16,
    roll_over: u16,
}

struct PacketRing {
    ptr: *mut u8,
    len: usize,
    frame_nr: usize,
    frames_per_block: usize,
    cursor: usize,
    /// Cached offset (from frame start) of the IP header, discovered on the
    /// first frame — TPACKET offset bases vary, so we verify once and reuse.
    net_cache: Cell<usize>,
}

use std::cell::Cell;

// Safety: ring memory is mmap'd shared with the kernel; only this thread
// touches tp_status fields, kernel writes frame data. We treat status as
// volatile via raw pointer reads/writes.
unsafe impl Send for PacketRing {}

impl PacketRing {
    fn new(fd: i32) -> Result<Self> {
        let (frame_nr, block_nr) = ring_consts();
        let req = TpacketReq {
            tp_block_size: BLOCK_SIZE as u32,
            tp_block_nr: block_nr as u32,
            tp_frame_size: FRAME_SIZE as u32,
            tp_frame_nr: frame_nr as u32,
        };
        // PACKET_VERSION must be set BEFORE PACKET_RX_RING — the kernel
        // picks the header layout (tpacket_hdr vs tpacket2_hdr) at ring
        // creation time.
        let ver = TPACKET_V1;
        let vr = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_VERSION,
                &ver as *const _ as *const libc::c_void,
                mem::size_of::<i32>() as u32,
            )
        };
        if vr != 0 {
            return Err(anyhow!("PACKET_VERSION: {}", std::io::Error::last_os_error()));
        }
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_PACKET,
                PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                mem::size_of::<TpacketReq>() as u32,
            )
        };
        if ret != 0 {
            return Err(anyhow!("PACKET_RX_RING: {}", std::io::Error::last_os_error()));
        }
        let len = BLOCK_SIZE * block_nr;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(anyhow!("mmap rx ring: {}", std::io::Error::last_os_error()));
        }
        Ok(Self {
            ptr: ptr as *mut u8,
            len,
            frame_nr,
            frames_per_block: BLOCK_SIZE / FRAME_SIZE,
            cursor: 0,
            net_cache: Cell::new(0),
        })
    }

    #[inline]
    fn frame_ptr(&self, idx: usize) -> *mut u8 {
        let block = idx / self.frames_per_block;
        let slot = idx % self.frames_per_block;
        unsafe { self.ptr.add(block * BLOCK_SIZE + slot * FRAME_SIZE) }
    }

    /// Status word: tp_status is `unsigned long` (8 bytes) in V1. We always
    /// write the full u64 so no stale flag bits survive in the high word.
    #[inline]
    fn status(&self, fp: *const u8) -> u32 {
        unsafe { (fp as *const u32).read_volatile() }
    }

    #[inline]
    fn set_status(&self, fp: *mut u8, v: u32) {
        unsafe { (fp as *mut u64).write_volatile(v as u64) };
    }

    /// tp_len (u32 at header+8) — captured frame length.
    #[inline]
    fn frame_len(&self, fp: *const u8) -> usize {
        unsafe { (fp.add(8) as *const u32).read_volatile() as usize }
    }

    /// tp_net (u16 at header+18) — kernel's network-header offset. Its base
    /// is version/kernel dependent, so callers verify before trusting it.
    #[inline]
    fn tp_net(&self, fp: *const u8) -> usize {
        unsafe { (fp.add(18) as *const u16).read_volatile() as usize }
    }

    /// Find the IP header offset within a frame by scanning for a plausible
    /// IPv4/IPv6 header. Returns offset from frame start, or None.
    fn find_ip_offset(&self, fp: *const u8, flen: usize) -> Option<usize> {
        let hi = flen.min(FRAME_SIZE).saturating_sub(48);
        // scan [32, hi): first byte that looks like an IP version nibble and
        // passes a quick sanity check wins. Zeros/padding can't match.
        for off in 32..hi {
            let b = unsafe { *fp.add(off) };
            let ver = b >> 4;
            if ver == 4 {
                let ihl = (b & 0x0F) as usize;
                if ihl >= 5 && ihl <= 15 && unsafe { *fp.add(off + 9) } == 17 {
                    return Some(off);
                }
            } else if ver == 6 && unsafe { *fp.add(off + 6) } == 17 {
                return Some(off);
            }
        }
        None
    }
}

impl Drop for PacketRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
}

/// Interface name of the default IPv4 route (from /proc/net/route).
fn default_route_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        if f.len() >= 8 && f[1] == "00000000" {
            return Some(f[0].to_string());
        }
    }
    None
}

/// Resolve the interface index for the packet socket: the interface that
/// owns `bind_ip`; for wildcard bind use TSUNAMI_PACKET_IFACE, then the
/// default route interface, then first non-loopback UP interface.
fn ifindex_for(bind_ip: IpAddr, fallback_name: &str) -> Result<i32> {
    if !fallback_name.is_empty() {
        let c = CString::new(fallback_name)?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx != 0 {
            return Ok(idx as i32);
        }
    }
    // walk getifaddrs looking for an interface whose address matches bind_ip;
    // for wildcard, prefer the default-route interface, else first non-loopback.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(anyhow!("getifaddrs"));
        }
        let mut chosen: Option<i32> = None;
        let mut p = ifap;
        let want_specific = !bind_ip.is_unspecified();
        let want_name = if want_specific {
            None
        } else {
            default_route_iface()
        };
        while !p.is_null() {
            let ifa = &*p;
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy();
            let flags = ifa.ifa_flags as i32;
            let is_up = flags & libc::IFF_UP != 0;
            let is_loop = flags & libc::IFF_LOOPBACK != 0;
            if is_up && !name.is_empty() {
                if !want_specific {
                    if let Some(w) = &want_name {
                        if name.as_ref() == w {
                            chosen = Some(libc::if_nametoindex(ifa.ifa_name) as i32);
                            break;
                        }
                    }
                }
                let addr = ifa.ifa_addr;
                if !addr.is_null() {
                    let family = (*addr).sa_family as i32;
                    if want_specific && family == libc::AF_INET as i32 {
                        let sa = &*(addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
                        if ip == bind_ip {
                            chosen = Some(libc::if_nametoindex(ifa.ifa_name) as i32);
                            break;
                        }
                    }
                }
                if chosen.is_none() && !is_loop {
                    chosen = Some(libc::if_nametoindex(ifa.ifa_name) as i32);
                }
            }
            p = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
        chosen.ok_or_else(|| anyhow!("no suitable interface found"))
    }
}

fn open_packet_socket(ifindex: i32, eth_proto: u16, fanout_id: u16) -> Result<Socket> {
    // AF_PACKET isn't a socket2 Domain; use libc directly.
    let fd = unsafe { libc::socket(AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK, eth_proto.to_be() as i32) };
    if fd < 0 {
        return Err(anyhow!("packet socket: {}", std::io::Error::last_os_error()));
    }
    let sock = unsafe { Socket::from_raw_fd(fd) };
    // bind to interface + ethertype
    let sll = SockaddrLl {
        sll_family: AF_PACKET as u16,
        sll_protocol: eth_proto.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    let ret = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<SockaddrLl>() as u32,
        )
    };
    if ret != 0 {
        return Err(anyhow!("packet bind: {}", std::io::Error::last_os_error()));
    }
    // Join the fanout group: without this every worker socket receives a
    // copy of every packet (packet sockets are taps). FANOUT_HASH keeps a
    // flow on one worker; the connection validator is stateless so any
    // distribution is correct.
    if fanout_id != 0 {
        let fo = PacketFanout {
            id: fanout_id,
            typ: FANOUT_HASH,
            flags: 0,
            roll_over: 0,
        };
        let r = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                SOL_PACKET,
                PACKET_FANOUT,
                &fo as *const _ as *const libc::c_void,
                mem::size_of::<PacketFanout>() as u32,
            )
        };
        if r != 0 {
            return Err(anyhow!("PACKET_FANOUT: {}", std::io::Error::last_os_error()));
        }
    }
    Ok(sock)
}

fn open_udp_tx(bind: SocketAddr) -> Result<Socket> {
    let sock = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&bind.into())?;
    Ok(sock)
}

/// Spawn `n` AF_PACKET RX workers (one packet socket per family each).
pub fn run_packet_workers(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
) -> Result<Vec<std::thread::JoinHandle<()>>> {
    let n = if config.network.socket_workers == 0 {
        std::thread::available_parallelism().map(Into::into).unwrap_or(1)
    } else {
        config.network.socket_workers
    };
    let ifname = std::env::var("TSUNAMI_PACKET_IFACE").unwrap_or_default();
    // One validator key shared by all workers — FANOUT_HASH may land a
    // client's announce on a different worker than its connect, so conn_ids
    // must validate everywhere (same as the io_uring backend).
    let validator = Validator::new(config.protocol.max_connection_age);
    let mut handles = Vec::new();
    for i in 0..n {
        let config = config.clone();
        let store = store.clone();
        let stats = stats.clone();
        let access_list = access_list.clone();
        let ifname = ifname.clone();
        let validator = validator.for_worker();
        handles.push(
            std::thread::Builder::new()
                .name(format!("pkt-worker-{i:02}"))
                .spawn(move || {
                    if let Err(e) = worker_main(config, store, stats, access_list, ifname, validator) {
                        log::error!("pkt worker {i} died: {e:#}");
                    }
                })
                .context("spawn pkt worker")?,
        );
    }
    Ok(handles)
}

fn worker_main(
    config: Config,
    store: Arc<Store>,
    stats: Arc<Stats>,
    access_list: Arc<AccessList>,
    ifname: String,
    mut validator: Validator,
) -> Result<()> {
    let mut rings: Vec<(PacketRing, Socket, bool)> = Vec::new(); // (ring, tx_sock_unused, is_v4)
    let mut tx_socks: Vec<(Socket, bool)> = Vec::new();

    // Fanout group ids: unique per tracker port + family so multiple
    // tracker instances on one box don't join each other's groups.
    let fid4 = config.network.bind_ipv4.port() as u16;
    let fid6 = (config.network.bind_ipv6.port() as u16) | 0x8000;

    if config.network.use_ipv4 {
        let idx = ifindex_for(config.network.bind_ipv4.ip(), &ifname)?;
        let psock = open_packet_socket(idx, ETH_P_IP, fid4)?;
        let ring = PacketRing::new(psock.as_raw_fd())?;
        let tx = open_udp_tx(config.network.bind_ipv4)?;
        rings.push((ring, psock, true));
        tx_socks.push((tx, true));
    }
    if config.network.use_ipv6 {
        let idx = ifindex_for(config.network.bind_ipv6.ip(), &ifname)?;
        let psock = open_packet_socket(idx, ETH_P_IPV6, fid6)?;
        let ring = PacketRing::new(psock.as_raw_fd())?;
        let tx = open_udp_tx(config.network.bind_ipv6)?;
        rings.push((ring, psock, false));
        tx_socks.push((tx, false));
    }
    if rings.is_empty() {
        return Err(anyhow!("no packet sockets configured"));
    }

    let mut rng = Rng::new();
    let mut scratch: Vec<PeerEndpoint> = Vec::with_capacity(256);
    let mut scrape_scratch: Vec<(i32, i32, i32)> = Vec::with_capacity(128);
    let mut out = [0u8; 2048];
    loop {
        let mut any = false;
        for (ri, (ring, psock, _is_v4)) in rings.iter_mut().enumerate() {
            // poll gate: skip the ring scan entirely when no data is queued
            let mut pfd = libc::pollfd {
                fd: psock.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let pr = unsafe { libc::poll(&mut pfd, 1, 0) };
            if pr <= 0 {
                continue;
            }
            any = true;
            let tx = &tx_socks[ri].0;
            // drain up to frame_nr slots per pass
            for _ in 0..ring.frame_nr {
                let idx = ring.cursor;
                ring.cursor = (ring.cursor + 1) % ring.frame_nr;
                let fp = ring.frame_ptr(idx);
                if ring.status(fp) & TP_STATUS_USER == 0 {
                    continue;
                }
                let flen = ring.frame_len(fp);
                // Resolve IP header offset: cached value first (verified),
                // else kernel tp_net hint (base 16 on this kernel), else scan.
                let mut net_off = ring.net_cache.get();
                let cached_ok = net_off != 0
                    && net_off + 20 <= FRAME_SIZE
                    && matches!(unsafe { *fp.add(net_off) } >> 4, 4 | 6);
                if !cached_ok {
                    let cand = 16 + ring.tp_net(fp);
                    net_off = if cand + 20 <= FRAME_SIZE
                        && matches!(unsafe { *fp.add(cand) } >> 4, 4 | 6)
                    {
                        cand
                    } else {
                        match ring.find_ip_offset(fp, flen) {
                            Some(o) => o,
                            None => {
                                ring.set_status(fp, TP_STATUS_KERNEL);
                                continue;
                            }
                        }
                    };
                    ring.net_cache.set(net_off);
                }
                let ip_start = unsafe { fp.add(net_off) };
                // `avail` bounds all reads to the mapped frame slot.
                let avail = FRAME_SIZE - net_off;
                if let Some((src, dport, payload)) = parse_udp(ip_start, avail) {
                    let want = if src.is_ipv4() {
                        config.network.bind_ipv4.port()
                    } else {
                        config.network.bind_ipv6.port()
                    };
                    if dport == want {
                        process_packet(
                            src,
                            payload,
                            &mut out,
                            &mut |data: &[u8], dst: SocketAddr| {
                                let d: socket2::SockAddr = dst.into();
                                tx.send_to(data, &d).is_ok()
                            },
                            &store,
                            &stats,
                            &access_list,
                            &mut validator,
                            &mut rng,
                            &mut scratch,
                            &mut scrape_scratch,
                            &config,
                        );
                    }
                }
                ring.set_status(fp, TP_STATUS_KERNEL);
            }
        }
        if !any {
            std::thread::sleep(Duration::from_micros(50));
        }
    }
}

/// Parse IP packet at `ip` (points at IP header). `avail` = bytes from `ip`
/// to the end of the mapped frame slot — every read is bounds-checked
/// against it so a corrupt tp_net/tp_len can never escape the ring.
/// Returns (src SocketAddr, udp dest port, payload slice).
fn parse_udp<'a>(ip: *const u8, avail: usize) -> Option<(SocketAddr, u16, &'a [u8])> {
    unsafe {
        if avail < 20 {
            return None;
        }
        let version = (*ip >> 4) & 0xF;
        match version {
            4 => {
                let ihl = ((*ip & 0xF) as usize) * 4;
                if ihl < 20 || ihl > avail || *ip.add(9) != 17 {
                    return None; // UDP only
                }
                let src_ip = Ipv4Addr::from(u32::from_be_bytes([
                    *ip.add(12), *ip.add(13), *ip.add(14), *ip.add(15),
                ]));
                let udp = ip.add(ihl);
                if avail - ihl < 8 {
                    return None;
                }
                let sport = u16::from_be_bytes([*udp, *udp.add(1)]);
                let dport = u16::from_be_bytes([*udp.add(2), *udp.add(3)]);
                let ulen = u16::from_be_bytes([*udp.add(4), *udp.add(5)]) as usize;
                if ulen < 8 || ulen - 8 > avail - ihl - 8 {
                    return None;
                }
                let payload = std::slice::from_raw_parts(udp.add(8), ulen - 8);
                Some((SocketAddr::new(IpAddr::V4(src_ip), sport), dport, payload))
            }
            6 => {
                // IPv6: 40-byte base header; only direct next-header==UDP
                // (extension headers are rare for tracker traffic; skipped).
                if avail < 48 || *ip.add(6) != 17 {
                    return None;
                }
                let mut src = [0u8; 16];
                src.copy_from_slice(std::slice::from_raw_parts(ip.add(8), 16));
                let udp = ip.add(40);
                let sport = u16::from_be_bytes([*udp, *udp.add(1)]);
                let dport = u16::from_be_bytes([*udp.add(2), *udp.add(3)]);
                let ulen = u16::from_be_bytes([*udp.add(4), *udp.add(5)]) as usize;
                if ulen < 8 || ulen - 8 > avail - 48 {
                    return None;
                }
                let payload = std::slice::from_raw_parts(udp.add(8), ulen - 8);
                Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src)), sport), dport, payload))
            }
            _ => None,
        }
    }
}

/// Send a response datagram. Return false if it could not be transmitted.
pub type SendFn<'a> = &'a mut dyn FnMut(&[u8], SocketAddr) -> bool;

/// Process one UDP tracker payload, serializing any response into `out` and
/// handing it to `send`. Shared by all packet backends (AF_PACKET, AF_XDP).
#[allow(clippy::too_many_arguments)]
pub fn process_packet(
    src: SocketAddr,
    payload: &[u8],
    out: &mut [u8],
    send: SendFn<'_>,
    store: &Store,
    stats: &Stats,
    access_list: &AccessList,
    validator: &mut Validator,
    rng: &mut Rng,
    peer_scratch: &mut Vec<PeerEndpoint>,
    scrape_scratch: &mut Vec<(i32, i32, i32)>,
    config: &Config,
) {
    let ip = src.ip();
    let local = if src.is_ipv4() { &stats.udp_ipv4 } else { &stats.udp_ipv6 };
    local.requests.fetch_add(1, Ordering::Relaxed);
    local.bytes_rx.fetch_add(payload.len() as u64 + 28, Ordering::Relaxed);

    let resp_len = match protocol::parse_request(payload, config.protocol.max_scrape_torrents) {
        ParseResult::Ok(ParsedRequest::Connect { transaction_id }) => {
            local.connects.fetch_add(1, Ordering::Relaxed);
            let conn_id = validator.create(ip);
            protocol::write_connect_response(out, transaction_id, conn_id)
        }
        ParseResult::Ok(ParsedRequest::Announce(req)) => {
            if !validator.valid(ip, req.connection_id) {
                return;
            }
            let info_hash: InfoHash = req.info_hash;
            if req.port == 0 {
                local.errors.fetch_add(1, Ordering::Relaxed);
                protocol::write_error_response(out, req.transaction_id, "port can't be 0")
            } else if !access_list.allows(&info_hash) {
                local.errors.fetch_add(1, Ordering::Relaxed);
                protocol::write_error_response(out, req.transaction_id, "info hash not allowed")
            } else {
                local.announces.fetch_add(1, Ordering::Relaxed);
                if config.protocol.client_stats {
                    stats.client_stats.record(&req.peer_id);
                }
                let event = swarm::AnnounceEvent::from_wire(req.event as i32);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                match store.announce(
                    &info_hash, ip, req.port, req.peer_id, req.left, event, req.numwant,
                    now, rng, peer_scratch,
                ) {
                    Some((interval, seeders, leechers, added, removed)) => {
                        if added { stats.peers_added.fetch_add(1, Ordering::Relaxed); }
                        if removed { stats.peers_removed.fetch_add(1, Ordering::Relaxed); }
                        let mut o = protocol::write_announce_header(
                            out, req.transaction_id, interval,
                            leechers as i32, seeders as i32,
                        );
                        for p in peer_scratch.iter() {
                            match p.ip {
                                IpAddr::V4(v4) => o += protocol::put_peer_v4(out, o, v4, p.port),
                                IpAddr::V6(v6) => o += protocol::put_peer_v6(out, o, v6, p.port),
                            }
                        }
                        o
                    }
                    None => {
                        local.errors.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
        ParseResult::Ok(ParsedRequest::Scrape { connection_id, transaction_id, hashes }) => {
            if !validator.valid(ip, connection_id) {
                return;
            }
            local.scrapes.fetch_add(1, Ordering::Relaxed);
            let count = hashes.len().min(config.protocol.max_scrape_torrents);
            let s = store.scrape(&hashes[..count]);
            scrape_scratch.clear();
            scrape_scratch.extend(s.iter().map(|&(a, _c, l)| (a as i32, 0, l as i32)));
            protocol::write_scrape_response(out, transaction_id, scrape_scratch)
        }
        ParseResult::Err(ParseFailure::Sendable { connection_id, transaction_id, message }) => {
            if !validator.valid(ip, connection_id) {
                return;
            }
            local.errors.fetch_add(1, Ordering::Relaxed);
            protocol::write_error_response(out, transaction_id, message)
        }
        ParseResult::Err(ParseFailure::Drop) => return,
    };

    local.bytes_tx.fetch_add(resp_len as u64 + 28, Ordering::Relaxed);
    if !send(&out[..resp_len], src) {
        local.dropped.fetch_add(1, Ordering::Relaxed);
    }
}
