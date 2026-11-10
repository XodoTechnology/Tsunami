//! Probe: what does cqe.res contain for multishot recvmsg + buf_ring?
use std::alloc::Layout;
use std::cell::Cell;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicU16;

use io_uring::opcode::{RecvMsgMulti, SendMsg, Timeout};
use io_uring::types::{BufRingEntry, Fixed, Timespec};
use io_uring::IoUring;

const BUF_LEN: usize = 512;
const RING_ENTRIES: u16 = 64;
const BGID: u16 = 0;

fn main() -> anyhow::Result<()> {
    // UDP socket pair on loopback
    let rx = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    rx.set_reuse_address(true)?;
    rx.bind(&"127.0.0.1:39999".parse::<std::net::SocketAddr>()?.into())?;
    rx.set_nonblocking(true)?;
    let tx = std::net::UdpSocket::bind("127.0.0.1:0")?;

    let mut ring: IoUring<io_uring::squeue::Entry, io_uring::cqueue::Entry> = IoUring::builder()
        .setup_coop_taskrun()
        .setup_single_issuer()
        .setup_submit_all()
        .build(256)?;

    ring.submitter().register_files(&[rx.as_raw_fd()])?;

    // ---- buf ring ----
    let entry_size = std::mem::size_of::<BufRingEntry>();
    let ring_size = entry_size * RING_ENTRIES as usize;
    let buf_size = BUF_LEN * RING_ENTRIES as usize;
    let layout = Layout::from_size_align(ring_size + buf_size, 4096)?;
    let base = unsafe { std::alloc::alloc_zeroed(layout) };
    let buffers_addr = unsafe { base.add(ring_size) };
    let ring_addr = base as *const BufRingEntry;
    let tail_addr = unsafe { BufRingEntry::tail(ring_addr) } as *const AtomicU16;
    let local_tail = Cell::new(0u16);
    let mask = RING_ENTRIES - 1;

    for bid in 0..RING_ENTRIES {
        let cur = local_tail.get();
        local_tail.set(cur.wrapping_add(1));
        let idx = (cur & mask) as usize;
        let entry = unsafe { &mut *(ring_addr as *mut BufRingEntry).add(idx) };
        entry.set_addr(unsafe { buffers_addr.add(bid as usize * BUF_LEN) } as u64);
        entry.set_len(BUF_LEN as u32);
        entry.set_bid(bid);
    }
    unsafe { (*tail_addr).store(local_tail.get(), std::sync::atomic::Ordering::Release) };

    unsafe {
        ring.submitter()
            .register_buf_ring_with_flags(ring_addr as u64, RING_ENTRIES, BGID, 0)?;
    }

    // msghdr for recv: name space for sockaddr_in
    let name = Box::into_raw(Box::new(libc::sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    }));
    let msghdr = Box::into_raw(Box::new(unsafe {
        let mut h = MaybeUninit::<libc::msghdr>::zeroed().assume_init();
        h.msg_name = name as *mut libc::c_void;
        h.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        h.msg_iov = std::ptr::null_mut();
        h.msg_iovlen = 0;
        h.msg_control = std::ptr::null_mut();
        h.msg_controllen = 0;
        h.msg_flags = 0;
        h
    }));

    let recv_sqe = RecvMsgMulti::new(Fixed(0), msghdr, BGID)
        .build()
        .user_data(0xFFFF);
    unsafe { ring.submission().push(&recv_sqe)? };

    // timeout to keep loop alive
    let ts = Box::into_raw(Box::new(Timespec::new().sec(5)));
    let timeout_sqe = Timeout::new(ts).build().user_data(0xFFFE);

    ring.submitter().submit()?;

    // send a test packet after 100ms
    let tx2 = tx.try_clone()?;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let payload = [7u8; 200]; // distinctive payload
        let _ = tx2.send_to(&payload, "127.0.0.1:39999");
        let _ = tx2.send_to(&payload, "127.0.0.1:39999");
    });

    let mut got = 0;
    let mut rearm: Vec<io_uring::squeue::Entry> = Vec::new();
    loop {
        ring.submitter().submit_and_wait(1)?;
        for cqe in ring.completion() {
            let ud = cqe.user_data();
            if ud == 0xFFFF {
                let res = cqe.result();
                let flags = cqe.flags();
                let bid = io_uring::cqueue::buffer_select(flags);
                println!("RECV cqe: res={} flags={:#x} bid={:?} more={}", res, flags, bid, io_uring::cqueue::more(flags));
                if let Some(b) = bid {
                    let off = b as usize * BUF_LEN;
                    let buf = unsafe { std::slice::from_raw_parts(buffers_addr.add(off), BUF_LEN) };
                    // parse header
                    let namelen = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
                    let controllen = u32::from_ne_bytes(buf[4..8].try_into().unwrap());
                    let payloadlen = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
                    let hflags = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
                    println!("  hdr: namelen={} controllen={} payloadlen={} flags={:#x}", namelen, controllen, payloadlen, hflags);
                    println!("  first payload bytes: {:02x?}", &buf[16 + 16..16 + 16 + 8]);
                    // re-add buffer
                    let cur = local_tail.get();
                    local_tail.set(cur.wrapping_add(1));
                    let idx = (cur & mask) as usize;
                    let entry = unsafe { &mut *(ring_addr as *mut BufRingEntry).add(idx) };
                    entry.set_addr(unsafe { buffers_addr.add(off) } as u64);
                    entry.set_len(BUF_LEN as u32);
                    entry.set_bid(b);
                    unsafe { (*tail_addr).store(local_tail.get(), std::sync::atomic::Ordering::Release) };
                }
                got += 1;
                if got >= 2 {
                    println!("DONE");
                    return Ok(());
                }
                if !io_uring::cqueue::more(flags) {
                    rearm.push(recv_sqe.clone());
                }
            } else if ud == 0xFFFE {
                rearm.push(timeout_sqe.clone());
            }
        }
        for sqe in rearm.drain(..) {
            unsafe { ring.submission().push(&sqe)? };
        }
    }
}
