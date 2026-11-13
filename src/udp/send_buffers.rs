//! Pool of pre-allocated UDP response buffers for io_uring sendmsg.
//!
//! Each buffer owns its sockaddr storage, payload bytes, iovec and msghdr so
//! the kernel can DMA the response directly — zero copies after serialize.

use std::net::SocketAddr;
use std::ptr::{addr_of_mut, null_mut};

use io_uring::opcode::SendMsg;
use io_uring::types::Fixed;

pub const RESPONSE_BUF_LEN: usize = 2048;

const SOCKET_V4: Fixed = Fixed(0);
const SOCKET_V6: Fixed = Fixed(1);

/// user_data flag bit marking a sendmsg destined for an IPv6 peer, so the
/// completion handler can attribute bytes_tx to the right family counter.
/// Buffer indices are < ring_entries (<= 32768), far below this bit.
pub const SEND_V6: u64 = 1 << 32;

pub struct SendBuffer {
    name_v4: libc::sockaddr_in,
    name_v6: libc::sockaddr_in6,
    bytes: [u8; RESPONSE_BUF_LEN],
    iov: libc::iovec,
    mhdr: libc::msghdr,
}

impl SendBuffer {
    fn new() -> Box<Self> {
        let mut b = Box::new(Self {
            name_v4: libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
            name_v6: libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
                sin6_scope_id: 0,
            },
            bytes: [0; RESPONSE_BUF_LEN],
            iov: libc::iovec {
                iov_base: null_mut(),
                iov_len: 0,
            },
            // msghdr has private padding on musl; zero-init then set fields
            mhdr: unsafe { std::mem::zeroed() },
        });
        b.iov.iov_base = addr_of_mut!(b.bytes) as *mut libc::c_void;
        b.mhdr.msg_iov = addr_of_mut!(b.iov);
        b.mhdr.msg_iovlen = 1;
        b.mhdr.msg_control = null_mut();
        b.mhdr.msg_controllen = 0;
        b.mhdr.msg_flags = 0;
        // default to v4 name
        b.mhdr.msg_name = addr_of_mut!(b.name_v4) as *mut libc::c_void;
        b.mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
        b
    }
}

pub struct SendBuffers {
    bufs: Vec<Box<SendBuffer>>,
    in_use: Vec<bool>,
    /// Stack of allocatable indices — O(1) alloc/free, no scanning.
    free_list: Vec<u32>,
}

impl SendBuffers {
    pub fn new(capacity: usize) -> Self {
        let bufs = (0..capacity).map(|_| SendBuffer::new()).collect();
        Self {
            bufs,
            in_use: vec![false; capacity],
            free_list: (0..capacity as u32).rev().collect(),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Pop a free buffer index (LIFO — recently freed buffers stay cache-hot).
    #[inline]
    pub fn alloc(&mut self) -> Option<usize> {
        while let Some(idx) = self.free_list.pop() {
            let i = idx as usize;
            if !self.in_use[i] {
                self.in_use[i] = true;
                return Some(i);
            }
        }
        None
    }

    /// Return a buffer to the pool after its sendmsg CQE completed.
    /// Idempotent: a double-free is ignored via the in_use guard.
    /// # Safety
    /// Only call once the kernel is done with the buffer (CQE received).
    pub unsafe fn mark_free(&mut self, idx: usize) {
        if self.in_use[idx] {
            self.in_use[idx] = false;
            self.free_list.push(idx as u32);
        }
    }

    /// Mutable access to the payload bytes for serialization.
    #[inline]
    pub fn bytes_mut(&mut self, idx: usize) -> &mut [u8] {
        &mut self.bufs[idx].bytes
    }

    /// Record payload length written by the serializer.
    #[inline]
    pub fn set_len(&mut self, idx: usize, len: usize) {
        self.bufs[idx].iov.iov_len = len;
    }

    /// Build the sendmsg SQE for buffer `idx` destined to `addr`.
    /// The returned entry has user_data = idx for completion tracking.
    pub fn entry_for(&mut self, idx: usize, addr: SocketAddr) -> io_uring::squeue::Entry {
        let b = &mut *self.bufs[idx];
        let fd = match addr {
            SocketAddr::V4(a) => {
                b.name_v4.sin_port = a.port().to_be();
                b.name_v4.sin_addr.s_addr = u32::from(*a.ip()).to_be();
                b.mhdr.msg_name = addr_of_mut!(b.name_v4) as *mut libc::c_void;
                b.mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
                SOCKET_V4
            }
            SocketAddr::V6(a) => {
                b.name_v6.sin6_port = a.port().to_be();
                b.name_v6.sin6_addr.s6_addr = a.ip().octets();
                b.name_v6.sin6_scope_id = a.scope_id();
                b.mhdr.msg_name = addr_of_mut!(b.name_v6) as *mut libc::c_void;
                b.mhdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in6>() as u32;
                SOCKET_V6
            }
        };
        // Safety: mhdr/iov/bytes live inside a Box that outlives the SQE;
        // buffer is not freed until its CQE arrives.
        let ud = (idx as u64) | if matches!(addr, SocketAddr::V6(_)) { SEND_V6 } else { 0 };
        SendMsg::new(fd, addr_of_mut!(b.mhdr) as *mut libc::msghdr)
            .build()
            .user_data(ud)
    }
}
