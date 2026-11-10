//! Pool of pre-allocated UDP response buffers for io_uring sendmsg.
//!
//! Each buffer owns its sockaddr storage, payload bytes, iovec and msghdr so
//! the kernel can DMA the response directly — zero copies after serialize.

use std::net::SocketAddr;
use std::ptr::{addr_of_mut, null_mut};

use io_uring::opcode::SendMsg;
use io_uring::types::Fixed;

pub const RESPONSE_BUF_LEN: usize = 4096;

const SOCKET_V4: Fixed = Fixed(0);
const SOCKET_V6: Fixed = Fixed(1);

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
    free: Vec<bool>,
    likely_next: usize,
}

impl SendBuffers {
    pub fn new(capacity: usize) -> Self {
        let bufs = (0..capacity).map(|_| SendBuffer::new()).collect();
        Self {
            bufs,
            free: vec![true; capacity],
            likely_next: 0,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.bufs.len()
    }

    /// Find a free buffer index.
    pub fn alloc(&mut self) -> Option<usize> {
        if self.likely_next >= self.bufs.len() {
            return None;
        }
        for i in self.likely_next..self.bufs.len() {
            if self.free[i] {
                self.free[i] = false;
                self.likely_next = i + 1;
                return Some(i);
            }
        }
        // wrap-around scan
        for i in 0..self.likely_next {
            if self.free[i] {
                self.free[i] = false;
                self.likely_next = i + 1;
                return Some(i);
            }
        }
        None
    }

    /// Mark buffer free after its sendmsg CQE completed.
    /// # Safety
    /// Only call once the kernel is done with the buffer (CQE received).
    pub unsafe fn mark_free(&mut self, idx: usize) {
        self.free[idx] = true;
        if idx < self.likely_next {
            self.likely_next = idx;
        }
    }

    pub fn reset_likely_next(&mut self) {
        self.likely_next = 0;
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
        SendMsg::new(fd, addr_of_mut!(b.mhdr) as *mut libc::msghdr)
            .build()
            .user_data(idx as u64)
    }
}
