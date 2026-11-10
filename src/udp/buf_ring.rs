//! Provided-buffer ring for io_uring recvmsg multishot.
//!
//! Single allocation holds the ring entries followed by `buf_cnt` buffers of
//! `buf_len` bytes. The kernel pulls buffer ids from the ring; on each recvmsg
//! CQE we recover the buffer via the CQE's buffer-select flag and recycle it
//! by pushing its id back onto the ring.
//!
//! Adapted from the tokio-uring buf_ring design (MIT), simplified for a
//! fixed buffer size and single consumer.

use std::alloc::Layout;
use std::cell::Cell;
use std::io;
use std::rc::Rc;
use std::sync::atomic::{AtomicU16, Ordering};

use io_uring::types::BufRingEntry;

pub type Bgid = u16;
pub type Bid = u16;

#[derive(Clone)]
pub struct BufRing {
    raw: Rc<RawBufRing>,
}

/// A buffer filled by the kernel. Recycles its bid on drop.
pub struct RecvBuf {
    ring: BufRing,
    bid: Bid,
    len: usize,
}

impl RecvBuf {
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        let p = self.ring.raw.stable_ptr(self.bid);
        unsafe { std::slice::from_raw_parts(p, self.len) }
    }
}

impl Drop for RecvBuf {
    fn drop(&mut self) {
        self.ring.raw.recycle(self.bid);
    }
}

impl BufRing {
    /// Create and populate a buffer ring. Does NOT register with the kernel —
    /// call `register` with the submitter (needs the ring context).
    pub fn new(bgid: Bgid, ring_entries: u16, buf_len: usize) -> io::Result<Self> {
        let buf_cnt = ring_entries;
        RawBufRing::new(bgid, ring_entries, buf_cnt, buf_len).map(|raw| Self {
            raw: Rc::new(raw),
        })
    }

    pub fn bgid(&self) -> Bgid {
        self.raw.bgid
    }

    /// Register the ring with the kernel. # Safety: must be called on the
    /// io_uring that will consume it; memory must outlive registration.
    pub unsafe fn register(&self, submitter: &io_uring::Submitter<'_>) -> io::Result<()> {
        self.raw.register(submitter)
    }

    /// # Safety
    /// `res`/`flags` must come straight from a recvmsg CQE.
    /// Returns the filled buffer, or None for a zero-length read.
    pub unsafe fn get_buf(&self, res: u32, flags: u32) -> io::Result<Option<RecvBuf>> {
        let bid = match io_uring::cqueue::buffer_select(flags) {
            Some(b) => b,
            None => {
                if res == 0 {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("recvmsg CQE missing buffer-select flag: res={res} flags={flags:#x}"),
                ));
            }
        };
        let len = res as usize;
        debug_assert!(len <= self.raw.buf_len);
        Ok(Some(RecvBuf {
            ring: self.clone(),
            bid,
            len,
        }))
    }
}

struct RawBufRing {
    bgid: Bgid,
    ring_entries_mask: u16,
    buf_cnt: u16,
    buf_len: usize,
    layout: Layout,
    ring_addr: *mut BufRingEntry,
    buffers_addr: *mut u8,
    local_tail: Cell<u16>,
    tail_addr: *const AtomicU16,
    registered: Cell<bool>,
}

impl RawBufRing {
    fn new(bgid: Bgid, ring_entries: u16, buf_cnt: u16, buf_len: usize) -> io::Result<Self> {
        if ring_entries == 0 || buf_cnt == 0 || buf_len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad buf_ring args"));
        }
        let ring_entries = ring_entries.next_power_of_two();
        if ring_entries > (1 << 15) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "ring_entries > 32768"));
        }

        let entry_size = std::mem::size_of::<BufRingEntry>();
        let ring_size = entry_size * ring_entries as usize;
        let buf_size = buf_len * buf_cnt as usize;
        let layout = Layout::from_size_align(ring_size + buf_size, 4096)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Safety: layout has nonzero size; alloc_zeroed returns null on failure.
        let base = unsafe { std::alloc::alloc_zeroed(layout) };
        if base.is_null() {
            return Err(io::Error::new(io::ErrorKind::OutOfMemory, "buf_ring alloc"));
        }
        let ring_addr = base as *mut BufRingEntry;
        let buffers_addr = unsafe { base.add(ring_size) };
        // Safety: tail() computes the tail field address inside the ring.
        let tail_addr = unsafe { BufRingEntry::tail(ring_addr as *const BufRingEntry) }
            as *const AtomicU16;

        let this = Self {
            bgid,
            ring_entries_mask: ring_entries - 1,
            buf_cnt,
            buf_len,
            layout,
            ring_addr,
            buffers_addr,
            local_tail: Cell::new(0),
            tail_addr,
            registered: Cell::new(false),
        };

        // offer all buffers to the kernel
        for bid in 0..buf_cnt {
            this.add(bid);
        }
        this.sync();

        Ok(this)
    }

    /// Register with the kernel via the io_uring submitter.
    /// # Safety
    /// ring_addr/entries must stay valid until unregistered (they do — owned).
    pub unsafe fn register(&self, submitter: &io_uring::Submitter<'_>) -> io::Result<()> {
        submitter.register_buf_ring_with_flags(
            self.ring_addr as u64,
            self.ring_entries_mask + 1,
            self.bgid,
            0,
        )?;
        self.registered.set(true);
        Ok(())
    }

    #[inline]
    fn mask(&self) -> u16 {
        self.ring_entries_mask
    }

    #[inline]
    fn stable_ptr(&self, bid: Bid) -> *const u8 {
        debug_assert!(bid < self.buf_cnt);
        unsafe { self.buffers_addr.add(self.buf_len * bid as usize) }
    }

    fn add(&self, bid: Bid) {
        let cur_tail = self.local_tail.get();
        self.local_tail.set(cur_tail.wrapping_add(1));
        let idx = (cur_tail & self.mask()) as usize;
        // Safety: idx < ring_entries by mask; entry ptr valid for allocation.
        let entry = unsafe { &mut *self.ring_addr.add(idx) };
        entry.set_addr(self.stable_ptr(bid) as u64);
        entry.set_len(self.buf_len as u32);
        entry.set_bid(bid);
    }

    #[inline]
    fn sync(&self) {
        // Safety: tail_addr points into our ring allocation.
        unsafe {
            (*self.tail_addr).store(self.local_tail.get(), Ordering::Release);
        }
    }

    /// Return a consumed buffer id to the ring for kernel reuse.
    fn recycle(&self, bid: Bid) {
        debug_assert!(bid < self.buf_cnt);
        self.add(bid);
        self.sync();
    }
}

impl Drop for RawBufRing {
    fn drop(&mut self) {
        // Safety: layout/ptr pairing is correct.
        unsafe { std::alloc::dealloc(self.ring_addr as *mut u8, self.layout) };
    }
}
