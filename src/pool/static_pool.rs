use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::{Align, Pool, Slot, ValidAlign, check_buf_capacity};
use crate::driver::{PacketBuf, PacketMeta, RawPacketBuf};

/// Statically allocated [`Pool`].
///
/// Pick `SIZE` for the largest frame your links carry:
/// - 1514 for Ethernet. 1518 or 1522 with one or two VLAN tags.
/// - 9018 or so for Ethernet with jumbo frames.
/// - 128 or 256 for IEEE 802.15.4 without 6LoWPAN fragmentation. 256 leaves
///   room for the headers to grow when they are decompressed.
///
/// `SIZE` also caps the MTU of every interface. Going below the protocol minimums
/// works, but breaks interoperability:
/// - IPv6 needs 1280 bytes plus the link header (RFC 8200).
/// - IPv4 hosts must accept 576 bytes plus the link header (RFC 791).
///
/// `ALIGN` can be 1, 2, 4, 8, 16, 32 or 64.
///
/// Put it in a `static`:
///
/// ```
/// use xarxa::{Stack, StaticPool};
///
/// static POOL: StaticPool<1514, 16> = StaticPool::new();
///
/// let stack = Stack::new(&POOL, 0x1234_5678);
/// ```
///
/// The pool is zero-initialized, so a `static` of it lives in `.bss`. To put it
/// in DMA-capable memory, give the `static` a `#[link_section]`. That memory
/// must then be zeroed before the pool is used.
pub struct StaticPool<const SIZE: usize = 1514, const COUNT: usize = 16, const ALIGN: usize = 1>
where
    Align<ALIGN>: ValidAlign,
{
    /// `used[i]` is set while slot `i` is owned by a `PacketBuf`.
    used: [AtomicBool; COUNT],
    /// Perf optimization:
    /// - On free, store index in `next`.
    /// - start scanning at `next` insfead of 0.
    next: AtomicUsize,
    slots: [UnsafeCell<Slot<SIZE, ALIGN>>; COUNT],
}

// SAFETY: a slot is handed to at most one `PacketBuf` at a time. Its flag is
// set by the one `alloc` that wins it, and cleared only when that `PacketBuf`
// is dropped, in `free`. So no two threads ever touch the same slot, and the
// flags are atomic.
unsafe impl<const SIZE: usize, const COUNT: usize, const ALIGN: usize> Sync for StaticPool<SIZE, COUNT, ALIGN> where
    Align<ALIGN>: ValidAlign
{
}

impl<const SIZE: usize, const COUNT: usize, const ALIGN: usize> StaticPool<SIZE, COUNT, ALIGN>
where
    Align<ALIGN>: ValidAlign,
{
    /// Create a pool, with every buffer free.
    pub const fn new() -> Self {
        const { check_buf_capacity(SIZE) };

        Self {
            used: [const { AtomicBool::new(false) }; COUNT],
            next: AtomicUsize::new(0),
            slots: [const {
                UnsafeCell::new(Slot {
                    raw: MaybeUninit::zeroed(),
                    _align: [],
                    data: [0; SIZE],
                })
            }; COUNT],
        }
    }

    /// Claim a free slot: the first clear flag from `next` on, set with a CAS.
    #[cfg(target_has_atomic = "8")]
    fn claim(&self) -> Option<usize> {
        // Acquire pairs with the Release in `free`: the previous owner's writes to
        // the slot are done before ours start.
        self.scan(|used| {
            !used.load(Ordering::Relaxed)
                && used
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
        })
    }

    /// Claim a free slot: the first clear flag from `next` on.
    ///
    /// For targets with atomic load/store but no atomic read-modify-write (e.g.
    /// thumbv6m): the whole scan runs inside a critical section, so a plain load
    /// and store can't race another `claim`. `free` needs none: it only clears a
    /// set flag, and `claim` only sets a clear one.
    #[cfg(not(target_has_atomic = "8"))]
    fn claim(&self) -> Option<usize> {
        critical_section::with(|_| {
            // Acquire pairs with the Release in `free`, as in the atomic version.
            let index = self.scan(|used| !used.load(Ordering::Acquire))?;
            self.used[index].store(true, Ordering::Relaxed);
            Some(index)
        })
    }

    /// The first slot from `next` on, wrapping around, whose flag `f` accepts.
    #[inline(always)]
    fn scan(&self, mut f: impl FnMut(&AtomicBool) -> bool) -> Option<usize> {
        if COUNT == 0 {
            return None;
        }
        // Relaxed: `next` is only a hint, the flags decide.
        let start = self.next.load(Ordering::Relaxed);
        let mut i = start;
        loop {
            if f(&self.used[i]) {
                return Some(i);
            }
            i += 1;
            if i == COUNT {
                i = 0;
            }
            if i == start {
                return None;
            }
        }
    }

    /// Give a buffer back to its pool. Called when it is dropped.
    ///
    /// # Safety
    /// `raw` must be the `RawPacketBuf` `alloc` gave the buffer, and the buffer must
    /// no longer be used.
    unsafe fn free(raw: NonNull<RawPacketBuf>) {
        // SAFETY: `alloc` set `raw.pool` to a `&'static Self`. `raw`
        // is the first field of one of its slots, so a pointer to that slot.
        let (pool, index) = unsafe {
            let pool = &*raw.as_ref().pool.cast::<Self>();
            let slot = raw.cast::<UnsafeCell<Slot<SIZE, ALIGN>>>().as_ptr();
            (pool, slot.offset_from_unsigned(pool.slots.as_ptr()))
        };
        // Release pairs with the Acquire in `claim`: our writes to the slot are
        // done before the next owner's start.
        pool.used[index].store(false, Ordering::Release);
        pool.next.store(index, Ordering::Relaxed);
    }
}

impl<const SIZE: usize, const COUNT: usize, const ALIGN: usize> Default for StaticPool<SIZE, COUNT, ALIGN>
where
    Align<ALIGN>: ValidAlign,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const SIZE: usize, const COUNT: usize, const ALIGN: usize> Pool for StaticPool<SIZE, COUNT, ALIGN>
where
    Align<ALIGN>: ValidAlign,
{
    #[inline(never)] // helps code size: it has many callers
    fn alloc(&'static self) -> Option<PacketBuf> {
        let index = self.claim()?;
        let slot = self.slots[index].get();
        // SAFETY: the slot is ours (its flag is set), and nothing else points into
        // it. Its storage is initialized, since the pool starts out zeroed.
        unsafe {
            let data = (&raw mut (*slot).data).cast::<u8>();
            // Catch code that relies on fresh buffers being zeroed.
            #[cfg(test)]
            data.write_bytes(0xa5, SIZE);
            let raw = (&raw mut (*slot).raw).cast::<RawPacketBuf>();
            raw.write(RawPacketBuf {
                free: Self::free,
                pool: (self as *const Self).cast(),
                data: NonNull::new_unchecked(data),
                capacity: SIZE,
                headroom: 0,
                len: 0,
                meta: PacketMeta::default(),
            });
            // `free` gets back this slot's `RawPacketBuf`, whose `pool` is this pool,
            // which is `'static`.
            Some(PacketBuf::from_raw(NonNull::new_unchecked(raw)))
        }
    }

    fn buf_capacity(&self) -> usize {
        SIZE
    }
}
