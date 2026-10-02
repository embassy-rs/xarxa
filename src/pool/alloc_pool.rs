use alloc::boxed::Box;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use super::{Align, Pool, Slot, ValidAlign, check_buf_capacity};
use crate::driver::{PacketBuf, PacketMeta, RawPacketBuf};

/// A [`Pool`] that allocates each buffer from the heap.
///
/// At most `max_count` buffers are allocated at a time. If the heap runs out
/// before that, the allocation aborts, like any other heap allocation. Make sure
/// the heap has room for `max_count` buffers.
///
/// [`StaticPool`](super::StaticPool) explains how to pick `SIZE`.
///
/// `ALIGN` can be 1, 2, 4, 8, 16, 32 or 64.
///
/// The build fails for the same buffer sizes that fail with `StaticPool`.
///
/// It must be `'static`. It can go in a `static`:
///
/// ```
/// use xarxa::{AllocPool, Stack};
///
/// static POOL: AllocPool<1514> = AllocPool::new(64);
///
/// let stack = Stack::new(&POOL, 0x1234_5678);
/// ```
pub struct AllocPool<const SIZE: usize = 1514, const ALIGN: usize = 1>
where
    Align<ALIGN>: ValidAlign,
{
    max_count: usize,
    /// Number of buffers allocated right now.
    count: AtomicUsize,
}

impl<const SIZE: usize, const ALIGN: usize> AllocPool<SIZE, ALIGN>
where
    Align<ALIGN>: ValidAlign,
{
    /// Create a pool that allocates at most `max_count` buffers at a time.
    pub const fn new(max_count: usize) -> Self {
        const { check_buf_capacity(SIZE) };
        Self {
            max_count,
            count: AtomicUsize::new(0),
        }
    }

    /// Count one more buffer, if that stays within `max_count`.
    fn reserve(&self) -> bool {
        let mut n = self.count.load(Ordering::Relaxed);
        while n < self.max_count {
            match self
                .count
                .compare_exchange_weak(n, n + 1, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => n = actual,
            }
        }
        false
    }

    /// Give a buffer back to its pool. Called when it is dropped.
    ///
    /// # Safety
    /// `raw` must be the `RawPacketBuf` `alloc` gave the buffer, and the buffer must
    /// no longer be used.
    unsafe fn free(raw: NonNull<RawPacketBuf>) {
        // SAFETY: `alloc` set `raw.pool` to a `&'static Self`. `raw` is the first
        // field of a slot `alloc` got from `Box::into_raw`.
        unsafe {
            let pool = &*raw.as_ref().pool.cast::<Self>();
            drop(Box::from_raw(raw.cast::<Slot<SIZE, ALIGN>>().as_ptr()));
            pool.count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl<const SIZE: usize, const ALIGN: usize> Pool for AllocPool<SIZE, ALIGN>
where
    Align<ALIGN>: ValidAlign,
{
    #[inline(never)] // helps code size: it has many callers
    fn alloc(&'static self) -> Option<PacketBuf> {
        if !self.reserve() {
            return None;
        }
        // Zeroed, so the storage is initialized.
        let slot = Box::into_raw(Box::<Slot<SIZE, ALIGN>>::new_zeroed()).cast::<Slot<SIZE, ALIGN>>();
        // SAFETY: the slot is ours, and its storage is initialized.
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
            Some(PacketBuf::from_raw(NonNull::new_unchecked(raw)))
        }
    }

    fn buf_capacity(&self) -> usize {
        SIZE
    }
}
