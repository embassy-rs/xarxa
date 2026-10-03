//! Packet buffer pools.

// Pools hand out pointers into memory they manage, so they need `unsafe`.
#![allow(unsafe_code)]

#[cfg(feature = "alloc")]
mod alloc_pool;
mod static_pool;

#[cfg(feature = "alloc")]
pub use alloc_pool::AllocPool;
pub use static_pool::StaticPool;

use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::driver::{PacketBuf, RawPacketBuf};

/// Packet pool trait.
///
/// You mist likely don't want to implement this trait, instead use one of the ready-made
/// implementations provided by this crate:
/// - [`StaticPool`]: a fixed number of buffers, in a `static`. Needs no heap.
/// - `AllocPool`: buffers allocated from the heap, up to a limit. Needs the
///   `alloc` feature.
///
/// To implement it yourself, build buffers with [`PacketBuf::from_raw_parts`].
///
/// Implementations must guarantee:
/// - Every buffer `alloc` returns has a [`capacity`](PacketBuf::capacity) of
///   [`buf_capacity`](Self::buf_capacity).
/// - `buf_capacity` is between 128 and 65535, and never changes.
///
/// `PacketBuf` has no lifetime, so the pool must be `'static`.
pub trait Pool: Sync {
    /// Allocate a buffer.
    ///
    /// Returns `None` if the pool has no buffer to give.
    ///
    /// The buffer has zero headroom and length, and default metadata. Its storage
    /// may hold data from earlier packets.
    fn alloc(&'static self) -> Option<PacketBuf>;

    /// Size of the storage of each buffer, in bytes.
    fn buf_capacity(&self) -> usize;
}

/// A type-erased reference to a [`Pool`], without a vtable.
#[derive(Clone, Copy)]
pub(crate) struct PoolRef {
    pool: NonNull<()>,
    alloc: unsafe fn(NonNull<()>) -> Option<PacketBuf>,
}

// SAFETY: `pool` comes from a `&'static P` with `P: Pool`, and `Pool: Sync`.
unsafe impl Send for PoolRef {}
unsafe impl Sync for PoolRef {}

impl PoolRef {
    pub(crate) fn new<P: Pool + 'static>(pool: &'static P) -> Self {
        /// SAFETY: `pool` must point to a `P` that lives for `'static`.
        unsafe fn alloc<P: Pool + 'static>(pool: NonNull<()>) -> Option<PacketBuf> {
            let pool: &'static P = unsafe { pool.cast::<P>().as_ref() };
            pool.alloc()
        }

        Self {
            pool: NonNull::from(pool).cast(),
            alloc: alloc::<P>,
        }
    }

    /// Allocate a buffer, see [`Pool::alloc`].
    #[inline]
    pub(crate) fn alloc(&self) -> Option<PacketBuf> {
        // SAFETY: `pool` and `alloc` were made from the same `&'static P` in `new`.
        unsafe { (self.alloc)(self.pool) }
    }
}

/// One buffer of a pool: its `RawPacketBuf`, then its storage, aligned to `ALIGN`.
///
/// `raw` comes first, so a pointer to it is a pointer to the slot.
#[repr(C)]
struct Slot<const SIZE: usize, const ALIGN: usize>
where
    Align<ALIGN>: ValidAlign,
{
    raw: MaybeUninit<RawPacketBuf>,
    /// Aligns `data` to `ALIGN`.
    _align: [<Align<ALIGN> as ValidAlign>::Type; 0],
    data: [u8; SIZE],
}

/// A buffer alignment, for the `ALIGN` parameter of [`StaticPool`] and `AllocPool`.
///
/// [`ValidAlign`] is implemented for `Align<1>`, `Align<2>`, `Align<4>`,
/// `Align<8>`, `Align<16>`, `Align<32>` and `Align<64>`.
pub struct Align<const N: usize>;

/// The alignments the pools support. See [`Align`].
#[diagnostic::on_unimplemented(message = "pool align must be 1, 2, 4, 8, 16, 32 or 64")]
pub trait ValidAlign: sealed::Sealed {
    #[doc(hidden)]
    type Type: Copy;
}

mod sealed {
    pub trait Sealed {}

    macro_rules! align {
        ($($n:literal => $t:ident),*) => {
            $(
                #[derive(Clone, Copy)]
                #[repr(align($n))]
                pub struct $t;
                impl Sealed for super::Align<$n> {}
                impl super::ValidAlign for super::Align<$n> {
                    type Type = $t;
                }
            )*
        };
    }

    align!(1 => A1, 2 => A2, 4 => A4, 8 => A8, 16 => A16, 32 => A32, 64 => A64);
}

/// The smallest buffers a pool can have, in bytes.
pub(crate) const MIN_BUF_CAPACITY: usize = 128;

/// Fail the build if the buffers of a pool don't fit the stack. The pools call it
/// in a `const` block from their `new`.
///
/// The headroom a driver needs is only known when its interface is added, so
/// this leaves it out. `Stack::add_iface` checks again with it.
const fn check_buf_capacity(capacity: usize) {
    // Room for the largest headers the stack writes in front of a payload.
    core::assert!(capacity >= MIN_BUF_CAPACITY, "Pool buffers must be at least 128 bytes");
    // DHCP messages can be up to 576 bytes long, the IPv4 minimum MTU (RFC 2131 §2),
    // and DHCP runs on Ethernet.
    #[cfg(any(feature = "dhcpv4", feature = "dhcpv4-server"))]
    core::assert!(
        capacity >= crate::wire::ETHERNET_HEADER_LEN + crate::wire::IPV4_MIN_MTU,
        "DHCP needs Pool buffers of at least 590 bytes, plus the driver headroom"
    );
}

/// The pool type of the unit tests. They run in parallel threads of one process,
/// all sharing one pool, so it is big. Its buffers hold an Ethernet frame plus
/// the test device's driver headroom.
#[cfg(test)]
pub(crate) type TestPool = StaticPool<TEST_POOL_SIZE, 1024>;

/// The buffer size of [`TestPool`].
#[cfg(test)]
pub(crate) const TEST_POOL_SIZE: usize = 1514 + crate::test_device::TX_HEADROOM;

/// The pool the unit tests share.
#[cfg(test)]
pub(crate) fn test_pool() -> &'static TestPool {
    static POOL: TestPool = StaticPool::new();
    &POOL
}

/// [`test_pool`], erased.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pool_ref() -> PoolRef {
    PoolRef::new(test_pool())
}

#[cfg(test)]
mod tests;
