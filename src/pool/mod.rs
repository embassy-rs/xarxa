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

use crate::driver::{DriverBuf, RawDriverBuf};

/// Packet pool trait.
///
/// You most likely don't want to implement this trait, instead use one of the ready-made
/// implementations provided by this crate:
/// - [`StaticPool`]: a fixed number of buffers, in a `static`. Needs no heap.
/// - `AllocPool`: buffers allocated from the heap, up to a limit. Needs the
///   `alloc` feature.
///
/// To implement it yourself, build buffers with [`DriverBuf::from_raw`].
///
/// Implementations must guarantee:
/// - Every buffer `alloc` returns has a [`capacity`](DriverBuf::capacity) of
///   [`buf_capacity`](Self::buf_capacity).
/// - Every buffer `alloc` returns has the pool's own address as its
///   [`RawDriverBuf::pool`].
/// - `buf_capacity` is between 128 and 65535, and never changes.
///
/// `DriverBuf` has no lifetime, so the pool must be `'static`.
pub trait Pool: Sync {
    /// Allocate a buffer.
    ///
    /// Returns `None` if the pool has no buffer to give.
    ///
    /// The buffer has zero headroom and length, and default metadata. Its storage
    /// may hold data from earlier packets.
    fn alloc(&'static self) -> Option<DriverBuf>;

    /// Size of the storage of each buffer, in bytes.
    fn buf_capacity(&self) -> usize;
}

/// One buffer of a pool: its `RawDriverBuf`, then its storage, aligned to `ALIGN`.
///
/// `raw` comes first, so a pointer to it is a pointer to the slot.
#[repr(C)]
struct Slot<const SIZE: usize, const ALIGN: usize>
where
    Align<ALIGN>: ValidAlign,
{
    raw: MaybeUninit<RawDriverBuf>,
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

#[cfg(test)]
mod tests;
