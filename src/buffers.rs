//! Packet buffers, and the pool the stack allocates them from.
//!
//! Every buffer the stack allocates comes through [`Buffers`]. Only this stack
//! allocates from its pool (`Stack::new` takes it by `&'static mut`), and it
//! only takes buffers of its own pool: what drivers and sockets hand to it is
//! checked with [`Buffers::check_owned`].

// `PoolRef` erases the pool's type by hand.
#![allow(unsafe_code)]

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::driver::DriverBuf;
use crate::pool::Pool;

/// A packet buffer the network stack lets wait: in a socket's queue, or in the
/// application's hands.
///
/// This is what sockets hand out, from `alloc` and `recv`. It derefs to
/// [`DriverBuf`], which has the methods to read and change the packet.
///
/// Dropping it gives it back to the pool.
pub struct Buf(DriverBuf);

impl Buf {
    /// Make a `Buf` out of a [`DriverBuf`].
    pub fn from_driver_buf(buf: DriverBuf) -> Self {
        Buf(buf)
    }

    /// The buffer itself, to hand to something that takes a [`DriverBuf`].
    pub fn into_driver_buf(self) -> DriverBuf {
        self.0
    }
}

impl Deref for Buf {
    type Target = DriverBuf;
    #[inline]
    fn deref(&self) -> &DriverBuf {
        &self.0
    }
}

impl DerefMut for Buf {
    #[inline]
    fn deref_mut(&mut self) -> &mut DriverBuf {
        &mut self.0
    }
}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buf")
            .field("headroom", &self.headroom())
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Buf {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "Buf {{ headroom: {}, len: {} }}", self.headroom(), self.len());
    }
}

/// A type-erased reference to a [`Pool`], without a vtable.
#[derive(Clone, Copy)]
struct PoolRef {
    pool: NonNull<()>,
    alloc: unsafe fn(NonNull<()>) -> Option<DriverBuf>,
}

// SAFETY: `pool` comes from a `&'static P` with `P: Pool`, and `Pool: Sync`.
unsafe impl Send for PoolRef {}
unsafe impl Sync for PoolRef {}

impl PoolRef {
    fn new<P: Pool + 'static>(pool: &'static P) -> Self {
        /// SAFETY: `pool` must point to a `P` that lives for `'static`.
        unsafe fn alloc<P: Pool + 'static>(pool: NonNull<()>) -> Option<DriverBuf> {
            let pool: &'static P = unsafe { pool.cast::<P>().as_ref() };
            pool.alloc()
        }

        Self {
            pool: NonNull::from(pool).cast(),
            alloc: alloc::<P>,
        }
    }

    #[inline]
    fn alloc(&self) -> Option<DriverBuf> {
        // SAFETY: `pool` and `alloc` were made from the same `&'static P` in `new`.
        unsafe { (self.alloc)(self.pool) }
    }
}

/// The stack's pool.
pub(crate) struct Buffers {
    pool: PoolRef,
}

impl Buffers {
    pub(crate) fn new<P: Pool + 'static>(pool: &'static P) -> Self {
        Self {
            pool: PoolRef::new(pool),
        }
    }

    /// Allocate a buffer, see [`Pool::alloc`].
    #[inline]
    pub(crate) fn alloc(&self) -> Option<DriverBuf> {
        self.pool.alloc()
    }

    /// Whether `buf` comes from this stack's pool.
    #[inline]
    pub(crate) fn owns(&self, buf: &DriverBuf) -> bool {
        buf.pool() == self.pool.pool.as_ptr().cast_const()
    }

    /// Panic if `buf` doesn't come from this stack's pool. For buffers coming in
    /// from outside the stack: what drivers and sockets hand to it.
    #[inline]
    #[track_caller]
    pub(crate) fn check_owned(&self, buf: &DriverBuf) {
        assert!(self.owns(buf), "packet buffer from another stack's pool");
    }
}

/// The pool type of the unit tests, with as many buffers as a test can want.
/// Each test makes its own, since a pool belongs to one stack.
#[cfg(test)]
pub(crate) type TestPool = crate::pool::StaticPool<TEST_POOL_SIZE, 1024>;

/// The buffer size of [`TestPool`]: an Ethernet frame plus the test device's
/// driver headroom.
#[cfg(test)]
pub(crate) const TEST_POOL_SIZE: usize = 1514 + crate::test_device::TX_HEADROOM;

/// A fresh pool for a test.
#[cfg(test)]
#[allow(dead_code)] // which builds use it depends on the features
pub(crate) fn test_pool() -> &'static mut TestPool {
    // Zeroed on the heap rather than built on the test thread's stack, which is
    // too small for it. Untouched pages cost nothing.
    // SAFETY: an all-zero `StaticPool` is a new one: that is how it lives in `.bss`.
    alloc::boxed::Box::leak(unsafe { alloc::boxed::Box::<TestPool>::new_zeroed().assume_init() })
}

/// A fresh pool, for tests of what allocates without a stack.
#[cfg(test)]
#[allow(dead_code)] // which builds use it depends on the features
pub(crate) fn test_buffers() -> &'static Buffers {
    let pool: &'static TestPool = test_pool();
    alloc::boxed::Box::leak(alloc::boxed::Box::new(Buffers::new(pool)))
}

/// A buffer from a fresh pool, for tests that build packets by hand.
#[cfg(test)]
#[allow(dead_code)] // which builds use it depends on the features
pub(crate) fn test_buf() -> DriverBuf {
    use crate::pool::Pool;
    let pool: &'static TestPool = test_pool();
    pool.alloc().unwrap()
}

/// A [`Buf`] from a fresh pool, for tests of what holds them.
#[cfg(test)]
#[allow(dead_code)] // which builds use it depends on the features
pub(crate) fn test_kept_buf() -> Buf {
    Buf(test_buf())
}
