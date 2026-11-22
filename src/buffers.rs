//! Packet buffers, and the accounting that keeps the stack from running out.
//!
//! Every buffer the stack allocates comes through [`Buffers`], and every buffer
//! that waits (in a socket queue, the pending queue, the fragmenter, a
//! reassembly slot, the application's hands) is a [`Buf`], which only
//! [`Buffers::keep`] makes. So the rule below can't be skipped by accident:
//! nothing outside this module can allocate or make a `Buf` any other way.
//!
//! The rule: whatever makes a buffer wait leaves at least `reserve` buffers
//! free, one for each starved interface (one whose driver has no buffer to
//! receive into) and one more. A buffer that only moves through the stack, to a
//! device or out of one, comes back without anybody's help, so it may go below
//! that:
//!
//! | Allocation | Leaves free |
//! |---|---|
//! | [`alloc`](Buffers::alloc): standard, may end up waiting | `reserve` |
//! | [`alloc_starved`](Buffers::alloc_starved): first buffer of a starved driver | `reserve - 1` |
//! | [`alloc_urgent`](Buffers::alloc_urgent): a packet that frees others once sent | 0 |
//!
//! So however many buffers wait, each interface can always be given one to
//! receive into, and the stack can always send one solicitation or fragment.
//! Those are what the buffers that wait on a neighbor or in the fragmenter need
//! to move again.
//!
//! An interface whose driver still has a buffer needs none kept for it. It only
//! runs out by handing its last buffer to the stack with `receive`, and the stack
//! asks it again whether it is starved before it processes that buffer. If it is,
//! the buffer can only wait if one stays free for the interface. Otherwise it is
//! dropped, and the driver gets it back. A driver that drops its buffers itself
//! breaks this, see [`Driver::rx_give`](crate::driver::Driver::rx_give).
//!
//! The count is the pool's free count. A buffer is not tagged with where it came
//! from: one allocated below the threshold that then tries to wait fails
//! [`keep`](Buffers::keep) like any other, and is dropped.
//!
//! Only this stack allocates from its pool (`Stack::new` takes it by `&'static mut`),
//! and buffers dropped elsewhere only make the count go up. So a check followed by
//! an allocation can't race.

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

impl Buf {
    /// Wrap again a buffer that came in as a `Buf` and was refused: a send that
    /// handed it back. It needs no check, since it didn't go back to the pool in
    /// between, so the free count is what it was.
    #[allow(dead_code)] // which builds use it depends on the features
    pub(crate) fn from_refused(buf: DriverBuf) -> Self {
        Buf(buf)
    }
}

/// A type-erased reference to a [`Pool`], without a vtable.
#[derive(Clone, Copy)]
struct PoolRef {
    pool: NonNull<()>,
    alloc: unsafe fn(NonNull<()>) -> Option<DriverBuf>,
    has_free: unsafe fn(NonNull<()>, usize) -> bool,
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
        /// SAFETY: `pool` must point to a `P` that lives for `'static`.
        unsafe fn has_free<P: Pool + 'static>(pool: NonNull<()>, count: usize) -> bool {
            let pool: &'static P = unsafe { pool.cast::<P>().as_ref() };
            pool.has_free(count)
        }

        Self {
            pool: NonNull::from(pool).cast(),
            alloc: alloc::<P>,
            has_free: has_free::<P>,
        }
    }

    #[inline]
    fn alloc(&self) -> Option<DriverBuf> {
        // SAFETY: `pool` and `alloc` were made from the same `&'static P` in `new`.
        unsafe { (self.alloc)(self.pool) }
    }

    #[inline]
    fn has_free(&self, count: usize) -> bool {
        // SAFETY: `pool` and `has_free` were made from the same `&'static P` in `new`.
        unsafe { (self.has_free)(self.pool, count) }
    }
}

/// The stack's pool, and how many of its buffers are kept free.
pub(crate) struct Buffers {
    pool: PoolRef,
    /// How many interfaces are starved, as their drivers last said.
    starved: usize,
}

impl Buffers {
    pub(crate) fn new<P: Pool + 'static>(pool: &'static P) -> Self {
        Self {
            pool: PoolRef::new(pool),
            starved: 0,
        }
    }

    /// How many buffers whatever makes a buffer wait has to leave free: one for
    /// each starved interface, to give it, and one to send a solicitation or a
    /// fragment.
    #[inline]
    fn reserve(&self) -> usize {
        self.starved + 1
    }

    /// Record whether an interface is starved. `flag` is the interface's own
    /// record of it.
    #[inline]
    pub(crate) fn set_starved(&mut self, flag: &mut bool, starved: bool) {
        if *flag != starved {
            *flag = starved;
            if starved {
                self.starved += 1;
            } else {
                self.starved -= 1;
            }
        }
    }

    /// Allocate a buffer that may end up waiting. It leaves the reserve free.
    #[inline]
    pub(crate) fn alloc(&self) -> Option<DriverBuf> {
        if !self.pool.has_free(self.reserve() + 1) {
            return None;
        }
        self.pool.alloc()
    }

    /// Allocate a buffer that will wait, see [`keep`](Self::keep).
    #[allow(dead_code)] // which builds use it depends on the features
    #[inline]
    pub(crate) fn alloc_kept(&self) -> Option<Buf> {
        self.alloc().map(Buf)
    }

    /// Allocate the first buffer of a driver that has none to receive into. Its
    /// interface must be recorded as starved with [`set_starved`](Self::set_starved),
    /// so this takes the buffer kept for it. It leaves those of the other starved
    /// interfaces free, and one for [`alloc_urgent`](Self::alloc_urgent).
    #[inline]
    pub(crate) fn alloc_starved(&self) -> Option<DriverBuf> {
        if !self.pool.has_free(self.reserve()) {
            return None;
        }
        self.pool.alloc()
    }

    /// Allocate a buffer for a packet that goes straight to a device and frees
    /// others once it has gone: a neighbor solicitation, a fragment. It may take
    /// the last free buffer.
    ///
    /// The caller checks first that the device has room for it, and that it
    /// won't wait anywhere on the way. If it ends up waiting anyway, `keep` refuses
    /// it.
    #[allow(dead_code)] // which builds use it depends on the features
    #[inline]
    pub(crate) fn alloc_urgent(&self) -> Option<DriverBuf> {
        self.pool.alloc()
    }

    /// Let a buffer wait, if the reserve stays free.
    ///
    /// The error hands the buffer back. The caller drops it, or hands it back
    /// to whoever gave it.
    #[inline]
    pub(crate) fn keep(&self, buf: DriverBuf) -> Result<Buf, DriverBuf> {
        debug_assert!(self.owns(&buf), "packet buffer from another stack's pool");
        if !self.pool.has_free(self.reserve()) {
            return Err(buf);
        }
        Ok(Buf(buf))
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

/// The accounting of a fresh pool, for tests of what allocates without a stack.
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
