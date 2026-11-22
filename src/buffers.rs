//! Packet buffers that wait.

use core::fmt;
use core::ops::{Deref, DerefMut};

use crate::driver::DriverBuf;

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
