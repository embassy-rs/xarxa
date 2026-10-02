//! Owned packet buffers.
//!
//! Every packet in the stack is a [`PacketBuf`]: one buffer, owned by whoever
//! holds it (the driver, the stack, a socket, the application).
//!
//! Buffers come from the network stack's pool. A driver gets the buffers it
//! receives frames into from the stack, with
//! [`Driver::rx_give`](crate::Driver::rx_give). Dropping a buffer gives it back
//! to the pool it came from.

use core::fmt;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use crate::meta::PacketMeta;

/// The bookkeeping of one [`PacketBuf`]: where its storage is, its headroom and
/// length, its metadata, and how to free it.
///
/// Only pool implementations deal with this type. They keep one for each buffer,
/// fill it in, and pass it to [`PacketBuf::from_raw`].
pub struct RawPacketBuf {
    /// Called with this `RawPacketBuf` when the buffer is dropped. It gives the buffer
    /// back to its pool.
    pub free: unsafe fn(NonNull<RawPacketBuf>),
    /// For the pool's own use, for example to find itself in `free`. The buffer
    /// never reads it.
    pub pool: *const (),
    /// Start of the storage.
    pub data: NonNull<u8>,
    /// Size of the storage at `data`, in bytes.
    pub capacity: usize,
    /// Offset of the first valid byte within the storage.
    pub headroom: usize,
    /// Number of valid bytes.
    pub len: usize,
    /// Per-packet metadata. Zero-sized unless a `packetmeta-*` feature is enabled.
    pub meta: PacketMeta,
}

/// An owned network packet buffer.
///
/// ```text
/// | headroom | data (len) | tailroom |
/// ```
///
/// Dropping it gives it back to the pool it came from.
pub struct PacketBuf {
    raw: NonNull<RawPacketBuf>,
}

// SAFETY: a `PacketBuf` is the unique owner of its `RawPacketBuf` and storage, like a
// `Box` of them. Its `free` can be called from any thread (see `from_raw`).
unsafe impl Send for PacketBuf {}
unsafe impl Sync for PacketBuf {}

impl PacketBuf {
    /// Make a buffer out of a `RawPacketBuf` a pool filled in.
    ///
    /// For pool implementations. Dropping the buffer calls `raw.free` with `raw`.
    ///
    /// A fresh buffer usually has zero `headroom` and `len`, and default `meta`.
    ///
    /// # Safety
    ///
    /// - `raw` must be initialized, and valid for reads and writes until
    ///   `free` is called.
    /// - Its `data` must be valid for reads and writes of `capacity` bytes until
    ///   then. Those bytes must be initialized.
    /// - Its `headroom + len` must be at most `capacity`.
    /// - Nothing else may access `raw` or the storage until `free` is
    ///   called.
    /// - `free` must be safe to call once with `raw`, from any thread, after
    ///   the buffer is dropped.
    pub unsafe fn from_raw(raw: NonNull<RawPacketBuf>) -> Self {
        Self { raw }
    }

    #[inline]
    fn raw(&self) -> &RawPacketBuf {
        // SAFETY: we own the `RawPacketBuf` for as long as `self` exists.
        unsafe { self.raw.as_ref() }
    }

    #[inline]
    fn raw_mut(&mut self) -> &mut RawPacketBuf {
        // SAFETY: we own the `RawPacketBuf` for as long as `self` exists, and `&mut self`
        // makes this the only reference.
        unsafe { self.raw.as_mut() }
    }

    /// The whole storage, ignoring headroom and length.
    #[inline]
    fn storage(&self) -> &[u8] {
        let raw = self.raw();
        // SAFETY: `data` is valid and initialized for `capacity` bytes, and only
        // this buffer accesses it.
        unsafe { core::slice::from_raw_parts(raw.data.as_ptr(), raw.capacity) }
    }

    /// The packet's metadata.
    ///
    /// On a received packet this is what the driver attached to it. On a packet being
    /// sent it is what the application attached, and what the driver will see in
    /// [`Driver::transmit`](crate::Driver::transmit). It travels with the
    /// buffer through the whole stack, unaffected by header pushes and pulls.
    pub fn meta(&self) -> PacketMeta {
        self.raw().meta
    }

    /// Mutable reference to the packet's metadata.
    pub fn meta_mut(&mut self) -> &mut PacketMeta {
        &mut self.raw_mut().meta
    }

    /// Replace the packet's metadata.
    pub fn set_meta(&mut self, meta: PacketMeta) {
        self.raw_mut().meta = meta;
    }

    /// Total storage capacity of the buffer, in bytes.
    pub fn capacity(&self) -> usize {
        self.raw().capacity
    }

    /// Amount of free space in front of the payload.
    pub fn headroom(&self) -> usize {
        self.raw().headroom
    }

    /// Length of the payload.
    pub fn len(&self) -> usize {
        self.raw().len
    }

    /// Whether the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.raw().len == 0
    }

    /// Amount of free space behind the payload.
    pub fn tailroom(&self) -> usize {
        self.capacity() - self.headroom() - self.len()
    }

    /// Empty the buffer, with `headroom` bytes of room in front of the payload.
    ///
    /// Use it on a new buffer, before writing a payload.
    ///
    /// # Panics
    /// Panics if `headroom > capacity`.
    pub fn reserve(&mut self, headroom: usize) {
        assert!(headroom <= self.capacity());
        let raw = self.raw_mut();
        raw.headroom = headroom;
        raw.len = 0;
    }

    /// Grow the payload at the front by `n` bytes, taking them from the headroom.
    ///
    /// # Panics
    /// Panics if `n > headroom`.
    pub fn push_front(&mut self, n: usize) {
        assert!(n <= self.headroom());
        let raw = self.raw_mut();
        raw.headroom -= n;
        raw.len += n;
    }

    /// Shrink the payload at the front by `n` bytes, returning them to the headroom.
    ///
    /// # Panics
    /// Panics if `n > len`.
    pub fn pull_front(&mut self, n: usize) {
        assert!(n <= self.len());
        let raw = self.raw_mut();
        raw.headroom += n;
        raw.len -= n;
    }

    /// Make room for `headroom` bytes in front of the payload, moving the payload
    /// back if there isn't enough already.
    ///
    /// Returns `false` if the buffer can't fit `headroom` plus the payload, leaving
    /// it unchanged.
    pub fn ensure_headroom(&mut self, headroom: usize) -> bool {
        if self.headroom() >= headroom {
            return true;
        }
        let len = self.len();
        if headroom + len > self.capacity() {
            return false;
        }
        let old = self.headroom();
        self.storage_mut().copy_within(old..old + len, headroom);
        self.raw_mut().headroom = headroom;
        true
    }

    /// Set the payload length, growing or shrinking it at the back.
    ///
    /// This does not clear newly exposed bytes.
    ///
    /// # Panics
    /// Panics if `headroom + len > capacity`.
    pub fn set_len(&mut self, len: usize) {
        assert!(self.headroom() + len <= self.capacity());
        self.raw_mut().len = len;
    }

    /// The whole underlying storage, ignoring headroom and length.
    ///
    /// Its alignment is up to the pool the buffer came from.
    pub fn storage_mut(&mut self) -> &mut [u8] {
        let raw = self.raw_mut();
        // SAFETY: `data` is valid and initialized for `capacity` bytes, and only
        // this buffer accesses it. `&mut self` makes this the only reference.
        unsafe { core::slice::from_raw_parts_mut(raw.data.as_ptr(), raw.capacity) }
    }
}

impl Drop for PacketBuf {
    #[inline(never)] // helps code size
    fn drop(&mut self) {
        let free = self.raw().free;
        // SAFETY: `from_raw` was given this `RawPacketBuf`, and the buffer is never used
        // again.
        unsafe { free(self.raw) }
    }
}

impl Deref for PacketBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        let raw = self.raw();
        let start = raw.headroom;
        let len = raw.len;
        // SAFETY: `headroom + len <= capacity`, which every method that changes
        // either of them checks.
        unsafe { self.storage().get_unchecked(start..start + len) }
    }
}

impl DerefMut for PacketBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let raw = self.raw();
        let start = raw.headroom;
        let len = raw.len;
        // SAFETY: `headroom + len <= capacity`, which every method that changes
        // either of them checks.
        unsafe { self.storage_mut().get_unchecked_mut(start..start + len) }
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("headroom", &self.headroom())
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketBuf {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "PacketBuf {{ headroom: {}, len: {} }}", self.headroom(), self.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;
    use std::boxed::Box;
    use std::sync::Mutex;

    const SIZE: usize = 256;

    /// A pool of heap buffers, freed on drop. Counts what is out.
    struct TestPool {
        out: Mutex<usize>,
    }

    /// One heap buffer. The `RawPacketBuf` comes first, so a pointer to it is a pointer
    /// to the whole thing.
    #[repr(C)]
    struct TestBuf {
        raw: MaybeUninit<RawPacketBuf>,
        data: [u8; SIZE],
    }

    impl TestPool {
        fn alloc(&'static self) -> Option<PacketBuf> {
            *self.out.lock().unwrap() += 1;
            let buf = Box::leak(Box::new(TestBuf {
                raw: MaybeUninit::uninit(),
                data: [0xa5; SIZE],
            }));
            let raw = buf.raw.write(RawPacketBuf {
                free,
                pool: (self as *const TestPool).cast(),
                data: NonNull::from(&mut buf.data).cast(),
                capacity: SIZE,
                headroom: 0,
                len: 0,
                meta: PacketMeta::default(),
            });
            // SAFETY: the allocation is fresh and only given to this buffer.
            // `free` gets back the `RawPacketBuf` of a `TestBuf`.
            Some(unsafe { PacketBuf::from_raw(NonNull::from(raw)) })
        }
    }

    unsafe fn free(raw: NonNull<RawPacketBuf>) {
        // SAFETY: the `RawPacketBuf` is the first field of a `TestBuf` from `Box::leak`,
        // and its pool is a `&'static TestPool`.
        unsafe {
            let pool = &*raw.as_ref().pool.cast::<TestPool>();
            drop(Box::from_raw(raw.cast::<TestBuf>().as_ptr()));
            *pool.out.lock().unwrap() -= 1;
        }
    }

    fn pool() -> &'static TestPool {
        Box::leak(Box::new(TestPool { out: Mutex::new(0) }))
    }

    #[test]
    fn push_pull() {
        let mut buf = pool().alloc().unwrap();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.headroom(), 0);
        assert_eq!(buf.capacity(), SIZE);
        assert_eq!(buf.tailroom(), SIZE);

        buf.reserve(42);
        assert_eq!(buf.headroom(), 42);
        buf.set_len(100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.tailroom(), SIZE - 142);
        buf.fill(0xaa);

        buf.push_front(20);
        assert_eq!(buf.headroom(), 22);
        assert_eq!(buf.len(), 120);
        assert_eq!(buf[20], 0xaa);

        buf.pull_front(20);
        assert_eq!(buf.headroom(), 42);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf[0], 0xaa);
    }

    #[test]
    fn ensure_headroom() {
        let mut buf = pool().alloc().unwrap();
        buf.reserve(10);
        buf.set_len(4);
        buf.copy_from_slice(&[1, 2, 3, 4]);

        // Already enough: nothing moves.
        assert!(buf.ensure_headroom(4));
        assert_eq!(buf.headroom(), 10);
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // Not enough: the payload moves back, unchanged.
        assert!(buf.ensure_headroom(20));
        assert_eq!(buf.headroom(), 20);
        assert_eq!(buf.len(), 4);
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // The headroom overlapping the payload is fine, it's a move not a copy.
        assert!(buf.ensure_headroom(22));
        assert_eq!(&*buf, &[1, 2, 3, 4]);

        // Doesn't fit: the buffer is left alone.
        assert!(!buf.ensure_headroom(SIZE - 3));
        assert_eq!(buf.headroom(), 22);
        assert_eq!(&*buf, &[1, 2, 3, 4]);
        assert!(buf.ensure_headroom(SIZE - 4));
        assert_eq!(&*buf, &[1, 2, 3, 4]);
    }

    #[test]
    #[should_panic]
    fn push_beyond_headroom() {
        let mut buf = pool().alloc().unwrap();
        buf.push_front(1);
    }

    /// Dropping a buffer gives it back to the pool it came from.
    #[test]
    fn drop_releases_to_its_pool() {
        let a = pool();
        let b = pool();
        let buf_a = a.alloc().unwrap();
        let buf_b = b.alloc().unwrap();
        assert_eq!(*a.out.lock().unwrap(), 1);
        assert_eq!(*b.out.lock().unwrap(), 1);
        drop(buf_a);
        assert_eq!(*a.out.lock().unwrap(), 0);
        assert_eq!(*b.out.lock().unwrap(), 1);
        drop(buf_b);
        assert_eq!(*b.out.lock().unwrap(), 0);
    }

    /// Metadata rides along with the buffer, untouched by the header pushes and pulls
    /// the packet goes through on its way up or down the stack.
    #[cfg(feature = "packetmeta-id")]
    #[test]
    fn meta_travels_with_the_buffer() {
        let mut buf = pool().alloc().unwrap();
        assert_eq!(buf.meta(), PacketMeta::default());

        buf.meta_mut().id = 0xdead_beef;
        buf.reserve(20);
        buf.set_len(10);
        buf.push_front(20);
        buf.pull_front(4);
        assert_eq!(buf.meta().id, 0xdead_beef);

        buf.set_meta(PacketMeta::default());
        assert_eq!(buf.meta().id, 0);
    }
}
