//! Reassembly of incoming fragments: IPv4 (feature `ipv4-reassembly`) and
//! 6LoWPAN (feature `sixlowpan-reassembly`).
//!
//! The fragments of one datagram are copied into a `PacketBuf` taken from the
//! pool, at their offsets, and the buffer is handed up the stack whole once the
//! last hole is filled. So a reassembled packet must fit one buffer of the pool,
//! and each datagram being reassembled pins one pool buffer until it completes or
//! expires.

use core::fmt;

use crate::config::REASSEMBLY_BUFFER_COUNT;
use crate::driver::PacketBuf;
use crate::pool::PoolRef;
use crate::stack::Stack;
use crate::storage::Assembler;
use crate::time::{Clock, Duration, Instant};
use crate::wire::*;

/// Problem when assembling: something was out of bounds, or no packet buffer is free.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerError;

impl fmt::Display for AssemblerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerError")
    }
}

impl core::error::Error for AssemblerError {}

/// Packet assembler is full
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AssemblerFullError;

impl fmt::Display for AssemblerFullError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AssemblerFullError")
    }
}

impl core::error::Error for AssemblerFullError {}

/// Holds different fragments of one packet, used for assembling fragmented packets.
///
/// The fragments are assembled into a `PacketBuf`, taken from the pool when the
/// first one arrives and handed out whole by [`assemble`](Self::assemble).
#[derive(Debug)]
pub struct PacketAssembler<K> {
    key: Option<K>,
    buffer: Option<PacketBuf>,

    assembler: Assembler,
    total_size: Option<usize>,
    expires_at: Instant,
}

impl<K> PacketAssembler<K> {
    /// Create a new empty buffer for fragments.
    pub const fn new() -> Self {
        Self {
            key: None,
            buffer: None,

            assembler: Assembler::new(),
            total_size: None,
            expires_at: Instant::ZERO,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.key = None;
        self.buffer = None;
        self.assembler.clear();
        self.total_size = None;
        self.expires_at = Instant::ZERO;
    }

    /// The buffer the fragments are assembled into, taken from the pool on first use.
    fn buffer(&mut self, pool: PoolRef) -> Result<&mut PacketBuf, AssemblerError> {
        if self.buffer.is_none() {
            self.buffer = Some(pool.alloc().ok_or(AssemblerError)?);
        }
        // NOTE(unwrap): filled in just above.
        Ok(unwrap!(self.buffer.as_mut()))
    }

    /// Set the total size of the packet assembler.
    pub(crate) fn set_total_size(&mut self, size: usize) -> Result<(), AssemblerError> {
        if let Some(old_size) = self.total_size
            && old_size != size
        {
            return Err(AssemblerError);
        }

        self.total_size = Some(size);
        Ok(())
    }

    /// Add a fragment into the packet that is being reassembled.
    ///
    /// # Errors
    /// - `AssemblerError`: if the data goes at a place that does not exist, if
    ///   the fragments leave more holes than can be tracked, or if no packet
    ///   buffer is free.
    pub(crate) fn add(&mut self, pool: PoolRef, data: &[u8], offset: usize) -> Result<(), AssemblerError> {
        let len = data.len();
        let buffer = self.buffer(pool)?;
        if buffer.capacity() < offset + len {
            return Err(AssemblerError);
        }

        self.assembler.add(offset, len).map_err(|_| AssemblerError)?;

        // NOTE(unwrap): allocated just above.
        let buffer = unwrap!(self.buffer.as_mut());
        if buffer.len() < offset + len {
            buffer.set_len(offset + len);
        }
        buffer[offset..][..len].copy_from_slice(data);

        debug!("frag assembler: receiving {} octets at offset {}", len, offset);

        Ok(())
    }

    /// Get the reassembled packet, if reassembly is complete.
    /// This will mark the assembler as empty, so that it can be reused.
    pub(crate) fn assemble(&mut self, pool: PoolRef) -> Option<PacketBuf> {
        if !self.is_complete() {
            return None;
        }

        // NOTE: we can unwrap because `is_complete` already checks this.
        let total_size = self.total_size.unwrap();
        self.buffer(pool).ok()?.set_len(total_size);
        let buffer = self.buffer.take();
        self.reset();
        buffer
    }

    /// Returns `true` when all fragments have been received, otherwise `false`.
    pub(crate) fn is_complete(&self) -> bool {
        self.total_size == Some(self.assembler.peek_front())
    }

    /// Returns `true` when the packet assembler is free to use.
    fn is_free(&self) -> bool {
        self.key.is_none()
    }
}

/// Set holding multiple [`PacketAssembler`].
#[derive(Debug)]
pub struct PacketAssemblerSet<K: Eq + Copy> {
    assemblers: [PacketAssembler<K>; REASSEMBLY_BUFFER_COUNT],
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    /// Create a new set of packet assemblers.
    pub fn new() -> Self {
        Self {
            assemblers: [const { PacketAssembler::new() }; REASSEMBLY_BUFFER_COUNT],
        }
    }

    /// Get a [`PacketAssembler`] for a specific key.
    ///
    /// If it doesn't exist, it is created, with the `expires_at` timestamp.
    ///
    /// # Errors
    /// - `AssemblerFullError`: if the assembler set is full.
    pub(crate) fn get(&mut self, key: &K, expires_at: Instant) -> Result<&mut PacketAssembler<K>, AssemblerFullError> {
        let mut empty_slot = None;
        for slot in &mut self.assemblers {
            if slot.key.as_ref() == Some(key) {
                return Ok(slot);
            }
            if slot.is_free() {
                empty_slot = Some(slot)
            }
        }

        let slot = empty_slot.ok_or(AssemblerFullError)?;
        slot.key = Some(*key);
        slot.expires_at = expires_at;
        Ok(slot)
    }

    /// Remove all [`PacketAssembler`]s that are expired.
    pub fn remove_expired(&mut self, clock: &mut Clock) {
        for frag in &mut self.assemblers {
            if !frag.is_free() && clock.expired(frag.expires_at) {
                frag.reset();
            }
        }
    }
}

/// The fields that identify the fragments of one IPv4 datagram.
#[cfg(feature = "ipv4-reassembly")]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Ipv4FragKey {
    id: u16,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    protocol: IpProtocol,
}

#[cfg(feature = "ipv4-reassembly")]
impl Ipv4FragKey {
    /// The key identifying the packet a fragment belongs to.
    pub(crate) fn of(packet: &Ipv4Packet<'_>) -> Self {
        Self {
            id: packet.ident(),
            src_addr: packet.src_addr(),
            dst_addr: packet.dst_addr(),
            protocol: packet.next_header(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum FragKey {
    #[cfg(feature = "ipv4-reassembly")]
    Ipv4(Ipv4FragKey),
    #[cfg(feature = "sixlowpan-reassembly")]
    Sixlowpan(SixlowpanFragKey),
}

pub(crate) struct FragmentsBuffer {
    pub assembler: PacketAssemblerSet<FragKey>,

    pub reassembly_timeout: Duration,
}

impl FragmentsBuffer {
    pub(crate) fn new() -> Self {
        Self {
            assembler: PacketAssemblerSet::new(),
            reassembly_timeout: Duration::from_secs(60),
        }
    }
}

impl Stack<'_> {
    /// Get the packet reassembly timeout.
    ///
    /// This is how long the fragments of an incoming IPv4 or 6LoWPAN packet are
    /// kept while waiting for the rest of it. The default is 60 seconds.
    pub fn reassembly_timeout(&self) -> Duration {
        self.fragments.reassembly_timeout
    }

    /// Set the packet reassembly timeout.
    ///
    /// Fragments of an incoming IPv4 or 6LoWPAN packet that is not complete by
    /// then are dropped, and the packet buffer they were kept in is freed.
    pub fn set_reassembly_timeout(&mut self, timeout: Duration) {
        self.fragments.reassembly_timeout = timeout;
    }

    /// Add an IPv4 fragment to the packet it belongs to.
    ///
    /// Returns the whole packet once its last fragment is in, with this
    /// fragment's IP header in front, patched to describe the whole datagram.
    /// `None` while the packet is incomplete, or if the fragment was dropped.
    #[cfg(feature = "ipv4-reassembly")]
    pub(crate) fn reassemble_ipv4(&mut self, mut buf: PacketBuf, now: Instant) -> Option<PacketBuf> {
        let ipv4_packet = Ipv4Packet::new_unchecked(&mut buf);

        let key = FragKey::Ipv4(Ipv4FragKey::of(&ipv4_packet));

        let f = match self
            .fragments
            .assembler
            .get(&key, now + self.fragments.reassembly_timeout)
        {
            Ok(f) => f,
            Err(_) => {
                debug!("No available packet assembler for fragmented packet");
                return None;
            }
        };

        if !ipv4_packet.more_frags() {
            // This is the last fragment, so we know the total size
            check!(f.set_total_size(
                ipv4_packet.total_len() as usize - ipv4_packet.header_len() as usize
                    + ipv4_packet.frag_offset() as usize,
            ));
        }

        if let Err(e) = f.add(
            self.inner.pool,
            ipv4_packet.payload(),
            ipv4_packet.frag_offset() as usize,
        ) {
            debug!("fragmentation error: {:?}", e);
            return None;
        }

        let mut payload = f.assemble(self.inner.pool)?;

        // The reassembled packet is this fragment's IP header, patched to
        // describe the whole datagram, in front of the reassembled payload.
        let header_len = ipv4_packet.header_len() as usize;
        let payload_len = payload.len();
        if !payload.ensure_headroom(header_len) {
            debug!("reassembled packet does not fit in a packet buffer");
            return None;
        }
        payload.push_front(header_len);
        payload[..header_len].copy_from_slice(&buf[..header_len]);
        let mut packet = Ipv4Packet::new_unchecked(&mut payload);
        packet.set_total_len((header_len + payload_len) as u16);
        packet.set_more_frags(false);
        packet.set_frag_offset(0);
        // Always computed, whatever the device offloads: the reassembled packet
        // continues up the ingress path and is handed to raw sockets as-is, so its
        // header has to describe itself correctly.
        packet.fill_checksum();
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::idle_deadline;

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
    struct Key {
        id: usize,
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        p_assembler.set_total_size(5).unwrap();

        let data = b"Rust";
        p_assembler.add(crate::pool::test_pool_ref(), &data[..], 0).unwrap();
        p_assembler.add(crate::pool::test_pool_ref(), &data[..], 1).unwrap();

        assert_eq!(
            p_assembler.assemble(crate::pool::test_pool_ref()).as_deref(),
            Some(&b"RRust"[..])
        )
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler.add(crate::pool::test_pool_ref(), b"Hello ", 0).unwrap();
        assert_eq!(p_assembler.assemble(crate::pool::test_pool_ref()).as_deref(), None);

        p_assembler
            .add(crate::pool::test_pool_ref(), b"World!", b"Hello ".len())
            .unwrap();

        assert_eq!(
            p_assembler.assemble(crate::pool::test_pool_ref()).as_deref(),
            Some(&b"Hello World!"[..])
        );
    }

    #[test]
    fn packet_assembler_out_of_order_assemble() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        let data = b"Hello World!";

        p_assembler.set_total_size(data.len()).unwrap();

        p_assembler
            .add(crate::pool::test_pool_ref(), b"World!", b"Hello ".len())
            .unwrap();
        assert_eq!(p_assembler.assemble(crate::pool::test_pool_ref()).as_deref(), None);

        p_assembler.add(crate::pool::test_pool_ref(), b"Hello ", 0).unwrap();

        assert_eq!(
            p_assembler.assemble(crate::pool::test_pool_ref()).as_deref(),
            Some(&b"Hello World!"[..])
        );
    }

    #[test]
    fn packet_assembler_too_large() {
        let mut p_assembler = PacketAssembler::<Key>::new();

        assert_eq!(p_assembler.set_total_size(crate::pool::TEST_POOL_SIZE), Ok(()));
        assert_eq!(p_assembler.set_total_size(crate::pool::TEST_POOL_SIZE), Ok(()));
        assert_eq!(
            p_assembler.add(crate::pool::test_pool_ref(), &[0; 8], crate::pool::TEST_POOL_SIZE - 8),
            Ok(())
        );
        assert_eq!(
            p_assembler.add(crate::pool::test_pool_ref(), &[0; 8], crate::pool::TEST_POOL_SIZE - 7),
            Err(AssemblerError)
        );
    }

    #[test]
    fn packet_assembler_set() {
        let key = Key { id: 1 };

        let mut set = PacketAssemblerSet::new();

        assert!(set.get(&key, Instant::ZERO).is_ok());
    }

    #[test]
    fn packet_assembler_set_full() {
        let mut set = PacketAssemblerSet::new();
        for i in 0..REASSEMBLY_BUFFER_COUNT {
            set.get(&Key { id: i }, Instant::ZERO).unwrap();
        }
        assert!(
            set.get(
                &Key {
                    id: REASSEMBLY_BUFFER_COUNT
                },
                Instant::ZERO
            )
            .is_err()
        );
    }

    #[test]
    fn packet_assembler_set_expiry() {
        let mut set = PacketAssemblerSet::new();
        let key = Key { id: 0 };
        set.get(&key, Instant::from_secs(10)).unwrap();
        let mut clock = Clock::new(Instant::from_secs(9));
        set.remove_expired(&mut clock);
        assert_eq!(clock.next(), Instant::from_secs(10));

        // Polling at the deadline removes it.
        let mut clock = Clock::new(Instant::from_secs(10));
        set.remove_expired(&mut clock);
        assert_eq!(clock.next(), idle_deadline(clock.now()));
    }

    #[test]
    fn packet_assembler_set_assembling_many() {
        let mut set = PacketAssemblerSet::new();

        let key = Key { id: 0 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert!(assr.assemble(crate::pool::test_pool_ref()).is_none());
        assr.set_total_size(0).unwrap();
        assr.assemble(crate::pool::test_pool_ref()).unwrap();

        // Test that `.assemble()` effectively deletes it.
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assert!(assr.assemble(crate::pool::test_pool_ref()).is_none());
        assr.set_total_size(0).unwrap();
        assr.assemble(crate::pool::test_pool_ref()).unwrap();

        let key = Key { id: 1 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble(crate::pool::test_pool_ref()).unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(0).unwrap();
        assr.assemble(crate::pool::test_pool_ref()).unwrap();

        let key = Key { id: 2 };
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.set_total_size(2).unwrap();
        assr.add(crate::pool::test_pool_ref(), &[0x00], 0).unwrap();
        assert!(assr.assemble(crate::pool::test_pool_ref()).is_none());
        let assr = set.get(&key, Instant::ZERO).unwrap();
        assr.add(crate::pool::test_pool_ref(), &[0x01], 1).unwrap();
        assert_eq!(
            assr.assemble(crate::pool::test_pool_ref()).as_deref(),
            Some(&[0x00, 0x01][..])
        );
    }
}
