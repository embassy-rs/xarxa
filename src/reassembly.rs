//! Reassembly of incoming fragments: IPv4 (feature `ipv4-reassembly`) and
//! 6LoWPAN (feature `sixlowpan-reassembly`).
//!
//! The fragments of one datagram are copied into a `DriverBuf` taken from the
//! pool, at their offsets, and the buffer is handed up the stack whole once the
//! last hole is filled. So a reassembled packet must fit one buffer of the pool,
//! and each datagram being reassembled pins one pool buffer until it completes or
//! expires.

use core::fmt;

use crate::buffers::{Buf, Buffers};
use crate::config::REASSEMBLY_BUFFER_COUNT;
use crate::driver::DriverBuf;
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

/// How long a reassembly has to be in progress before the fragments of another
/// datagram may take its slot, when none is free. Long enough that datagrams
/// whose fragments arrive interleaved don't push each other out, and short
/// next to the reassembly timeout, so that one that never completes doesn't
/// block the others for long.
const REASSEMBLY_MIN_AGE: Duration = Duration::from_secs(1);

/// A fragment of a datagram, for [`PacketAssemblerSet::add`].
pub(crate) struct Fragment<'a, K> {
    /// The datagram it belongs to.
    pub key: K,
    /// Where its data goes in the datagram.
    pub offset: usize,
    pub data: &'a [u8],
    /// The size of the whole datagram, if the fragment tells.
    pub total_size: Option<usize>,
    /// The largest datagram the packet buffer it is reassembled in can take.
    pub max_size: usize,
    /// Whether a fragment that partly overlaps the data received so far
    /// discards it, and starts the reassembly over (RFC 4944 5.3). Without it,
    /// the fragment is merged in, over what was there (IPv4).
    pub restart_on_overlap: bool,
}

/// Holds different fragments of one packet, used for assembling fragmented packets.
///
/// The fragments are assembled into a buffer, taken from the pool when the
/// first one arrives and handed out whole by [`assemble`](Self::assemble). It
/// waits for the other fragments, so it is a [`Buf`]: it is only taken while
/// the pool has one to spare.
#[derive(Debug)]
pub struct PacketAssembler<K> {
    key: Option<K>,
    buffer: Option<Buf>,

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
    fn buffer(&mut self, buffers: &Buffers) -> Result<&mut Buf, AssemblerError> {
        if self.buffer.is_none() {
            self.buffer = Some(buffers.alloc_kept().ok_or(AssemblerError)?);
        }
        // NOTE(unwrap): filled in just above.
        Ok(unwrap!(self.buffer.as_mut()))
    }

    /// Add a fragment into the packet that is being reassembled.
    ///
    /// # Errors
    /// - `AssemblerError`: if the packet can't be completed anymore: the
    ///   fragment disagrees on its total size, or puts data past it, or leaves
    ///   more holes than can be tracked, or no packet buffer is free.
    fn add(&mut self, buffers: &Buffers, frag: &Fragment<'_, K>) -> Result<(), AssemblerError> {
        let len = frag.data.len();
        let end = frag.offset + len;
        if let Some(total_size) = frag.total_size {
            if self.total_size.is_some_and(|old_size| old_size != total_size) {
                return Err(AssemblerError);
            }
            self.total_size = Some(total_size);
        }
        if let Some(total_size) = self.total_size {
            let data_end = self.assembler.iter_data().last().map_or(0, |(_, data_end)| data_end);
            if end.max(data_end) > total_size {
                return Err(AssemblerError);
            }
        }

        if frag.restart_on_overlap {
            let overlap: usize = self
                .assembler
                .iter_data()
                .map(|(start, data_end)| data_end.min(end).saturating_sub(start.max(frag.offset)))
                .sum();
            if overlap == len {
                // All of it is in already: a duplicate. One cut differently looks
                // the same, and is dropped too.
                return Ok(());
            }
            if overlap != 0 {
                debug!("frag assembler: overlapping fragment, starting over");
                self.assembler.clear();
            }
        }

        let buffer = self.buffer(buffers)?;
        if buffer.capacity() < end {
            return Err(AssemblerError);
        }

        self.assembler.add(frag.offset, len).map_err(|_| AssemblerError)?;

        // NOTE(unwrap): allocated just above.
        let buffer = unwrap!(self.buffer.as_mut());
        if buffer.len() < end {
            buffer.set_len(end);
        }
        buffer[frag.offset..][..len].copy_from_slice(frag.data);

        debug!("frag assembler: receiving {} octets at offset {}", len, frag.offset);

        Ok(())
    }

    /// Get the reassembled packet, if reassembly is complete.
    /// This will mark the assembler as empty, so that it can be reused.
    fn assemble(&mut self, buffers: &Buffers) -> Option<DriverBuf> {
        if !self.is_complete() {
            return None;
        }

        // NOTE: we can unwrap because `is_complete` already checks this.
        let total_size = self.total_size.unwrap();
        self.buffer(buffers).ok()?.set_len(total_size);
        let buffer = self.buffer.take();
        self.reset();
        buffer.map(Buf::into_driver_buf)
    }

    /// Returns `true` when all fragments have been received, otherwise `false`.
    fn is_complete(&self) -> bool {
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
    /// The datagram reassembled last. A late duplicate of one of its fragments
    /// would start a reassembly that can't complete, so it is dropped.
    last_completed: Option<K>,
}

impl<K: Eq + Copy> PacketAssemblerSet<K> {
    /// Create a new set of packet assemblers.
    pub fn new() -> Self {
        Self {
            assemblers: [const { PacketAssembler::new() }; REASSEMBLY_BUFFER_COUNT],
            last_completed: None,
        }
    }

    /// Add a fragment to the datagram it belongs to, at `now`. The datagram's
    /// first fragment takes a slot for it, which `timeout` later expires.
    ///
    /// Returns the whole datagram, in a buffer from `buffers`, once its last
    /// fragment is in. A fragment that makes its datagram impossible to
    /// complete is dropped, along with the datagram's slot, if it has one.
    pub(crate) fn add(
        &mut self,
        buffers: &Buffers,
        frag: Fragment<'_, K>,
        now: Instant,
        timeout: Duration,
    ) -> Option<DriverBuf> {
        let end = frag.offset + frag.data.len();
        if end > frag.max_size || frag.total_size.is_some_and(|total_size| total_size > frag.max_size) {
            debug!("fragmented packet too large for a packet buffer");
            if let Some(slot) = self.assemblers.iter_mut().find(|slot| slot.key == Some(frag.key)) {
                slot.reset();
            }
            return None;
        }
        if self.last_completed == Some(frag.key) {
            debug!("fragment of a packet already reassembled");
            return None;
        }

        let Some(slot) = self.slot(frag.key, now, timeout) else {
            debug!("No available packet assembler for fragmented packet");
            return None;
        };
        if let Err(e) = slot.add(buffers, &frag) {
            debug!("fragmentation error: {:?}", e);
            slot.reset();
            return None;
        }
        let packet = slot.assemble(buffers)?;
        self.last_completed = Some(frag.key);
        Some(packet)
    }

    /// The slot of the datagram `key`. A new datagram takes a free slot, or else
    /// the one closest to expiring, once that one is `REASSEMBLY_MIN_AGE` old.
    fn slot(&mut self, key: K, now: Instant, timeout: Duration) -> Option<&mut PacketAssembler<K>> {
        if let Some(i) = self.assemblers.iter().position(|slot| slot.key == Some(key)) {
            return Some(&mut self.assemblers[i]);
        }

        let i = match self.assemblers.iter().position(|slot| slot.is_free()) {
            Some(i) => i,
            None => {
                let mut oldest: Option<usize> = None;
                for (i, slot) in self.assemblers.iter().enumerate() {
                    if oldest.is_none_or(|oldest| slot.expires_at < self.assemblers[oldest].expires_at) {
                        oldest = Some(i);
                    }
                }
                let oldest = oldest?;
                // Taken at `expires_at - timeout`, with the timeout set now.
                if now + timeout.saturating_sub(REASSEMBLY_MIN_AGE) < self.assemblers[oldest].expires_at {
                    return None;
                }
                debug!("frag assembler: dropping an incomplete packet for a new one");
                oldest
            }
        };

        let slot = &mut self.assemblers[i];
        slot.reset();
        slot.key = Some(key);
        slot.expires_at = now + timeout;
        Some(slot)
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
    pub(crate) fn reassemble_ipv4(&mut self, mut buf: DriverBuf, now: Instant) -> Option<DriverBuf> {
        let ipv4_packet = Ipv4Packet::new_unchecked(&mut buf);
        let header_len = ipv4_packet.header_len() as usize;
        let offset = ipv4_packet.frag_offset() as usize;
        let data = ipv4_packet.payload();
        let frag = Fragment {
            key: FragKey::Ipv4(Ipv4FragKey::of(&ipv4_packet)),
            offset,
            data,
            // The last fragment tells the size of the whole datagram.
            total_size: (!ipv4_packet.more_frags()).then_some(offset + data.len()),
            // The reassembled packet gets an IP header in front.
            max_size: self.inner.buf_capacity - header_len,
            restart_on_overlap: false,
        };
        let mut payload =
            self.fragments
                .assembler
                .add(&self.inner.buffers, frag, now, self.fragments.reassembly_timeout)?;

        // The reassembled packet is this fragment's IP header, patched to
        // describe the whole datagram, in front of the reassembled payload.
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

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
    struct Key {
        id: usize,
    }

    const TIMEOUT: Duration = Duration::from_secs(60);

    /// A fragment of datagram `id`, merged over what was there on overlap.
    fn frag(id: usize, offset: usize, data: &[u8], total_size: Option<usize>) -> Fragment<'_, Key> {
        Fragment {
            key: Key { id },
            offset,
            data,
            total_size,
            max_size: crate::buffers::TEST_POOL_SIZE,
            restart_on_overlap: false,
        }
    }

    fn add(set: &mut PacketAssemblerSet<Key>, now: Instant, frag: Fragment<Key>) -> Option<std::vec::Vec<u8>> {
        set.add(crate::buffers::test_buffers(), frag, now, TIMEOUT)
            .map(|buf| buf.to_vec())
    }

    #[test]
    fn packet_assembler_overlap() {
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, b"Rust", Some(5))), None);
        assert_eq!(
            add(&mut set, Instant::ZERO, frag(0, 1, b"Rust", Some(5))).as_deref(),
            Some(&b"RRust"[..])
        );
    }

    #[test]
    fn packet_assembler_assemble() {
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, b"Hello ", None)), None);
        assert_eq!(
            add(&mut set, Instant::ZERO, frag(0, 6, b"World!", Some(12))).as_deref(),
            Some(&b"Hello World!"[..])
        );
    }

    #[test]
    fn packet_assembler_out_of_order_assemble() {
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 6, b"World!", Some(12))), None);
        assert_eq!(
            add(&mut set, Instant::ZERO, frag(0, 0, b"Hello ", None)).as_deref(),
            Some(&b"Hello World!"[..])
        );
    }

    /// The fragments of a datagram larger than a packet buffer are dropped
    /// without taking a slot, and free the one the datagram had.
    #[test]
    fn packet_assembler_too_large() {
        let size = crate::buffers::TEST_POOL_SIZE;
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, &[0; 8], Some(size + 1))), None);
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, size - 7, &[0; 8], None)), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, &[0; 8], None)), None);
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 16, &[0; 8], Some(size + 1))), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
        assert_eq!(
            add(&mut set, Instant::ZERO, frag(1, 0, &[1; 8], Some(8))).as_deref(),
            Some(&[1; 8][..])
        );
    }

    /// A fragment that makes its datagram impossible to complete frees the slot.
    #[test]
    fn packet_assembler_error_frees_slot() {
        let mut set = PacketAssemblerSet::new();
        // Data past the total size, in either order.
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, b"ab", None)), None);
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 2, b"cdef", Some(4))), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
        assert_eq!(add(&mut set, Instant::ZERO, frag(1, 4, b"ef", None)), None);
        assert_eq!(add(&mut set, Instant::ZERO, frag(1, 0, b"ab", Some(2))), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
        // Two different total sizes.
        assert_eq!(add(&mut set, Instant::ZERO, frag(2, 0, b"ab", Some(4))), None);
        assert_eq!(add(&mut set, Instant::ZERO, frag(2, 2, b"cd", Some(6))), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
    }

    /// A late duplicate of a fragment of the datagram just completed doesn't
    /// start a reassembly that could never complete.
    #[test]
    fn packet_assembler_late_duplicate() {
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 0, b"ab", None)), None);
        assert!(add(&mut set, Instant::ZERO, frag(0, 2, b"cd", Some(4))).is_some());
        assert_eq!(add(&mut set, Instant::ZERO, frag(0, 2, b"cd", Some(4))), None);
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
    }

    /// With every slot taken, a new datagram takes the place of the one closest
    /// to expiring, once that one has had `REASSEMBLY_MIN_AGE`.
    #[test]
    fn packet_assembler_eviction() {
        let mut set = PacketAssemblerSet::new();
        for id in 0..REASSEMBLY_BUFFER_COUNT {
            assert_eq!(
                add(&mut set, Instant::from_millis(id as u32), frag(id, 0, b"ab", None)),
                None
            );
        }
        let new = REASSEMBLY_BUFFER_COUNT;
        assert_eq!(
            add(&mut set, Instant::from_millis(999), frag(new, 0, b"ab", Some(2))),
            None
        );
        assert!(set.assemblers.iter().all(|slot| slot.key != Some(Key { id: new })));
        assert_eq!(
            add(&mut set, Instant::from_millis(1000), frag(new, 0, b"ab", Some(2))).as_deref(),
            Some(&b"ab"[..])
        );
        // The oldest one was dropped, the others are still there.
        assert!(set.assemblers.iter().all(|slot| slot.key != Some(Key { id: 0 })));
        for id in (0..REASSEMBLY_BUFFER_COUNT).skip(1) {
            assert!(set.assemblers.iter().any(|slot| slot.key == Some(Key { id })));
        }
    }

    /// With `restart_on_overlap` (6LoWPAN), a fragment that overlaps the data so
    /// far, other than as a duplicate, starts the reassembly over.
    #[test]
    fn packet_assembler_restart_on_overlap() {
        let restart = |offset, data, total_size| Fragment {
            restart_on_overlap: true,
            ..frag(0, offset, data, total_size)
        };
        let mut set = PacketAssemblerSet::new();
        assert_eq!(add(&mut set, Instant::ZERO, restart(0, b"abcd", Some(8))), None);
        // A duplicate is dropped.
        assert_eq!(add(&mut set, Instant::ZERO, restart(2, b"XX", Some(8))), None);
        // One that overlaps differently discards "abcd".
        assert_eq!(add(&mut set, Instant::ZERO, restart(2, b"cdef", Some(8))), None);
        assert_eq!(add(&mut set, Instant::ZERO, restart(6, b"gh", Some(8))), None);
        assert_eq!(
            add(&mut set, Instant::ZERO, restart(0, b"AB", Some(8))).as_deref(),
            Some(&b"ABcdefgh"[..])
        );
    }

    #[test]
    fn packet_assembler_set_full() {
        let mut set = PacketAssemblerSet::new();
        for id in 0..REASSEMBLY_BUFFER_COUNT {
            assert_eq!(add(&mut set, Instant::ZERO, frag(id, 0, b"ab", None)), None);
        }
        let new = REASSEMBLY_BUFFER_COUNT;
        assert_eq!(add(&mut set, Instant::ZERO, frag(new, 0, b"ab", Some(2))), None);
        assert!(set.assemblers.iter().all(|slot| slot.key != Some(Key { id: new })));
    }

    #[test]
    fn packet_assembler_set_expiry() {
        let mut set = PacketAssemblerSet::new();
        assert_eq!(
            set.add(
                crate::buffers::test_buffers(),
                frag(0, 0, b"ab", None),
                Instant::ZERO,
                Duration::from_secs(10)
            )
            .map(|buf| buf.len()),
            None
        );
        let mut clock = Clock::new(Instant::from_secs(9));
        set.remove_expired(&mut clock);
        assert_eq!(clock.next(), Instant::from_secs(10));

        // Polling at the deadline removes it.
        let mut clock = Clock::new(Instant::from_secs(10));
        set.remove_expired(&mut clock);
        assert_eq!(clock.next(), idle_deadline(clock.now()));
        assert!(set.assemblers.iter().all(|slot| slot.is_free()));
    }
}
