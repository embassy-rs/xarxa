// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP, and RFC 4861 § 7.2 and § 7.3.

use crate::error::Full;
use crate::storage::BoundedVec;

use crate::driver::PacketBuf;
use crate::error::NotUnicast;
use crate::iface::IfaceHandle;
use crate::time::{Clock, Duration, Instant};
use crate::wire::{HardwareAddress, IpAddr};

/// Key identifying a neighbor: the interface it is reachable through, plus its
/// protocol address.
pub(crate) type Key = (IfaceHandle, IpAddr);

// Maximum number of entries in the neighbor cache, and maximum number of packets
// waiting for neighbor resolution (when full, the oldest packet is dropped to
// make room). Both are compile-time knobs.
pub(crate) use crate::config::{NEIGHBOR_CACHE_COUNT, PENDING_QUEUE_COUNT};

/// Maximum number of solicitations sent for one resolution before giving up.
/// (RFC 4861 MAX_MULTICAST_SOLICIT)
pub(crate) const MAX_MULTICAST_SOLICIT: u8 = 3;

/// Delay between solicitation retransmissions. (RFC 4861 RETRANS_TIMER)
pub(crate) const RETRANS_TIMER: Duration = Duration::from_millis(1_000);

/// State of a neighbor cache entry, in the style of RFC 4861 § 7.3.2.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
enum State {
    /// Address resolution started, and the first solicitation went out, since the
    /// last poll. The poll sets the retransmission timer.
    Started,
    /// Address resolution is in progress: solicitations are being sent, no answer
    /// yet. Egress packets for this neighbor are queued in the [PendingQueue]
    /// meanwhile.
    Incomplete {
        /// Number of solicitations sent so far.
        probes_sent: u8,
        /// When to send the next solicitation.
        retrans_at: Instant,
    },
    /// The neighbor's hardware address is known.
    Reachable {
        hardware_addr: HardwareAddress,
        /// The timestamp past which the mapping should be discarded.
        expires_at: Instant,
    },
    /// The mapping expired. Unlike RFC 4861's STALE, it isn't used to send: the
    /// next packet for the neighbor resolves it again, which stands in for the
    /// DELAY and PROBE states. Traffic from the neighbor, with the same hardware
    /// address, makes it reachable again without that.
    Stale { hardware_addr: HardwareAddress },
}

impl From<State> for NeighborState {
    fn from(state: State) -> Self {
        match state {
            State::Incomplete { .. } | State::Started => NeighborState::Incomplete,
            State::Reachable {
                hardware_addr,
                expires_at,
            } => NeighborState::Reachable {
                hardware_addr,
                expires_at,
            },
            State::Stale { hardware_addr } => NeighborState::Stale { hardware_addr },
        }
    }
}

/// An answer to a neighbor cache lookup.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(HardwareAddress),
    /// Resolution of this neighbor is already in progress.
    Pending,
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
}

#[cfg(all(test, feature = "ipv6"))]
impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        matches!(self, Answer::Found(_))
    }
}

/// A due resolution timer, returned by [NeighborCache::poll_retransmit].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeEvent {
    /// Another solicitation should be sent to the neighbor.
    Retransmit(IpAddr),
    /// Resolution failed after the maximum number of solicitations. The entry has
    /// been removed; packets queued on it should be dropped.
    Failed(IpAddr),
}

/// An entry in the [`NeighborCache`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbor {
    /// Interface the neighbor is reachable through.
    pub iface: IfaceHandle,
    /// The neighbor's IP address.
    pub addr: IpAddr,
    /// Whether the hardware address is known yet.
    pub state: NeighborState,
}

/// State of a [`Neighbor`] entry.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    /// Address resolution is in progress. Packets for this neighbor are parked
    /// until it resolves or resolution gives up.
    Incomplete,
    /// The neighbor's hardware address is known.
    Reachable {
        /// The neighbor's hardware address.
        hardware_addr: HardwareAddress,
        /// When the entry expires.
        expires_at: Instant,
    },
    /// The entry expired. The stack no longer sends to this hardware address.
    /// The next packet for the neighbor resolves it again.
    ///
    /// Traffic from the neighbor with the same hardware address makes the entry
    /// reachable again.
    Stale {
        /// The neighbor's hardware address, when it was last known.
        hardware_addr: HardwareAddress,
    },
}

/// The neighbor cache: the stack's map of IP addresses to hardware addresses.
///
/// It holds one entry per neighbor, keyed by the interface it is reachable
/// through plus its IP address. Entries are filled in by ARP and neighbor
/// discovery, and expire after 60 s unless traffic from the neighbor refreshes
/// them.
///
/// Access it with [`Stack::neighbor_cache`] and [`Stack::neighbor_cache_mut`].
///
/// [`Stack::neighbor_cache`]: crate::Stack::neighbor_cache
/// [`Stack::neighbor_cache_mut`]: crate::Stack::neighbor_cache_mut
#[derive(Debug)]
pub struct NeighborCache {
    storage: BoundedVec<(Key, State), NEIGHBOR_CACHE_COUNT>,
}

impl NeighborCache {
    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub(crate) fn new() -> Self {
        Self {
            storage: BoundedVec::new(),
        }
    }

    /// Look up a neighbor.
    ///
    /// The time isn't looked at: [`expire`](Self::expire) runs at the start of
    /// every poll, and the expiries count toward the poll deadline.
    pub(crate) fn lookup(&self, key: &Key) -> Answer {
        assert!(key.1.is_unicast());

        match self.get_state(key) {
            Some(State::Reachable { hardware_addr, .. }) => Answer::Found(hardware_addr),
            Some(State::Incomplete { .. } | State::Started) => Answer::Pending,
            _ => Answer::NotFound,
        }
    }

    /// Whether the cache has an entry for a neighbor, in any state.
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    pub(crate) fn contains(&self, key: &Key) -> bool {
        self.storage.iter().any(|(probe, _)| probe == key)
    }

    /// Create an INCOMPLETE entry for a neighbor, starting address resolution.
    ///
    /// The caller sends the first solicitation itself. The end of the next poll
    /// (or the current one) sets the retransmission timer, which takes over from
    /// there (see [NeighborCache::poll_retransmit]).
    pub(crate) fn start_resolution(&mut self, key: Key) {
        debug_assert!(key.1.is_unicast());

        self.insert_state(key, State::Started);
    }

    /// Advance the retransmission timers of the neighbors being resolved on `iface`,
    /// one entry per call.
    ///
    /// `cursor` is the scan position. Start it at 0 and call in a loop until `None`
    /// is returned: each call resumes the scan where the previous one stopped, so
    /// the whole loop is one pass over the cache.
    ///
    /// An entry with probes left gets its probe counter bumped and its timer
    /// rearmed, and is returned as [ProbeEvent::Retransmit] so the caller sends
    /// another solicitation; an entry that exhausted its probes is removed and
    /// returned as [ProbeEvent::Failed] so the caller drops the packets queued on it.
    pub(crate) fn poll_retransmit(
        &mut self,
        iface: IfaceHandle,
        timestamp: Instant,
        cursor: &mut usize,
    ) -> Option<ProbeEvent> {
        while let Some((key, state)) = self.storage.get_mut(*cursor) {
            let addr = key.1;
            match state {
                State::Incomplete {
                    probes_sent,
                    retrans_at,
                } if key.0 == iface && timestamp >= *retrans_at => {
                    if *probes_sent >= MAX_MULTICAST_SOLICIT {
                        // The last entry moves into `cursor`; examine it next.
                        self.storage.swap_remove(*cursor);
                        return Some(ProbeEvent::Failed(addr));
                    }
                    *probes_sent += 1;
                    *retrans_at = timestamp + RETRANS_TIMER;
                    *cursor += 1;
                    return Some(ProbeEvent::Retransmit(addr));
                }
                _ => *cursor += 1,
            }
        }
        None
    }

    /// Make the entries that expired stale, set the retransmission timer of the
    /// resolutions started since the last call, and count every timer and expiry
    /// that hasn't passed toward the next deadline.
    ///
    /// The poll calls this at its start, before anything in it looks a neighbor
    /// up, and at its end, after everything that can start a resolution or fill
    /// an entry. Only the end call's deadline counts.
    pub(crate) fn expire(&mut self, clock: &mut Clock) {
        for (_, state) in self.storage.iter_mut() {
            match *state {
                State::Started => {
                    *state = State::Incomplete {
                        probes_sent: 1,
                        retrans_at: clock.after(RETRANS_TIMER),
                    }
                }
                // A due one is retransmitted per interface, after the start call.
                State::Incomplete { retrans_at, .. } => {
                    clock.expired(retrans_at);
                }
                State::Reachable {
                    hardware_addr,
                    expires_at,
                } => {
                    if clock.expired(expires_at) {
                        *state = State::Stale { hardware_addr };
                    }
                }
                State::Stale { .. } => {}
            }
        }
    }

    pub(crate) fn reset_expiry_if_existing(
        &mut self,
        key: Key,
        source_hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Some(state) = self.get_state_mut(&key)
            && let State::Reachable { hardware_addr, .. } | State::Stale { hardware_addr } = *state
            && source_hardware_addr == hardware_addr
        {
            *state = State::Reachable {
                hardware_addr,
                expires_at: timestamp + Self::ENTRY_LIFETIME,
            };
        }
    }

    pub(crate) fn fill(&mut self, key: Key, hardware_addr: HardwareAddress, timestamp: Instant) {
        debug_assert!(key.1.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(key, hardware_addr, expires_at);
    }

    pub(crate) fn fill_with_expiration(&mut self, key: Key, hardware_addr: HardwareAddress, expires_at: Instant) {
        debug_assert!(key.1.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        match self.get_state(&key) {
            Some(
                State::Reachable {
                    hardware_addr: old_hardware_addr,
                    ..
                }
                | State::Stale {
                    hardware_addr: old_hardware_addr,
                },
            ) if old_hardware_addr != hardware_addr => {
                trace!("replaced {} => {} (was {})", key.1, hardware_addr, old_hardware_addr);
            }
            Some(State::Reachable { .. } | State::Stale { .. }) => {}
            Some(State::Incomplete { .. } | State::Started) => {
                trace!("filled {} => {} (was incomplete)", key.1, hardware_addr);
            }
            None => {
                trace!("filled {} => {} (was empty)", key.1, hardware_addr);
            }
        }

        self.insert_state(
            key,
            State::Reachable {
                hardware_addr,
                expires_at,
            },
        );
    }

    /// Get the entry for a neighbor.
    ///
    /// An entry that expired is reported as [`NeighborState::Stale`] from the
    /// next poll on, until the stack reuses its slot. Before that poll it is
    /// still `Reachable`, with an `expires_at` that has passed.
    pub fn get(&self, iface: IfaceHandle, addr: IpAddr) -> Option<Neighbor> {
        let state = self.get_state(&(iface, addr))?;
        Some(Neighbor {
            iface,
            addr,
            state: state.into(),
        })
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = Neighbor> + '_ {
        self.storage.iter().map(|((iface, addr), state)| Neighbor {
            iface: *iface,
            addr: *addr,
            state: (*state).into(),
        })
    }

    /// Add or replace an entry, mapping `addr` on `iface` to `hardware_addr`.
    ///
    /// `expires_at` is when the entry stops being used. There are no static
    /// entries. To keep an entry, insert it again before it expires.
    ///
    /// The stack changes the entry too:
    /// - Traffic from the neighbor sets it to expire 60 s later.
    /// - ARP or neighbor discovery replaces it if the neighbor answers with a
    ///   different hardware address.
    ///
    /// If the cache is full, another entry is evicted to make room.
    ///
    /// # Errors
    /// - `NotUnicast`: if `addr` or `hardware_addr` is not unicast. The cache
    ///   is left unchanged.
    pub fn insert(
        &mut self,
        iface: IfaceHandle,
        addr: IpAddr,
        hardware_addr: HardwareAddress,
        expires_at: Instant,
    ) -> Result<(), NotUnicast> {
        if !addr.is_unicast() || !hardware_addr.is_unicast() {
            return Err(NotUnicast);
        }

        self.fill_with_expiration((iface, addr), hardware_addr, expires_at);
        Ok(())
    }

    /// Remove the entry for a neighbor, returning it if there was one.
    ///
    /// Removing an entry whose resolution is still in progress drops the packets
    /// parked on it at the next poll.
    pub fn remove(&mut self, iface: IfaceHandle, addr: IpAddr) -> Option<Neighbor> {
        let index = self.storage.iter().position(|(key, _)| *key == (iface, addr))?;
        let ((iface, addr), state) = self.storage.swap_remove(index);
        Some(Neighbor {
            iface,
            addr,
            state: state.into(),
        })
    }

    /// Keep only the entries for which `f` returns true.
    ///
    /// Same caveat as [`NeighborCache::remove`] for entries being resolved.
    pub fn retain(&mut self, mut f: impl FnMut(&Neighbor) -> bool) {
        self.storage.retain(|((iface, addr), state)| {
            f(&Neighbor {
                iface: *iface,
                addr: *addr,
                state: (*state).into(),
            })
        });
    }

    /// Remove all entries for one interface.
    ///
    /// Same caveat as [`NeighborCache::remove`] for entries being resolved.
    pub fn clear_iface(&mut self, iface: IfaceHandle) {
        self.storage.retain(|(key, _)| key.0 != iface);
    }

    /// Remove all entries.
    ///
    /// Same caveat as [`NeighborCache::remove`] for entries being resolved.
    pub fn clear(&mut self) {
        self.storage.clear()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    fn insert_state(&mut self, key: Key, state: State) {
        if let Some(entry) = self.get_state_mut(&key) {
            *entry = state;
        } else if let Err((key, state)) = self.storage.push((key, state)) {
            // The cache is full, and we need to evict an entry. Prefer evicting
            // stale entries, then resolved ones: evicting an in-progress resolution
            // would strand the packets queued on it.
            let mut index = 0;
            let mut best = (u8::MAX, Instant::ZERO);
            for (i, (_, state)) in self.storage.iter().enumerate() {
                let rank = match state {
                    State::Stale { .. } => (0u8, Instant::ZERO),
                    State::Reachable { expires_at, .. } => (1u8, *expires_at),
                    State::Incomplete { retrans_at, .. } => (2u8, *retrans_at),
                    State::Started => (3u8, Instant::ZERO),
                };
                if rank < best {
                    best = rank;
                    index = i;
                }
            }

            let (_old_key, _) = self.storage[index];
            trace!("neighbor cache full, evicted {}", _old_key.1);
            self.storage[index] = (key, state);
        }
    }

    fn get_state(&self, key: &Key) -> Option<State> {
        self.storage
            .iter()
            .find(|(probe, _)| probe == key)
            .map(|(_, state)| *state)
    }

    fn get_state_mut(&mut self, key: &Key) -> Option<&mut State> {
        self.storage
            .iter_mut()
            .find(|(probe, _)| probe == key)
            .map(|(_, state)| state)
    }
}

/// A packet waiting for neighbor resolution.
#[derive(Debug)]
pub(crate) struct PendingPacket {
    pub key: Key,
    pub buf: PacketBuf,
}

/// A queue of egress packets waiting for neighbor resolution.
///
/// When egress needs a neighbor that is not in the [NeighborCache], the fully-built IP packet
/// is queued here and a solicitation (ARP request / NDISC neighbor solicit) is sent
/// instead, retransmitted per RFC 4861 until an answer arrives or the probe limit is
/// reached. When the answer arrives and fills the cache, the queued packets are
/// flushed to the device; if resolution fails, they are dropped.
#[derive(Debug, Default)]
pub(crate) struct PendingQueue {
    packets: BoundedVec<PendingPacket, PENDING_QUEUE_COUNT>,
}

impl PendingQueue {
    pub fn new() -> Self {
        Self {
            packets: BoundedVec::new(),
        }
    }

    /// Queue a packet waiting for `key` to resolve.
    pub fn push(&mut self, key: Key, buf: PacketBuf) {
        let packet = PendingPacket { key, buf };
        if let Err(packet) = self.packets.push(packet) {
            trace!("neighbor: pending queue full, dropping oldest packet");
            self.packets.remove(0);
            unwrap!(self.packets.push(packet).map_err(|_| Full));
        }
    }

    /// Whether any packet is waiting for `key`.
    pub fn has_matching(&self, key: &Key) -> bool {
        self.packets.iter().any(|packet| packet.key == *key)
    }

    /// The index and key of the first packet at or after `cursor` that is parked
    /// on `iface`, or `None` once there is none. This is how a caller walks the
    /// queue while removing packets from it.
    pub fn next_on(&self, iface: IfaceHandle, cursor: usize) -> Option<(usize, Key)> {
        self.packets
            .iter()
            .enumerate()
            .skip(cursor)
            .find(|(_, packet)| packet.key.0 == iface)
            .map(|(index, packet)| (index, packet.key))
    }

    /// Remove and return the first packet waiting for `key` (FIFO order).
    pub fn pop_matching(&mut self, key: &Key) -> Option<PendingPacket> {
        let index = self.packets.iter().position(|packet| packet.key == *key)?;
        Some(self.packets.remove(index))
    }

    /// Drop the packets whose resolution is gone: the entry was removed or
    /// evicted, or it resolved and went stale before the device took them.
    ///
    /// Otherwise a packet leaves the queue when its resolution succeeds or fails
    /// (RFC 4861 §7.2.2), so it needs no timer of its own.
    pub fn purge_orphans(&mut self, cache: &NeighborCache) {
        self.packets.retain(|packet| {
            let keep = matches!(
                cache.get_state(&packet.key),
                Some(State::Started | State::Incomplete { .. } | State::Reachable { .. })
            );
            if !keep {
                trace!(
                    "neighbor: dropping queued packet for {}, its resolution is gone",
                    packet.key.1
                );
            }
            keep
        });
    }

    /// Drop all packets queued on the given interface.
    pub fn purge_iface(&mut self, iface: IfaceHandle) {
        self.packets.retain(|packet| packet.key.0 != iface);
    }
}

#[cfg(all(test, feature = "ipv6"))]
mod test {
    use super::*;
    use crate::iface::IfaceHandle;
    use crate::time::{MAX_POLL_DELAY, idle_deadline};
    use crate::wire::Ipv6Addr;
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};
    #[allow(unused_imports)]
    use std::vec::Vec;

    const IF_0: IfaceHandle = IfaceHandle::new(0);
    const IF_1: IfaceHandle = IfaceHandle::new(1);

    fn take_matching(queue: &mut PendingQueue, key: &Key) -> std::vec::Vec<PendingPacket> {
        let mut taken = std::vec::Vec::new();
        while let Some(packet) = queue.pop_matching(key) {
            taken.push(packet);
        }
        taken
    }

    #[cfg(feature = "medium-ethernet")]
    const fn haddr(n: u8) -> HardwareAddress {
        HardwareAddress::Ethernet(crate::wire::EthernetAddress([0, 0, 0, 0, 0, n]))
    }
    #[cfg(not(feature = "medium-ethernet"))]
    const fn haddr(n: u8) -> HardwareAddress {
        HardwareAddress::Ieee802154(crate::wire::Ieee802154Address::Extended([0, 0, 0, 0, 0, 0, 0, n]))
    }

    /// An 802.15.4 address is cached like an Ethernet one.
    #[test]
    #[cfg(feature = "medium-ieee802154")]
    fn fill_ieee802154() {
        let addr = HardwareAddress::Ieee802154(crate::wire::Ieee802154Address::Extended([
            0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        ]));
        let mut cache = NeighborCache::new();
        cache.fill(key(MOCK_IP_ADDR_1), addr, Instant::from_millis(0));
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(addr)
        );
    }

    /// `insert` refuses addresses that are not unicast, on either side of the
    /// mapping, and leaves the cache alone.
    #[test]
    fn insert_rejects_non_unicast() {
        let mut cache = NeighborCache::new();
        let expires_at = Instant::from_secs(60);
        let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            cache.insert(IF_0, all_nodes.into(), HADDR_A, expires_at),
            Err(NotUnicast)
        );
        assert_eq!(
            cache.insert(IF_0, Ipv6Addr::UNSPECIFIED.into(), HADDR_A, expires_at),
            Err(NotUnicast)
        );
        #[cfg(feature = "medium-ethernet")]
        assert_eq!(
            cache.insert(
                IF_0,
                MOCK_IP_ADDR_1.into(),
                HardwareAddress::Ethernet(crate::wire::EthernetAddress::BROADCAST),
                expires_at
            ),
            Err(NotUnicast)
        );
        assert!(cache.is_empty());

        cache.insert(IF_0, MOCK_IP_ADDR_1.into(), HADDR_A, expires_at).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
    }

    const HADDR_A: HardwareAddress = haddr(1);
    const HADDR_B: HardwareAddress = haddr(2);
    const HADDR_C: HardwareAddress = haddr(3);
    const HADDR_D: HardwareAddress = haddr(4);

    fn key(addr: Ipv6Addr) -> Key {
        (IF_0, addr.into())
    }

    #[test]
    fn test_fill() {
        let mut cache = NeighborCache::new();

        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)).found());
        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_2), Instant::from_millis(0)).found());

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_2), Instant::from_millis(0)).found());
    }

    #[test]
    fn test_expire() {
        let mut cache = NeighborCache::new();

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        let later = Instant::from_millis(0) + NeighborCache::ENTRY_LIFETIME * 2;
        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), later).found());
    }

    #[test]
    fn test_replace() {
        let mut cache = NeighborCache::new();

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_per_iface() {
        let mut cache = NeighborCache::new();

        // The same protocol address resolves independently on different interfaces.
        cache.fill((IF_0, MOCK_IP_ADDR_1.into()), HADDR_A, Instant::ZERO);
        cache.fill((IF_1, MOCK_IP_ADDR_1.into()), HADDR_B, Instant::ZERO);
        assert_eq!(cache.lookup(&(IF_0, MOCK_IP_ADDR_1.into())), Answer::Found(HADDR_A));
        assert_eq!(cache.lookup(&(IF_1, MOCK_IP_ADDR_1.into())), Answer::Found(HADDR_B));

        cache.clear_iface(IF_0);
        assert!(!cache.lookup(&(IF_0, MOCK_IP_ADDR_1.into())).found());
        assert_eq!(cache.lookup(&(IF_1, MOCK_IP_ADDR_1.into())), Answer::Found(HADDR_B));
    }

    #[test]
    fn test_flush() {
        let mut cache = NeighborCache::new();

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::ZERO);
        cache.fill((IF_1, MOCK_IP_ADDR_2.into()), HADDR_B, Instant::ZERO);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Found(HADDR_A));
        assert_eq!(cache.lookup(&(IF_1, MOCK_IP_ADDR_2.into())), Answer::Found(HADDR_B));
        assert_eq!(cache.len(), 2);

        // Clearing removes every entry, on every interface.
        cache.clear();
        assert!(!cache.lookup(&key(MOCK_IP_ADDR_1)).found());
        assert!(!cache.lookup(&(IF_1, MOCK_IP_ADDR_2.into())).found());
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_evict() {
        let mut cache = NeighborCache::new();

        // Fill the cache to capacity, with the entry for MOCK_IP_ADDR_2 being the
        // one that expires soonest.
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::from_millis(100));
        cache.fill(key(MOCK_IP_ADDR_2), HADDR_B, Instant::from_millis(50));
        for i in 0..(NEIGHBOR_CACHE_COUNT - 2) {
            let mut addr = MOCK_IP_ADDR_3.octets();
            addr[14] = 1;
            addr[15] = i as u8;
            cache.fill(key(Ipv6Addr::from(addr)), HADDR_C, Instant::from_millis(200));
        }
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_2), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_4), Instant::from_millis(1000)).found());

        cache.fill(key(MOCK_IP_ADDR_4), HADDR_D, Instant::from_millis(300));
        assert!(!lookup_at(&mut cache, &key(MOCK_IP_ADDR_2), Instant::from_millis(1000)).found());
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_4), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_resolution_failure() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1));
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Pending);

        // First probe was sent at t0; nothing to do before the retransmission timer.
        assert_eq!(cache.poll_retransmit(IF_0, t0, &mut 0), None);
        assert_eq!(next_deadline(&mut cache, t0), t0 + RETRANS_TIMER);

        // Second and third probes.
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER * 2, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );

        // Probe limit reached: resolution fails, the entry is removed.
        assert_eq!(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER * 3, &mut 0),
            Some(ProbeEvent::Failed(MOCK_IP_ADDR_1.into()))
        );
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::NotFound);
        let t3 = t0 + RETRANS_TIMER * 3;
        assert_eq!(next_deadline(&mut cache, t3), idle_deadline(t3));
    }

    #[test]
    fn test_resolution_success() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1));
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Pending);

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, t0);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Found(HADDR_A));

        // The resolved entry has no retransmission timer anymore, only its expiry.
        let t1 = t0 + RETRANS_TIMER;
        assert_eq!(cache.poll_retransmit(IF_0, t1, &mut 0), None);
        assert_eq!(next_deadline(&mut cache, t1), t0 + NeighborCache::ENTRY_LIFETIME);
    }

    /// A poll makes an expired entry stale. It isn't used to send, however long
    /// ago it expired, and traffic from the neighbor makes it reachable again.
    #[test]
    fn test_expired_entry_goes_stale() {
        let mut cache = NeighborCache::new();
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::ZERO);
        let entry = |cache: &NeighborCache| cache.get(IF_0, MOCK_IP_ADDR_1.into()).unwrap().state;

        let expired = Instant::ZERO + NeighborCache::ENTRY_LIFETIME;
        assert_eq!(lookup_at(&mut cache, &key(MOCK_IP_ADDR_1), expired), Answer::NotFound);
        next_deadline(&mut cache, expired);
        assert_eq!(entry(&cache), NeighborState::Stale { hardware_addr: HADDR_A });

        // Polled once a day for 100 days, twice around the clock.
        let mut now = expired;
        for _ in 0..100 {
            now += MAX_POLL_DELAY;
            next_deadline(&mut cache, now);
            assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::NotFound);
        }
        assert_eq!(entry(&cache), NeighborState::Stale { hardware_addr: HADDR_A });

        // Traffic from another hardware address leaves it stale, traffic from
        // the same one makes it reachable.
        cache.reset_expiry_if_existing(key(MOCK_IP_ADDR_1), HADDR_B, now);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::NotFound);
        cache.reset_expiry_if_existing(key(MOCK_IP_ADDR_1), HADDR_A, now);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Found(HADDR_A));
        assert_eq!(
            entry(&cache),
            NeighborState::Reachable {
                hardware_addr: HADDR_A,
                expires_at: now + NeighborCache::ENTRY_LIFETIME
            }
        );
    }

    /// A full cache evicts a stale entry before any other.
    #[test]
    fn test_evict_stale_first() {
        let mut cache = NeighborCache::new();
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, Instant::ZERO);
        let later = Instant::ZERO + NeighborCache::ENTRY_LIFETIME;
        next_deadline(&mut cache, later);
        // The others are all reachable.
        cache.fill(key(MOCK_IP_ADDR_2), HADDR_B, later);
        for i in 0..(NEIGHBOR_CACHE_COUNT - 2) {
            let mut addr = MOCK_IP_ADDR_3.octets();
            addr[14] = 1;
            addr[15] = i as u8;
            cache.fill(key(Ipv6Addr::from(addr)), HADDR_C, later);
        }

        cache.fill(key(MOCK_IP_ADDR_4), HADDR_D, later);
        assert!(cache.get(IF_0, MOCK_IP_ADDR_1.into()).is_none());
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_2), later),
            Answer::Found(HADDR_B)
        );
        assert_eq!(
            lookup_at(&mut cache, &key(MOCK_IP_ADDR_4), later),
            Answer::Found(HADDR_D)
        );
    }

    /// What a poll at `now` does to the cache, and the deadline it counts.
    fn next_deadline(cache: &mut NeighborCache, now: Instant) -> Instant {
        let mut clock = Clock::new(now);
        cache.expire(&mut clock);
        clock.next()
    }

    /// Look up a neighbor after a poll at `at`.
    fn lookup_at(cache: &mut NeighborCache, key: &Key, at: Instant) -> Answer {
        cache.expire(&mut Clock::new(at));
        cache.lookup(key)
    }

    #[test]
    fn test_retransmit_other_iface() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution((IF_1, MOCK_IP_ADDR_1.into()));
        next_deadline(&mut cache, t0);
        // Polling one interface's timers doesn't touch another's entries.
        assert_eq!(cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0), None);
        assert_eq!(
            cache.poll_retransmit(IF_1, t0 + RETRANS_TIMER, &mut 0),
            Some(ProbeEvent::Retransmit(MOCK_IP_ADDR_1.into()))
        );
    }

    #[test]
    fn test_pending_queue() {
        let mut queue = PendingQueue::new();

        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::try_new().unwrap());
        queue.push(key(MOCK_IP_ADDR_2), PacketBuf::try_new().unwrap());
        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::try_new().unwrap());
        // Same address, different interface: distinct key.
        queue.push((IF_1, MOCK_IP_ADDR_1.into()), PacketBuf::try_new().unwrap());

        let taken = take_matching(&mut queue, &key(MOCK_IP_ADDR_1));
        assert_eq!(taken.len(), 2);
        assert!(take_matching(&mut queue, &key(MOCK_IP_ADDR_1)).is_empty());
        assert_eq!(take_matching(&mut queue, &key(MOCK_IP_ADDR_2)).len(), 1);
        assert_eq!(take_matching(&mut queue, &(IF_1, MOCK_IP_ADDR_1.into())).len(), 1);
    }

    #[test]
    fn test_pending_queue_full() {
        let mut queue = PendingQueue::new();

        for _ in 0..PENDING_QUEUE_COUNT {
            queue.push(key(MOCK_IP_ADDR_1), PacketBuf::try_new().unwrap());
        }
        // This push drops the oldest packet to make room.
        queue.push(key(MOCK_IP_ADDR_2), PacketBuf::try_new().unwrap());

        assert_eq!(
            take_matching(&mut queue, &key(MOCK_IP_ADDR_1)).len(),
            PENDING_QUEUE_COUNT - 1
        );
        assert_eq!(take_matching(&mut queue, &key(MOCK_IP_ADDR_2)).len(), 1);
    }

    /// A parked packet stays while its resolution is in progress or resolved, and
    /// goes once its entry is gone.
    #[test]
    fn test_pending_queue_orphans() {
        let mut queue = PendingQueue::new();
        let mut cache = NeighborCache::new();
        cache.start_resolution(key(MOCK_IP_ADDR_1));

        queue.push(key(MOCK_IP_ADDR_1), PacketBuf::try_new().unwrap());
        queue.push(key(MOCK_IP_ADDR_2), PacketBuf::try_new().unwrap());
        queue.purge_orphans(&cache);
        assert!(take_matching(&mut queue, &key(MOCK_IP_ADDR_2)).is_empty());

        cache.remove(IF_0, MOCK_IP_ADDR_1.into());
        queue.purge_orphans(&cache);
        assert!(take_matching(&mut queue, &key(MOCK_IP_ADDR_1)).is_empty());
    }

    #[test]
    fn test_pending_queue_purge_iface() {
        let mut queue = PendingQueue::new();

        queue.push((IF_0, MOCK_IP_ADDR_1.into()), PacketBuf::try_new().unwrap());
        queue.push((IF_1, MOCK_IP_ADDR_1.into()), PacketBuf::try_new().unwrap());

        queue.purge_iface(IF_0);
        assert!(take_matching(&mut queue, &(IF_0, MOCK_IP_ADDR_1.into())).is_empty());
        assert_eq!(take_matching(&mut queue, &(IF_1, MOCK_IP_ADDR_1.into())).len(), 1);
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NeighborCache {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "NeighborCache({=[?]})", self.storage.as_slice());
    }
}
