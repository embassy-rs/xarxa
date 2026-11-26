// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP, and RFC 4861 § 7.2 and § 7.3.

use crate::storage::BoundedVec;

use crate::buffers::Buf;
use crate::error::NotUnicast;
use crate::iface::IfaceHandle;
use crate::stack::POOL_RETRY_DELAY;
use crate::time::{Clock, Duration, Instant};
use crate::wire::{HardwareAddress, IpAddr};

/// Key identifying a neighbor: the interface it is reachable through, plus its
/// protocol address.
pub(crate) type Key = (IfaceHandle, IpAddr);

// Maximum number of entries in the neighbor cache. A compile-time knob.
pub(crate) use crate::config::NEIGHBOR_CACHE_COUNT;

/// Maximum number of solicitations sent for one resolution before giving up.
/// (RFC 4861 MAX_MULTICAST_SOLICIT)
pub(crate) const MAX_MULTICAST_SOLICIT: u8 = 3;

/// Delay between solicitation retransmissions. (RFC 4861 RETRANS_TIMER)
pub(crate) const RETRANS_TIMER: Duration = Duration::from_millis(1_000);

/// State of a neighbor cache entry, in the style of RFC 4861 § 7.3.2.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
enum State {
    /// Address resolution started since the last poll. The poll sets the
    /// retransmission timer.
    Started {
        /// Whether the first solicitation went out. If not, the poll retries it
        /// soon.
        sent: bool,
    },
    /// Address resolution is in progress: solicitations are being sent, no answer
    /// yet. The entry holds one egress packet for this neighbor meanwhile.
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
            State::Incomplete { .. } | State::Started { .. } => NeighborState::Incomplete,
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
#[derive(Debug)]
pub(crate) enum ProbeEvent {
    /// Another solicitation should be sent to the neighbor.
    Retransmit(IpAddr),
    /// Resolution failed after the maximum number of solicitations. The entry has
    /// been removed, and this is the packet that was parked on it, if any.
    Failed(IpAddr, Option<Buf>),
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
    /// Address resolution is in progress. A packet for this neighbor is parked
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
/// An entry also holds the packet parked on the neighbor while it is resolved:
/// one per neighbor, so a neighbor that never answers holds back only the
/// packets sent to it.
///
/// Access it with [`Stack::neighbor_cache`] and [`Stack::neighbor_cache_mut`].
///
/// [`Stack::neighbor_cache`]: crate::Stack::neighbor_cache
/// [`Stack::neighbor_cache_mut`]: crate::Stack::neighbor_cache_mut
#[derive(Debug)]
pub struct NeighborCache {
    storage: BoundedVec<Entry, NEIGHBOR_CACHE_COUNT>,
}

/// An entry of the [`NeighborCache`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
struct Entry {
    key: Key,
    state: State,
    /// The packet waiting for the neighbor. It was sent while the neighbor was
    /// being resolved, and stays after the resolution while the device has no
    /// room for it. It goes with the entry, and when the entry goes stale.
    parked: Option<Buf>,
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
            Some(State::Incomplete { .. } | State::Started { .. }) => Answer::Pending,
            _ => Answer::NotFound,
        }
    }

    /// Whether the cache has an entry for a neighbor, in any state.
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    pub(crate) fn contains(&self, key: &Key) -> bool {
        self.storage.iter().any(|entry| entry.key == *key)
    }

    /// Create an INCOMPLETE entry for a neighbor, starting address resolution.
    ///
    /// The caller sends the first solicitation itself, and says with `sent`
    /// whether it went out. The end of the next poll (or the current one) sets
    /// the retransmission timer, which takes over from there (see
    /// [NeighborCache::poll_retransmit]).
    pub(crate) fn start_resolution(&mut self, key: Key, sent: bool) {
        debug_assert!(key.1.is_unicast());

        self.insert_state(key, State::Started { sent });
    }

    /// Advance the retransmission timers of the neighbors being resolved on `iface`,
    /// one entry per call.
    ///
    /// `cursor` is the scan position. Start it at 0 and call in a loop until `None`
    /// is returned: each call resumes the scan where the previous one stopped, so
    /// the whole loop is one pass over the cache.
    ///
    /// An entry with probes left is returned as [ProbeEvent::Retransmit], so the
    /// caller sends another solicitation. Only [`probe_sent`](Self::probe_sent)
    /// counts it and rearms the timer, once it went out: a solicitation there
    /// was no buffer or no room in the device for is not one the neighbor failed
    /// to answer (RFC 4861 §7.2.2 counts the solicitations sent). An entry that
    /// exhausted its probes is removed and returned as [ProbeEvent::Failed], with
    /// the packet parked on it.
    pub(crate) fn poll_retransmit(
        &mut self,
        iface: IfaceHandle,
        timestamp: Instant,
        cursor: &mut usize,
    ) -> Option<ProbeEvent> {
        while let Some(entry) = self.storage.get_mut(*cursor) {
            let (entry_iface, addr) = entry.key;
            match entry.state {
                State::Incomplete {
                    probes_sent,
                    retrans_at,
                } if entry_iface == iface && timestamp >= retrans_at => {
                    if probes_sent >= MAX_MULTICAST_SOLICIT {
                        // The last entry moves into `cursor`; examine it next.
                        let entry = self.storage.swap_remove(*cursor);
                        return Some(ProbeEvent::Failed(addr, entry.parked));
                    }
                    *cursor += 1;
                    return Some(ProbeEvent::Retransmit(addr));
                }
                _ => *cursor += 1,
            }
        }
        None
    }

    /// Count a solicitation that went out for a neighbor being resolved, and time
    /// the next one.
    pub(crate) fn probe_sent(&mut self, key: &Key, timestamp: Instant) {
        if let Some(State::Incomplete {
            probes_sent,
            retrans_at,
        }) = self.get_state_mut(key)
        {
            *probes_sent += 1;
            *retrans_at = timestamp + RETRANS_TIMER;
        }
    }

    /// Make the entries that expired stale, set the retransmission timer of the
    /// resolutions started since the last call, and count every timer and expiry
    /// that hasn't passed toward the next deadline.
    ///
    /// The poll calls this at its start, before anything in it looks a neighbor
    /// up, and at its end, after everything that can start a resolution or fill
    /// an entry. Only the end call's deadline counts.
    pub(crate) fn expire(&mut self, clock: &mut Clock) {
        for entry in self.storage.iter_mut() {
            match entry.state {
                State::Started { sent } => {
                    // A first solicitation that didn't go out is tried again soon.
                    let delay = if sent { RETRANS_TIMER } else { POOL_RETRY_DELAY };
                    entry.state = State::Incomplete {
                        probes_sent: sent as u8,
                        retrans_at: clock.after(delay),
                    }
                }
                // A due one is retransmitted per interface, after the start call.
                // One whose solicitation couldn't go out stays due, and is tried
                // again by the poll that follows a freed buffer or room in the
                // device.
                State::Incomplete { retrans_at, .. } => {
                    clock.expired(retrans_at);
                }
                State::Reachable {
                    hardware_addr,
                    expires_at,
                } => {
                    if clock.expired(expires_at) {
                        entry.state = State::Stale { hardware_addr };
                        // The stack no longer sends to this hardware address.
                        if entry.parked.take().is_some() {
                            trace!(
                                "neighbor: dropping parked packet for {}, its entry went stale",
                                entry.key.1
                            );
                        }
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
            Some(State::Incomplete { .. } | State::Started { .. }) => {
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
        self.storage.iter().map(Entry::neighbor)
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
    /// Removing an entry drops the packet parked on it, if any.
    pub fn remove(&mut self, iface: IfaceHandle, addr: IpAddr) -> Option<Neighbor> {
        let index = self.storage.iter().position(|entry| entry.key == (iface, addr))?;
        Some(self.storage.swap_remove(index).neighbor())
    }

    /// Keep only the entries for which `f` returns true.
    ///
    /// Same caveat as [`NeighborCache::remove`] for parked packets.
    pub fn retain(&mut self, mut f: impl FnMut(&Neighbor) -> bool) {
        self.storage.retain(|entry| f(&entry.neighbor()));
    }

    /// Remove all entries for one interface.
    ///
    /// Same caveat as [`NeighborCache::remove`] for parked packets.
    pub fn clear_iface(&mut self, iface: IfaceHandle) {
        self.storage.retain(|entry| entry.key.0 != iface);
    }

    /// Remove all entries.
    ///
    /// Same caveat as [`NeighborCache::remove`] for parked packets.
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

    /// Set the state of a neighbor's entry, creating it if there is none. An
    /// existing entry keeps its parked packet.
    fn insert_state(&mut self, key: Key, state: State) {
        if let Some(entry) = self.get_state_mut(&key) {
            *entry = state;
            return;
        }
        let entry = Entry {
            key,
            state,
            parked: None,
        };
        if let Err(entry) = self.storage.push(entry) {
            // The cache is full, and we need to evict an entry. Prefer evicting
            // stale entries, then resolved ones: evicting an in-progress resolution
            // drops the packet parked on it.
            let mut index = 0;
            let mut best = (u8::MAX, Instant::ZERO);
            for (i, probe) in self.storage.iter().enumerate() {
                let rank = match probe.state {
                    State::Stale { .. } => (0u8, Instant::ZERO),
                    State::Reachable { expires_at, .. } => (1u8, expires_at),
                    State::Incomplete { retrans_at, .. } => (2u8, retrans_at),
                    State::Started { .. } => (3u8, Instant::ZERO),
                };
                if rank < best {
                    best = rank;
                    index = i;
                }
            }

            trace!("neighbor cache full, evicted {}", self.storage[index].key.1);
            self.storage[index] = entry;
        }
    }

    /// Park a packet on a neighbor that is being resolved. It holds one: if it
    /// already holds one, or isn't being resolved, the packet is handed back.
    pub(crate) fn park(&mut self, key: &Key, buf: Buf) -> Result<(), Buf> {
        match self.get_mut(key) {
            Some(Entry {
                state: State::Started { .. } | State::Incomplete { .. },
                parked: parked @ None,
                ..
            }) => {
                *parked = Some(buf);
                Ok(())
            }
            _ => Err(buf),
        }
    }

    /// Whether a packet is parked on a neighbor.
    pub(crate) fn has_parked(&self, key: &Key) -> bool {
        self.storage
            .iter()
            .any(|entry| entry.key == *key && entry.parked.is_some())
    }

    /// The index of the first entry at or after `cursor` on `iface` whose
    /// neighbor is resolved and that holds a parked packet, for
    /// [`take_parked_at`](Self::take_parked_at).
    pub(crate) fn next_resolved_parked(&self, iface: IfaceHandle, cursor: usize) -> Option<usize> {
        self.storage
            .iter()
            .enumerate()
            .skip(cursor)
            .find(|(_, entry)| {
                entry.key.0 == iface && entry.parked.is_some() && matches!(entry.state, State::Reachable { .. })
            })
            .map(|(index, _)| index)
    }

    /// Take the packet parked on the resolved neighbor at `index`, from
    /// [`next_resolved_parked`](Self::next_resolved_parked), with the
    /// neighbor's address and hardware address.
    pub(crate) fn take_parked_at(&mut self, index: usize) -> (IpAddr, HardwareAddress, Buf) {
        let entry = &mut self.storage[index];
        let State::Reachable { hardware_addr, .. } = entry.state else {
            unreachable!()
        };
        (entry.key.1, hardware_addr, unwrap!(entry.parked.take()))
    }

    /// Take the packet parked on a neighbor, if any.
    pub(crate) fn take_parked(&mut self, key: &Key) -> Option<Buf> {
        self.get_mut(key)?.parked.take()
    }

    fn get_state(&self, key: &Key) -> Option<State> {
        self.storage
            .iter()
            .find(|entry| entry.key == *key)
            .map(|entry| entry.state)
    }

    fn get_state_mut(&mut self, key: &Key) -> Option<&mut State> {
        self.get_mut(key).map(|entry| &mut entry.state)
    }

    fn get_mut(&mut self, key: &Key) -> Option<&mut Entry> {
        self.storage.iter_mut().find(|entry| entry.key == *key)
    }
}

impl Entry {
    fn neighbor(&self) -> Neighbor {
        Neighbor {
            iface: self.key.0,
            addr: self.key.1,
            state: self.state.into(),
        }
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

    fn buf() -> Buf {
        crate::buffers::test_kept_buf()
    }

    fn is_retransmit(event: Option<ProbeEvent>, addr: Ipv6Addr) -> bool {
        matches!(event, Some(ProbeEvent::Retransmit(a)) if a == addr.into())
    }

    /// Whether the event is a failed resolution of `addr`, and whether a packet
    /// was parked on it.
    fn is_failed(event: Option<ProbeEvent>, addr: Ipv6Addr, parked: bool) -> bool {
        matches!(event, Some(ProbeEvent::Failed(a, p)) if a == addr.into() && p.is_some() == parked)
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

        cache.start_resolution(key(MOCK_IP_ADDR_1), true);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Pending);

        // First probe was sent at t0; nothing to do before the retransmission timer.
        assert!(cache.poll_retransmit(IF_0, t0, &mut 0).is_none());
        assert_eq!(next_deadline(&mut cache, t0), t0 + RETRANS_TIMER);

        // Second and third probes.
        let t1 = t0 + RETRANS_TIMER;
        assert!(is_retransmit(cache.poll_retransmit(IF_0, t1, &mut 0), MOCK_IP_ADDR_1));
        cache.probe_sent(&key(MOCK_IP_ADDR_1), t1);
        let t2 = t0 + RETRANS_TIMER * 2;
        assert!(is_retransmit(cache.poll_retransmit(IF_0, t2, &mut 0), MOCK_IP_ADDR_1));
        cache.probe_sent(&key(MOCK_IP_ADDR_1), t2);

        // Probe limit reached: resolution fails, the entry is removed.
        assert!(is_failed(
            cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER * 3, &mut 0),
            MOCK_IP_ADDR_1,
            false
        ));
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::NotFound);
        let t3 = t0 + RETRANS_TIMER * 3;
        assert_eq!(next_deadline(&mut cache, t3), idle_deadline(t3));
    }

    /// Only the solicitations that went out count toward giving up. One that
    /// didn't stays due, and the resolution doesn't fail for it.
    #[test]
    fn test_unsent_probes_dont_count() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        // The first solicitation didn't go out: it is tried again soon.
        cache.start_resolution(key(MOCK_IP_ADDR_1), false);
        assert_eq!(next_deadline(&mut cache, t0), t0 + POOL_RETRY_DELAY);

        // It stays due for as long as it isn't sent, and holds no deadline.
        let mut now = t0 + POOL_RETRY_DELAY;
        for _ in 0..10 {
            assert!(is_retransmit(cache.poll_retransmit(IF_0, now, &mut 0), MOCK_IP_ADDR_1));
            assert_eq!(next_deadline(&mut cache, now), idle_deadline(now));
            now += RETRANS_TIMER;
        }

        // Three that go out, a second apart, and then it fails.
        for _ in 0..MAX_MULTICAST_SOLICIT {
            assert!(is_retransmit(cache.poll_retransmit(IF_0, now, &mut 0), MOCK_IP_ADDR_1));
            cache.probe_sent(&key(MOCK_IP_ADDR_1), now);
            assert!(cache.poll_retransmit(IF_0, now, &mut 0).is_none());
            assert_eq!(next_deadline(&mut cache, now), now + RETRANS_TIMER);
            now += RETRANS_TIMER;
        }
        assert!(is_failed(
            cache.poll_retransmit(IF_0, now, &mut 0),
            MOCK_IP_ADDR_1,
            false
        ));
    }

    #[test]
    fn test_resolution_success() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1), true);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Pending);

        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, t0);
        assert_eq!(cache.lookup(&key(MOCK_IP_ADDR_1)), Answer::Found(HADDR_A));

        // The resolved entry has no retransmission timer anymore, only its expiry.
        let t1 = t0 + RETRANS_TIMER;
        assert!(cache.poll_retransmit(IF_0, t1, &mut 0).is_none());
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

        cache.start_resolution((IF_1, MOCK_IP_ADDR_1.into()), true);
        next_deadline(&mut cache, t0);
        // Polling one interface's timers doesn't touch another's entries.
        assert!(cache.poll_retransmit(IF_0, t0 + RETRANS_TIMER, &mut 0).is_none());
        assert!(is_retransmit(
            cache.poll_retransmit(IF_1, t0 + RETRANS_TIMER, &mut 0),
            MOCK_IP_ADDR_1
        ));
    }

    /// A neighbor being resolved holds one parked packet. Another is handed
    /// back, and so is one for a neighbor that isn't being resolved.
    #[test]
    fn test_park() {
        let mut cache = NeighborCache::new();
        let k1 = key(MOCK_IP_ADDR_1);
        let k1_if1 = (IF_1, MOCK_IP_ADDR_1.into());
        cache.start_resolution(k1, true);
        cache.start_resolution(k1_if1, true);

        assert!(cache.park(&k1, buf()).is_ok());
        assert!(cache.park(&k1, buf()).is_err());
        assert!(cache.has_parked(&k1));
        // Same address, different interface: another neighbor, with its own slot.
        assert!(!cache.has_parked(&k1_if1));
        assert!(cache.park(&k1_if1, buf()).is_ok());
        // No entry, or one that isn't being resolved: nothing to wait for.
        assert!(cache.park(&key(MOCK_IP_ADDR_2), buf()).is_err());
        cache.fill(key(MOCK_IP_ADDR_2), HADDR_B, Instant::ZERO);
        assert!(cache.park(&key(MOCK_IP_ADDR_2), buf()).is_err());

        // Resolved, it can be taken from its index.
        assert_eq!(cache.next_resolved_parked(IF_0, 0), None);
        cache.fill(k1, HADDR_A, Instant::ZERO);
        let index = cache.next_resolved_parked(IF_0, 0).unwrap();
        assert_eq!(cache.next_resolved_parked(IF_1, 0), None);
        let (addr, hardware_addr, _) = cache.take_parked_at(index);
        assert_eq!((addr, hardware_addr), (MOCK_IP_ADDR_1.into(), HADDR_A));
        assert!(!cache.has_parked(&k1));
        assert_eq!(cache.next_resolved_parked(IF_0, 0), None);

        assert!(cache.take_parked(&k1_if1).is_some());
        assert!(cache.take_parked(&k1_if1).is_none());
    }

    /// A parked packet goes with its entry: removed, evicted, failed, or gone
    /// stale.
    #[test]
    fn test_parked_goes_with_entry() {
        let mut cache = NeighborCache::new();
        let t0 = Instant::ZERO;

        cache.start_resolution(key(MOCK_IP_ADDR_1), true);
        cache.park(&key(MOCK_IP_ADDR_1), buf()).unwrap();
        cache.remove(IF_0, MOCK_IP_ADDR_1.into());
        assert!(!cache.has_parked(&key(MOCK_IP_ADDR_1)));

        // A failed resolution hands it to the caller.
        cache.start_resolution(key(MOCK_IP_ADDR_1), true);
        cache.park(&key(MOCK_IP_ADDR_1), buf()).unwrap();
        next_deadline(&mut cache, t0);
        let mut now = t0;
        for _ in 1..MAX_MULTICAST_SOLICIT {
            now += RETRANS_TIMER;
            assert!(is_retransmit(cache.poll_retransmit(IF_0, now, &mut 0), MOCK_IP_ADDR_1));
            cache.probe_sent(&key(MOCK_IP_ADDR_1), now);
        }
        now += RETRANS_TIMER;
        assert!(is_failed(
            cache.poll_retransmit(IF_0, now, &mut 0),
            MOCK_IP_ADDR_1,
            true
        ));

        // Resolved, it waits for the device, until the entry goes stale.
        cache.start_resolution(key(MOCK_IP_ADDR_1), true);
        cache.park(&key(MOCK_IP_ADDR_1), buf()).unwrap();
        cache.fill(key(MOCK_IP_ADDR_1), HADDR_A, t0);
        assert!(cache.has_parked(&key(MOCK_IP_ADDR_1)));
        next_deadline(&mut cache, t0 + NeighborCache::ENTRY_LIFETIME);
        assert!(!cache.has_parked(&key(MOCK_IP_ADDR_1)));

        cache.start_resolution((IF_1, MOCK_IP_ADDR_1.into()), true);
        cache.park(&(IF_1, MOCK_IP_ADDR_1.into()), buf()).unwrap();
        cache.clear_iface(IF_1);
        assert!(!cache.has_parked(&(IF_1, MOCK_IP_ADDR_1.into())));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NeighborCache {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "NeighborCache({=[?]})", self.storage.as_slice());
    }
}
