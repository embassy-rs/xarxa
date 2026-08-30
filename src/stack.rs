//! The network stack.

use crate::config::IFACE_COUNT;
#[cfg(feature = "_raw")]
use crate::config::RAW_SOCKET_COUNT;
#[cfg(feature = "tcp-listener")]
use crate::config::TCP_LISTENER_COUNT;
#[cfg(feature = "tcp")]
use crate::config::TCP_SOCKET_COUNT;
#[cfg(feature = "udp")]
use crate::config::UDP_SOCKET_COUNT;
use crate::driver::{ChecksumCapabilities, Driver, PacketBuf};
#[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
use crate::fragmentation::Fragmenter;
#[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
use crate::icmp_error::{IcmpError, parse_quoted_packet};
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
use crate::iface::link_local_addr;
use crate::iface::{Iface, IfaceHandle, IfaceIter, IfaceState, Medium};
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
use crate::neighbor::{Answer as NeighborAnswer, Key as NeighborKey, NeighborCache, PendingQueue, ProbeEvent};
use crate::rand::Rand;
#[cfg(feature = "_raw")]
use crate::raw::{RawHandle, RawSocket, RawSocketIter, RawSocketState};
#[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
use crate::reassembly::FragmentsBuffer;
use crate::route::Routes;
use crate::storage::{Full, MaybeBox, Slab, Vec};
#[cfg(feature = "tcp")]
use crate::tcp::{SocketBuffer, TcpHandle, TcpRepr, TcpSocket, TcpSocketIter, TcpSocketState};
#[cfg(feature = "tcp-listener")]
use crate::tcp::{TcpListener, TcpListenerHandle, TcpListenerIter, TcpListenerState};
use crate::time::Instant;
#[cfg(feature = "udp")]
use crate::udp::{UdpHandle, UdpSocket, UdpSocketIter, UdpSocketState};
use crate::wire::*;

/// A network stack.
pub struct Stack<'d> {
    pub(crate) inner: StackInner,
    pub(crate) ifaces: Slab<IfaceState<'d>, IFACE_COUNT>,
    #[allow(unused)]
    pub(crate) sockets: Sockets<'d>,
    #[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
    pub(crate) fragments: FragmentsBuffer,
}

/// The stack's socket storage, one slab per socket type.
pub(crate) struct Sockets<'d> {
    #[cfg(feature = "udp")]
    pub(crate) udp: Slab<UdpSocketState, UDP_SOCKET_COUNT>,
    #[cfg(feature = "_raw")]
    pub(crate) raw: Slab<RawSocketState, RAW_SOCKET_COUNT>,
    #[cfg(feature = "tcp")]
    pub(crate) tcp: Slab<TcpSocketState<'d>, TCP_SOCKET_COUNT>,
    #[cfg(feature = "tcp-listener")]
    pub(crate) tcp_listeners: Slab<TcpListenerState, TCP_LISTENER_COUNT>,
    /// Only TCP sockets hold lent storage; without them `'d` is unused.
    #[cfg(not(feature = "tcp"))]
    _lent: core::marker::PhantomData<&'d mut ()>,
}

/// The device-independent part of the stack.
///
/// Separate from `Stack` so that its methods can borrow an interface from `Stack::ifaces`
/// while taking `&mut self`.
pub(crate) struct StackInner {
    pub(crate) now: Instant,
    #[cfg_attr(not(any(feature = "udp", feature = "tcp")), allow(dead_code))]
    pub(crate) rand: Rand,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub(crate) neighbor_cache: NeighborCache,
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pending: PendingQueue,
    pub(crate) routes: Routes,
    #[cfg(feature = "ipv4-fragmentation")]
    pub(crate) ipv4_id: u16,
    /// Set when a socket send failed for lack of a packet buffer or device room.
    /// `Stack::poll` wakes the send wakers of every packet socket when set.
    #[cfg(all(feature = "async", any(feature = "udp", feature = "_raw")))]
    pub(crate) tx_starved: bool,
    /// The stack's hostname. Empty when unset.
    #[cfg(feature = "hostname")]
    pub(crate) hostname: heapless::String<HOSTNAME_MAX_LEN>,
}

/// Maximum hostname length, in bytes. The DNS label limit (RFC 1035 §2.3.4).
#[cfg(feature = "hostname")]
const HOSTNAME_MAX_LEN: usize = 63;

impl StackInner {
    /// Note that a socket send was held back for lack of a packet buffer or
    /// device room, so `Stack::poll` wakes the packet sockets' send wakers.
    #[cfg(any(feature = "udp", feature = "_raw"))]
    pub(crate) fn set_tx_starved(&mut self) {
        #[cfg(feature = "async")]
        {
            self.tx_starved = true;
        }
    }

    /// The hostname to send in outgoing DHCP messages. `None` when unset.
    #[cfg(all(feature = "dhcpv4", feature = "hostname"))]
    pub(crate) fn hostname(&self) -> Option<&str> {
        if self.hostname.is_empty() {
            None
        } else {
            Some(&self.hostname)
        }
    }

    /// Forget everything the link layer learned about an interface: its neighbor
    /// cache entries and the packets parked on them.
    pub(crate) fn purge_iface_link_state(&mut self, handle: IfaceHandle) {
        #[cfg(not(any(feature = "medium-ethernet", feature = "medium-ieee802154")))]
        let _ = handle;
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        {
            self.neighbor_cache.clear_iface(handle);
            self.pending.purge_iface(handle);
        }
    }
}

/// Borrowed stack context for socket egress.
pub(crate) struct TxContext<'a, 'd> {
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<IfaceState<'d>, IFACE_COUNT>,
}

/// The interface a socket is bound to, if any.
///
/// The `Iface` variant only exists with the `iface-bind` feature. This way
/// this is zero-sized when not enabled and costs no code size.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum IfaceBinding {
    /// Not bound: all interfaces.
    #[default]
    Any,
    /// Bound to one interface.
    #[cfg(feature = "iface-bind")]
    Iface(IfaceHandle),
}

impl IfaceBinding {
    /// The bound interface, or `None`.
    pub(crate) fn iface(self) -> Option<IfaceHandle> {
        match self {
            IfaceBinding::Any => None,
            #[cfg(feature = "iface-bind")]
            IfaceBinding::Iface(iface) => Some(iface),
        }
    }

    /// Whether a packet arriving on (or, in [`TxContext::route`], leaving
    /// through) `arrival` passes the binding.
    pub(crate) fn matches(self, arrival: IfaceHandle) -> bool {
        self.match_score(arrival).is_some()
    }

    /// Score the binding against a packet's arrival interface, for demux.
    ///
    /// `None` if the binding excludes the interface, else how specific the
    /// binding is: bound outscores unbound, like the other exact tuple parts.
    pub(crate) fn match_score(self, arrival: IfaceHandle) -> Option<u8> {
        match self.iface() {
            None => Some(0),
            Some(bound) => (bound == arrival).then_some(1),
        }
    }
}

#[cfg(feature = "iface-bind")]
impl From<Option<IfaceHandle>> for IfaceBinding {
    fn from(iface: Option<IfaceHandle>) -> Self {
        match iface {
            Some(iface) => IfaceBinding::Iface(iface),
            None => IfaceBinding::Any,
        }
    }
}

/// A complete egress routing decision for one destination, produced by
/// [`TxContext::route`]: the interface the packet goes out of, the next hop to
/// resolve on that link, and the interface's IP MTU.
///
/// Made once per packet: callers that need routing information before building
/// the packet (TCP sizes segments by the egress MTU) route first and then
/// transmit via [`TxContext::transmit_ip`], so the packet is never routed
/// twice.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct EgressRoute {
    pub(crate) iface: IfaceHandle,
    /// The address to resolve on the link: the destination itself when on-link
    /// (or broadcast/multicast), else the gateway from the routing table.
    pub(crate) next_hop: IpAddress,
    /// The egress interface's IP-layer MTU.
    #[cfg_attr(not(feature = "tcp"), allow(dead_code))]
    pub(crate) ip_mtu: usize,
}

impl TxContext<'_, '_> {
    /// The current time, as last set by [`Stack::poll`].
    #[cfg(feature = "tcp")]
    pub(crate) fn now(&self) -> Instant {
        self.inner.now
    }

    /// The stack's PRNG.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn rand(&mut self) -> &mut Rand {
        &mut self.inner.rand
    }

    /// Check whether any interface has the given IP address assigned.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn has_ip_addr(&self, addr: IpAddress) -> bool {
        self.ifaces.iter().any(|(_, iface)| iface.has_ip_addr(addr))
    }

    /// Get a source address for sending to the given destination, selected from the
    /// interface the packet would go out of, honoring the socket's interface
    /// binding.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn get_source_address(&self, binding: IfaceBinding, dst_addr: &IpAddress) -> Option<IpAddress> {
        let route = self.route(binding, dst_addr)?;
        self.ifaces
            .get(route.iface.index())
            .get_source_address(dst_addr, self.inner.now)
    }

    /// A source address for sending to `dst_addr` out of the interface `route`
    /// names.
    #[cfg(feature = "udp")]
    pub(crate) fn get_source_address_routed(&self, route: &EgressRoute, dst_addr: &IpAddress) -> Option<IpAddress> {
        self.ifaces
            .get(route.iface.index())
            .get_source_address(dst_addr, self.inner.now)
    }

    /// Whether the interface can take one more frame right now.
    ///
    /// Asked before a packet is built, so that a device with no room holds the
    /// sender back instead of losing the packet.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    #[cfg(any(feature = "udp", feature = "tcp", feature = "_raw"))]
    pub(crate) fn can_transmit(&mut self, iface: IfaceHandle) -> bool {
        self.ifaces.get_mut(iface.index()).can_transmit_new_packet()
    }

    /// Which checksums the egress interface computes itself, so the stack
    /// doesn't do it in software.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn checksum_caps(&self, iface: IfaceHandle) -> ChecksumCapabilities {
        self.ifaces.get(iface.index()).checksum_caps()
    }

    /// Make the egress routing decision for a destination: the interface the
    /// destination is on-link for (next hop: the destination itself), else the
    /// interface and gateway named by the matching route.
    ///
    /// A bound socket (`binding`) routes only through its interface: the
    /// destination must be on-link for it or have a route through it, and
    /// broadcast/multicast destinations go straight out of it. A binding whose
    /// interface was removed routes nothing.
    pub(crate) fn route(&self, binding: IfaceBinding, dst_addr: &IpAddress) -> Option<EgressRoute> {
        // The interfaces the packet may go out of: the bound one, or all of
        // them. The routing-table lookup applies the same constraint.
        let mut candidates = self.ifaces.iter().filter(|(_, iface)| binding.matches(iface.handle));

        if !dst_addr.is_unicast() {
            // Broadcast and multicast destinations carry nothing to route on, so
            // they go out the first interface (for a bound socket, its own). The
            // next hop is the destination itself, resolved to a
            // broadcast/multicast hardware address.
            // TODO: let the send API pick the interface for unbound sockets.
            return candidates.next().map(|(_, iface)| EgressRoute {
                iface: iface.handle,
                next_hop: *dst_addr,
                ip_mtu: iface.ip_mtu(),
            });
        }

        if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
            return Some(EgressRoute {
                iface: iface.handle,
                next_hop: *dst_addr,
                ip_mtu: iface.ip_mtu(),
            });
        }

        let route = self.inner.routes.lookup(binding, dst_addr, self.inner.now)?;
        Some(EgressRoute {
            iface: route.iface,
            next_hop: route.via_router,
            ip_mtu: self.ifaces.get(route.iface.index()).ip_mtu(),
        })
    }

    /// The first Ethernet-medium interface, for unbound Ethernet-mode raw
    /// sockets, whose frames carry no routing information.
    #[cfg(feature = "raw-ethernet")]
    pub(crate) fn first_ethernet_iface(&self) -> Option<IfaceHandle> {
        self.ifaces
            .iter()
            .find(|(_, iface)| iface.medium() == Medium::Ethernet)
            .map(|(_, iface)| iface.handle)
    }

    /// [`route`](Self::route) for a locally-generated reply to an ingress packet
    /// that arrived on `arrival`.
    ///
    /// Replies are routed like any other egress, so a reply may leave a different
    /// interface than the packet came in on (asymmetric routing). The
    /// exception is an IPv6 link-local destination: it is meaningful only on the
    /// link the packet came from, so it goes back out the arrival interface, with
    /// the destination itself as the next hop.
    pub(crate) fn route_reply(&self, arrival: IfaceHandle, dst_addr: &IpAddress) -> Option<EgressRoute> {
        #[cfg(not(feature = "ipv6"))]
        let _ = arrival;

        #[cfg(feature = "ipv6")]
        if let IpAddress::Ipv6(dst) = dst_addr
            && dst.is_link_local()
        {
            return Some(EgressRoute {
                iface: arrival,
                next_hop: *dst_addr,
                ip_mtu: self.ifaces.get(arrival.index()).ip_mtu(),
            });
        }

        self.route(IfaceBinding::Any, dst_addr)
    }

    /// Transmit a fully-built IP payload, with the L4 header but not the IP header.
    ///
    /// `src_addr` and `dst_addr` must belong to the same address family, the packet
    /// is dropped otherwise.
    pub(crate) fn transmit_ip(
        &mut self,
        route: &EgressRoute,
        mut buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        let iface = self.ifaces.get_mut(route.iface.index());
        #[cfg(feature = "ipv4")]
        let checksum_caps = iface.checksum_caps();
        let ethertype = match (src_addr, dst_addr) {
            #[cfg(feature = "ipv4")]
            (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
                push_ipv4_header(&mut buf, src, dst, next_header, hop_limit, &checksum_caps);
                EthernetProtocol::Ipv4
            }
            #[cfg(feature = "ipv6")]
            (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
                push_ipv6_header(&mut buf, src, dst, next_header, hop_limit);
                EthernetProtocol::Ipv6
            }
            #[allow(unreachable_patterns)]
            _ => {
                debug!("cannot transmit, address family mismatch");
                return;
            }
        };
        self.inner.transmit_ip(iface, dst_addr, route.next_hop, buf, ethertype);
    }

    /// Transmit a fully-built Ethernet frame on the given interface, as-is.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    #[cfg(feature = "raw-ethernet")]
    pub(crate) fn transmit_ethernet(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        let iface = self.ifaces.get_mut(iface.index());
        self.inner.transmit_raw(iface, buf);
    }

    /// Transmit a fully-built IP packet (IP header included, emitted as-is).
    #[cfg(feature = "raw-ip")]
    pub(crate) fn transmit_raw_ip(&mut self, route: &EgressRoute, buf: PacketBuf, dst_addr: IpAddress) {
        let iface = self.ifaces.get_mut(route.iface.index());
        let ethertype = match dst_addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
        };
        self.inner.transmit_ip(iface, dst_addr, route.next_hop, buf, ethertype);
    }
}

/// Score `addr` against a bind's address filter, the way ingress demux ranks
/// candidate sockets: `None` if it does not match, else how specific the filter
/// that matched it is. No address matches anything (0), an unspecified one
/// matches its own IP version (1), and a concrete one matches only itself (2).
#[cfg(any(feature = "udp", feature = "tcp-listener"))]
pub(crate) fn addr_score(filter: &IpListenEndpoint, addr: &IpAddress) -> Option<u8> {
    match filter.addr {
        None => Some(0),
        Some(a) if a.is_unspecified() => (a.version() == addr.version()).then_some(1),
        Some(a) => (a == *addr).then_some(2),
    }
}

/// The bottom of the ephemeral (dynamic) local port range, per IANA. The range
/// runs to the top of the port space, 65535.
#[cfg(any(feature = "udp", feature = "tcp"))]
pub(crate) const EPHEMERAL_PORT_MIN: u16 = 49152;

/// Allocate an ephemeral local port: start at a random point in the range and
/// linearly probe upward (wrapping) for the first port `in_use` doesn't claim.
///
/// The random start makes local ports hard to predict for off-path attackers
/// (RFC 6056 §3.3). `None` is returned only when every port in the range is in use.
#[cfg(any(feature = "udp", feature = "tcp"))]
pub(crate) fn alloc_ephemeral_port(rand: &mut Rand, mut in_use: impl FnMut(u16) -> bool) -> Option<u16> {
    const RANGE: u32 = (u16::MAX - EPHEMERAL_PORT_MIN) as u32 + 1;
    let start = rand.rand_u32() % RANGE;
    (0..RANGE)
        .map(|i| EPHEMERAL_PORT_MIN + ((start + i) % RANGE) as u16)
        .find(|&port| !in_use(port))
}

/// The result of a neighbor lookup.
#[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
enum NeighborLookup {
    /// The destination hardware address.
    Found(HardwareAddress),
    /// The neighbor is being resolved; the packet should be queued as pending.
    Pending { next_hop: IpAddress },
}

impl<'d> Stack<'d> {
    /// Create a network stack.
    ///
    /// `random_seed` seeds the stack's PRNG, which picks TCP initial sequence
    /// numbers and ephemeral ports. This should be random, or at least different
    /// at every boot.
    pub fn new(random_seed: u64) -> Self {
        #[cfg_attr(not(feature = "ipv4-fragmentation"), allow(unused_mut))]
        let mut rand = Rand::new(random_seed);

        #[cfg(feature = "ipv4-fragmentation")]
        let ipv4_id = crate::fragmentation::initial_ipv4_id(&mut rand);

        Self {
            inner: StackInner {
                now: Instant::ZERO,
                rand,
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                neighbor_cache: NeighborCache::new(),
                #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
                pending: PendingQueue::new(),
                routes: Routes::new(),
                #[cfg(feature = "ipv4-fragmentation")]
                ipv4_id,
                #[cfg(all(feature = "async", any(feature = "udp", feature = "_raw")))]
                tx_starved: false,
                #[cfg(feature = "hostname")]
                hostname: heapless::String::new(),
            },
            ifaces: Slab::new(),
            sockets: Sockets {
                #[cfg(feature = "udp")]
                udp: Slab::new(),
                #[cfg(feature = "_raw")]
                raw: Slab::new(),
                #[cfg(feature = "tcp")]
                tcp: Slab::new(),
                #[cfg(feature = "tcp-listener")]
                tcp_listeners: Slab::new(),
                #[cfg(not(feature = "tcp"))]
                _lent: core::marker::PhantomData,
            },
            #[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
            fragments: FragmentsBuffer::new(),
        }
    }

    /// The stack's hostname, or `None` if not set.
    #[cfg(feature = "hostname")]
    pub fn hostname(&self) -> Option<&str> {
        if self.inner.hostname.is_empty() {
            None
        } else {
            Some(&self.inner.hostname)
        }
    }

    /// Set the stack's hostname.
    ///
    /// If set, it is sent to the DHCP server in outgoing DHCP messages, as the
    /// host name option.
    ///
    /// An empty string clears the hostname.
    ///
    /// # Panics
    /// Panics if `hostname` is longer than 63 bytes.
    #[cfg(feature = "hostname")]
    pub fn set_hostname(&mut self, hostname: &str) {
        self.inner.hostname.clear();
        if self.inner.hostname.push_str(hostname).is_err() {
            panic!("hostname too long, max is {} bytes", HOSTNAME_MAX_LEN);
        }
    }

    /// Add an interface to the stack, returning a handle to it.
    ///
    /// The stack owns the boxed device, so this needs the `alloc` feature.
    /// Without alloc, use [`add_iface_borrowed`](Self::add_iface_borrowed).
    ///
    /// Configure the interface after adding it. At minimum, you will want to
    /// add an IP address to it.
    ///
    /// ```no_run
    /// # use xarxa::{Stack, driver::Driver, wire::{IpCidr, Ipv4Address}};
    /// # fn configure(stack: &mut Stack, driver: Box<dyn Driver>) {
    /// let handle = stack.add_iface(driver).unwrap();
    /// stack
    ///     .iface(handle)
    ///     .add_ip_addr(IpCidr::new(Ipv4Address::new(192, 168, 1, 1).into(), 24))
    ///     .unwrap();
    /// # }
    /// ```
    ///
    /// # Panics
    /// Panics if the hardware address the device reports is not of the kind its
    /// medium uses.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another interface. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`IFACE_COUNT`].
    #[cfg(feature = "alloc")]
    pub fn add_iface(&mut self, driver: alloc::boxed::Box<dyn Driver + 'd>) -> core::result::Result<IfaceHandle, Full> {
        self.add_iface_inner(driver.into())
    }

    /// Add an interface to the stack, lending it the device, and returning a
    /// handle to it.
    ///
    /// The stack holds the device until it is dropped or the interface is
    /// removed, so the device must be declared before the stack, or be `'static`.
    /// Otherwise this is [`add_iface`](Self::add_iface).
    ///
    /// # Panics
    /// Panics if the hardware address the device reports is not of the kind its
    /// medium uses.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another interface. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`IFACE_COUNT`].
    pub fn add_iface_borrowed(&mut self, driver: &'d mut dyn Driver) -> core::result::Result<IfaceHandle, Full> {
        self.add_iface_inner(driver.into())
    }

    fn add_iface_inner(&mut self, driver: MaybeBox<'d, dyn Driver + 'd>) -> core::result::Result<IfaceHandle, Full> {
        let caps = driver.capabilities();
        let medium = Medium::from_driver(caps.medium)
            .expect("the driver's medium is not supported by this build: enable the matching medium-* cargo feature");
        let hardware_addr = HardwareAddress::from_driver(driver.hardware_address())
            .expect("the driver's hardware address kind is not supported by this build: enable the matching medium-* cargo feature");
        assert_eq!(
            hardware_addr.medium(),
            medium,
            "the device's hardware address does not match its medium"
        );
        #[cfg(feature = "medium-ieee802154")]
        let sixlowpan = crate::sixlowpan::State::new(&mut self.inner.rand);
        #[allow(unused_mut)]
        let mut ip_addrs = Vec::new();
        #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
        if let Some(ll) = link_local_addr(hardware_addr) {
            // Can't fail: the table is empty and holds at least one address.
            let _ = ip_addrs.push(ll);
        }
        let index = self.ifaces.add_with(|index| IfaceState {
            handle: IfaceHandle::new(index),
            driver,
            medium,
            caps,
            hardware_addr,
            ip_addrs,
            config_generation: 0,
            #[cfg(feature = "async")]
            waker: crate::waker::WakerRegistration::new(),
            #[cfg(feature = "dhcpv4")]
            dhcpv4: None,
            #[cfg(feature = "slaac")]
            slaac: None,
            last_link_state: crate::driver::LinkState::Down,
            #[cfg(feature = "multicast")]
            multicast: crate::multicast::State::new(),
            #[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
            fragmenter: Fragmenter::new(),
            #[cfg(feature = "medium-ieee802154")]
            sixlowpan,
        })?;
        // The link-local address is already assigned, so its solicited-node
        // group is joined before the first configuration change.
        #[cfg(all(
            feature = "multicast",
            all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6")
        ))]
        if self.ifaces.get(index).has_link_layer() {
            self.ifaces.get_mut(index).update_solicited_node_groups();
        }
        Ok(IfaceHandle::new(index))
    }

    /// Borrow an interface from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was removed).
    pub fn iface(&mut self, handle: IfaceHandle) -> Iface<'_, 'd> {
        self.ifaces.get(handle.index()); // Stale handles panic here, not on first use.
        Iface {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
            index: handle.index(),
        }
    }

    /// Remove an interface from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the interface was already removed).
    pub fn remove_iface(&mut self, handle: IfaceHandle) {
        self.ifaces.remove(handle.index());
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        {
            self.inner.neighbor_cache.clear_iface(handle);
            self.inner.pending.purge_iface(handle);
        }
        self.inner.routes.purge_iface(handle);
    }

    /// Access the neighbor cache.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn neighbor_cache(&self) -> &NeighborCache {
        &self.inner.neighbor_cache
    }

    /// Access the neighbor cache for modification.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub fn neighbor_cache_mut(&mut self) -> &mut NeighborCache {
        &mut self.inner.neighbor_cache
    }

    /// Access the routing table.
    pub fn routes(&self) -> &Routes {
        &self.inner.routes
    }

    /// Access the routing table for modification.
    pub fn routes_mut(&mut self) -> &mut Routes {
        &mut self.inner.routes
    }

    /// Add a UDP socket to the stack, returning a handle to it.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another UDP socket. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`UDP_SOCKET_COUNT`].
    #[cfg(feature = "udp")]
    pub fn add_udp_socket(&mut self) -> core::result::Result<UdpHandle, Full> {
        Ok(UdpHandle::new(self.sockets.udp.add_with(|_| UdpSocketState::new())?))
    }

    /// Remove a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "udp")]
    pub fn remove_udp_socket(&mut self, handle: UdpHandle) {
        self.sockets.udp.remove(handle.index());
    }

    /// Borrow a UDP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "udp")]
    pub fn udp_socket(&mut self, handle: UdpHandle) -> UdpSocket<'_, 'd> {
        self.sockets.udp.get(handle.index()); // Stale handles panic here, not on first use.
        UdpSocket {
            sockets: &mut self.sockets.udp,
            index: handle.index(),
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a raw socket to the stack, returning a handle to it.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another raw socket. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`RAW_SOCKET_COUNT`].
    #[cfg(feature = "_raw")]
    pub fn add_raw_socket(&mut self) -> core::result::Result<RawHandle, Full> {
        Ok(RawHandle::new(self.sockets.raw.add_with(|_| RawSocketState::new())?))
    }

    /// Remove a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "_raw")]
    pub fn remove_raw_socket(&mut self, handle: RawHandle) {
        self.sockets.raw.remove(handle.index());
    }

    /// Borrow a raw socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "_raw")]
    pub fn raw_socket(&mut self, handle: RawHandle) -> RawSocket<'_, 'd> {
        RawSocket {
            state: self.sockets.raw.get_mut(handle.index()),
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a TCP socket to the stack, with receive and transmit buffers of the
    /// given capacities, returning a handle to it.
    ///
    /// The buffers are allocated on the heap, so this needs the `alloc` feature.
    /// Without it, or to use your own buffers, see
    /// [`add_tcp_socket_with_bufs`](Self::add_tcp_socket_with_bufs).
    ///
    /// # Panics
    /// Panics if the receive buffer is larger than 1 GiB.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another TCP socket. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`TCP_SOCKET_COUNT`].
    #[cfg(all(feature = "tcp", feature = "alloc"))]
    pub fn add_tcp_socket(&mut self, rx_capacity: usize, tx_capacity: usize) -> core::result::Result<TcpHandle, Full> {
        self.add_tcp_socket_inner(
            SocketBuffer::new(alloc::vec![0; rx_capacity]),
            SocketBuffer::new(alloc::vec![0; tx_capacity]),
        )
    }

    /// Add a TCP socket to the stack, with borrowed receive and transmit
    /// buffers, and returning a handle to it.
    ///
    /// The stack holds the buffers until it is dropped or the socket is removed,
    /// so they must be declared before the stack, or be `'static`. Otherwise
    /// this is [`add_tcp_socket`](Self::add_tcp_socket).
    ///
    /// ```no_run
    /// # use xarxa::Stack;
    /// # fn add<'d>(stack: &mut Stack<'d>, rx: &'d mut [u8; 4096], tx: &'d mut [u8; 4096]) {
    /// let handle = stack.add_tcp_socket_with_bufs(rx, tx).unwrap();
    /// # }
    /// ```
    ///
    /// # Panics
    /// Panics if the receive buffer is larger than 1 GiB.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another TCP socket. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`TCP_SOCKET_COUNT`].
    #[cfg(feature = "tcp")]
    pub fn add_tcp_socket_with_bufs(
        &mut self,
        rx_buffer: &'d mut [u8],
        tx_buffer: &'d mut [u8],
    ) -> core::result::Result<TcpHandle, Full> {
        self.add_tcp_socket_inner(SocketBuffer::new(rx_buffer), SocketBuffer::new(tx_buffer))
    }

    #[cfg(feature = "tcp")]
    fn add_tcp_socket_inner(
        &mut self,
        rx_buffer: SocketBuffer<'d>,
        tx_buffer: SocketBuffer<'d>,
    ) -> core::result::Result<TcpHandle, Full> {
        Ok(TcpHandle::new(
            self.sockets
                .tcp
                .add_with(|_| TcpSocketState::new(rx_buffer, tx_buffer))?,
        ))
    }

    /// Remove a TCP socket from the stack.
    ///
    /// No RST is sent, and any buffered data is lost. To close a connection cleanly,
    /// [`TcpSocket::close`] it first and poll until it is fully closed.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "tcp")]
    pub fn remove_tcp_socket(&mut self, handle: TcpHandle) {
        self.sockets.tcp.remove(handle.index());
    }

    /// Borrow a TCP socket from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the socket was already removed).
    #[cfg(feature = "tcp")]
    pub fn tcp_socket(&mut self, handle: TcpHandle) -> TcpSocket<'_, 'd> {
        self.sockets.tcp.get(handle.index()); // Stale handles panic here, not on first use.
        TcpSocket {
            sockets: &mut self.sockets.tcp,
            index: handle.index(),
            tx: TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            },
        }
    }

    /// Add a TCP listener to the stack, returning a handle to it.
    ///
    /// Errors:
    /// - `Full` if the stack has no room for another listener. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`TCP_LISTENER_COUNT`].
    #[cfg(feature = "tcp-listener")]
    pub fn add_tcp_listener(&mut self) -> core::result::Result<TcpListenerHandle, Full> {
        Ok(TcpListenerHandle::new(
            self.sockets.tcp_listeners.add_with(|_| TcpListenerState::new())?,
        ))
    }

    /// Remove a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "tcp-listener")]
    pub fn remove_tcp_listener(&mut self, handle: TcpListenerHandle) {
        self.sockets.tcp_listeners.remove(handle.index());
    }

    /// Borrow a TCP listener from the stack.
    ///
    /// # Panics
    /// Panics if the handle is stale (the listener was already removed).
    #[cfg(feature = "tcp-listener")]
    pub fn tcp_listener(&mut self, handle: TcpListenerHandle) -> TcpListener<'_, 'd> {
        self.sockets.tcp_listeners.get(handle.index()); // Stale handles panic here, not on first use.
        TcpListener {
            listeners: &mut self.sockets.tcp_listeners,
            index: handle.index(),
            tcp: &mut self.sockets.tcp,
            rand: &mut self.inner.rand,
        }
    }

    /// Borrow the stack context for egress.
    pub(crate) fn tx_context(&mut self) -> TxContext<'_, 'd> {
        TxContext {
            inner: &mut self.inner,
            ifaces: &mut self.ifaces,
        }
    }

    /// Iterate over the interfaces added to the stack.
    ///
    /// See [`IfaceIter`] for how to use it.
    pub fn ifaces(&mut self) -> IfaceIter<'_, 'd> {
        IfaceIter { stack: self, next: 0 }
    }

    /// Iterate over the UDP sockets added to the stack.
    ///
    /// See [`UdpSocketIter`] for how to use it.
    #[cfg(feature = "udp")]
    pub fn udp_sockets(&mut self) -> UdpSocketIter<'_, 'd> {
        UdpSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the raw sockets added to the stack.
    ///
    /// See [`RawSocketIter`] for how to use it.
    #[cfg(feature = "_raw")]
    pub fn raw_sockets(&mut self) -> RawSocketIter<'_, 'd> {
        RawSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the TCP sockets added to the stack.
    ///
    /// See [`TcpSocketIter`] for how to use it.
    #[cfg(feature = "tcp")]
    pub fn tcp_sockets(&mut self) -> TcpSocketIter<'_, 'd> {
        TcpSocketIter { stack: self, next: 0 }
    }

    /// Iterate over the TCP listeners added to the stack.
    ///
    /// See [`TcpListenerIter`] for how to use it.
    #[cfg(feature = "tcp-listener")]
    pub fn tcp_listeners(&mut self) -> TcpListenerIter<'_, 'd> {
        TcpListenerIter { stack: self, next: 0 }
    }

    /// Process all pending ingress packets on all ifaces, advance the stack's
    /// internal timers, and transmit everything the TCP sockets have made due.
    ///
    /// `timestamp` is the current time.
    ///
    /// Returns a "poll deadline" instant. It is the earliest expiring timer. You should call `poll` at that instant to let it advance timers. Special cases:
    /// - If it's [`Instant::MIN`] or in the past, `poll` should be called again immediately.
    /// - If no timer is pending, [`Instant::MAX`] is returned. No need to call `poll` on a timer, only after
    ///   a packet is received or an operation is done on the Stack, a socket or an interface.
    pub fn poll(&mut self, timestamp: Instant) -> Instant {
        self.inner.now = timestamp;

        // Drop queued packets whose neighbor resolution timed out.
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        self.inner.pending.purge_expired(timestamp);

        #[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
        self.fragments.assembler.remove_expired(timestamp);

        let mut next = 0;
        while let Some(index) = self.ifaces.next_occupied(next) {
            next = index + 1;
            let handle = IfaceHandle::new(index);

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            self.poll_neighbor_timers(handle);

            #[allow(unused_mut)]
            while let Some(mut buf) = self.ifaces.get_mut(index).driver.receive() {
                #[cfg(feature = "packet-log")]
                {
                    trace!("received on iface {}", index);
                    let medium = self.ifaces.get(index).medium();
                    crate::packet_log::log_packet(&mut buf, packet_log_layer(medium));
                }
                self.process(handle, buf);
            }

            // `inner` has no user in a build with no link layer and no fragmentation.
            #[allow(unused_variables)]
            let Self { inner, ifaces, .. } = self;
            let iface = ifaces.get_mut(index);

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            inner.flush_resolved_pending(iface);

            #[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
            inner.fragment_egress(iface);

            // Spot the link state edges: wake whoever waits on the interface, and on the
            // way back up re-run both configuration protocols, since a link coming back
            // can mean a different network and what was learned before it dropped may
            // not hold there.
            {
                let link_state = iface.driver.link_state();
                if link_state != iface.last_link_state {
                    iface.last_link_state = link_state;
                    #[cfg(feature = "async")]
                    iface.waker.wake();
                    #[cfg(any(feature = "dhcpv4", feature = "slaac"))]
                    if link_state == crate::driver::LinkState::Up {
                        #[cfg(feature = "dhcpv4")]
                        iface.dhcpv4_reset(&mut self.inner);
                        #[cfg(feature = "slaac")]
                        if let Some(slaac) = iface.slaac.as_mut() {
                            slaac.restart();
                        }
                    }
                }
            }

            #[cfg(feature = "dhcpv4")]
            self.ifaces.get_mut(index).dhcpv4_dispatch(&mut self.inner);

            #[cfg(feature = "slaac")]
            {
                let iface = self.ifaces.get_mut(index);
                // A solicitation counts as sent even if the driver refuses the frame, so
                // don't spend the budget on a down link.
                if iface.last_link_state == crate::driver::LinkState::Up {
                    iface.ndisc_rs_egress(&mut self.inner);
                }
                if iface.slaac.as_ref().is_some_and(|s| s.sync_required(timestamp)) {
                    iface.sync_slaac_state(&mut self.inner);
                }
            }

            #[cfg(feature = "multicast")]
            self.ifaces.get_mut(index).multicast_egress(&mut self.inner);
        }

        #[allow(unused_mut)]
        let mut deadline = Instant::MAX;

        // Drive TCP egress: this both acknowledges what ingress just delivered and
        // advances the TCP timers (retransmissions, delayed ACKs, keep-alives,
        // zero-window probes, ...).
        #[cfg(feature = "tcp")]
        {
            let mut cx = TxContext {
                inner: &mut self.inner,
                ifaces: &mut self.ifaces,
            };
            for (_, socket) in self.sockets.tcp.iter_mut() {
                // If egress failed due to device busy or full packet pool,
                // avoid endless poll loops.
                let socket_deadline = match crate::tcp::flush(socket, &mut cx) {
                    Ok(()) => socket.poll_at(),
                    Err(crate::tcp::Blocked) => socket.poll_at_blocked(),
                };
                deadline = deadline.min(socket_deadline);
            }
        }

        // Sends held back for lack of a buffer or device room since the last poll
        // may succeed now: wake their tasks so they retry.
        #[cfg(all(feature = "async", any(feature = "udp", feature = "_raw")))]
        if core::mem::take(&mut self.inner.tx_starved) {
            #[cfg(feature = "udp")]
            for (_, socket) in self.sockets.udp.iter_mut() {
                socket.wake_tx();
            }
            #[cfg(feature = "_raw")]
            for (_, socket) in self.sockets.raw.iter_mut() {
                socket.wake_tx();
            }
        }

        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        {
            deadline = deadline.min(self.inner.neighbor_cache.poll_at());
            deadline = deadline.min(self.inner.pending.poll_at());
        }

        #[cfg(any(feature = "ipv4-reassembly", feature = "sixlowpan-reassembly"))]
        {
            deadline = deadline.min(self.fragments.assembler.poll_at());
        }

        #[cfg(feature = "dhcpv4")]
        {
            deadline = self
                .ifaces
                .iter()
                .filter_map(|(_, iface)| iface.dhcpv4.as_ref().map(|client| client.poll_at()))
                .fold(deadline, Instant::min);
        }

        #[cfg(feature = "slaac")]
        {
            deadline = self
                .ifaces
                .iter()
                .filter_map(|(_, iface)| iface.slaac.as_ref().map(|s| s.poll_at(timestamp)))
                .fold(deadline, Instant::min);
        }

        #[cfg(feature = "multicast")]
        {
            deadline = self
                .ifaces
                .iter()
                .map(|(_, iface)| iface.multicast.poll_at())
                .fold(deadline, Instant::min);
        }

        deadline
    }
}

impl<'d> Stack<'d> {
    fn process(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        match self.ifaces.get(iface.index()).medium() {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => self.process_ethernet(iface, buf),
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.process_ip(iface, buf),
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => self.process_ieee802154(iface, buf),
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn process_ethernet(&mut self, iface: IfaceHandle, mut buf: PacketBuf) {
        let eth_frame = check!(EthernetFrame::new_checked(&mut buf));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != self.ifaces.get(iface.index()).ethernet_addr()
        {
            return;
        }

        let src_addr = eth_frame.src_addr();
        let ethertype = eth_frame.ethertype();

        // Offer the whole frame to Ethernet-mode raw sockets. Ethertypes the stack
        // itself processes are copied to the socket, everything else is consumed
        // by it.
        #[cfg(feature = "raw-ethernet")]
        let Some(mut buf) = ({
            let stack_wants = matches!(
                ethertype,
                EthernetProtocol::Arp | EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6
            );
            self.process_raw_ethernet(iface, ethertype, stack_wants, buf)
        }) else {
            return;
        };

        buf.pull_front(ETHERNET_HEADER_LEN);

        match ethertype {
            #[cfg(feature = "ipv4")]
            EthernetProtocol::Arp => self.inner.process_arp(self.ifaces.get_mut(iface.index()), buf),
            #[cfg(feature = "ipv4")]
            EthernetProtocol::Ipv4 => self.process_ipv4(iface, Some(src_addr), buf),
            #[cfg(feature = "ipv6")]
            EthernetProtocol::Ipv6 => self.process_ipv6(iface, Some(HardwareAddress::Ethernet(src_addr)), buf),
            // Drop all other traffic.
            _ => {}
        }
    }

    #[cfg(feature = "medium-ip")]
    fn process_ip(&mut self, iface: IfaceHandle, buf: PacketBuf) {
        if buf.is_empty() {
            return;
        }
        match IpVersion::of_packet(&buf) {
            #[cfg(feature = "ipv4")]
            Ok(IpVersion::Ipv4) => self.process_ipv4(iface, None, buf),
            #[cfg(feature = "ipv6")]
            Ok(IpVersion::Ipv6) => self.process_ipv6(iface, None, buf),
            Err(_) => {}
        }
    }

    // IPv4 only arrives over Ethernet and IP interfaces; a build with neither
    // medium never calls this.
    #[cfg(feature = "ipv4")]
    #[cfg_attr(not(any(feature = "medium-ethernet", feature = "medium-ip")), allow(dead_code))]
    fn process_ipv4(&mut self, iface: IfaceHandle, eth_src: Option<EthernetAddress>, mut buf: PacketBuf) {
        let ipv4_packet = check!(Ipv4Packet::new_checked(&mut buf));

        if ipv4_packet.version() != 4 {
            return;
        }
        let checksum_caps = self.ifaces.get(iface.index()).checksum_caps();
        if checksum_caps.ipv4.rx() && !ipv4_packet.verify_checksum() {
            trace!("ipv4: header checksum incorrect");
            return;
        }
        #[cfg(feature = "ipv4-reassembly")]
        let mut buf = if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
            let Some(buf) = self.reassemble_ipv4(buf) else {
                return;
            };
            buf
        } else {
            buf
        };
        #[cfg(not(feature = "ipv4-reassembly"))]
        if ipv4_packet.more_frags() || ipv4_packet.frag_offset() != 0 {
            trace!("ipv4: fragmented packets not supported");
            return;
        }
        let ipv4_packet = check!(Ipv4Packet::new_checked(&mut buf));

        let src_addr = ipv4_packet.src_addr();
        let dst_addr = ipv4_packet.dst_addr();
        let next_header = ipv4_packet.next_header();
        let header_len = ipv4_packet.header_len() as usize;
        let total_len = ipv4_packet.total_len() as usize;

        // The DHCP client sees its replies before the destination check: they may
        // be addressed to the address being leased, which isn't ours yet, or to
        // broadcast.
        #[cfg(feature = "dhcpv4")]
        if next_header == IpProtocol::Udp && self.ifaces.get(iface.index()).dhcpv4.is_some() {
            let udp_len = match buf.get_mut(header_len..total_len).map(UdpPacket::new_checked) {
                Some(Ok(udp)) if udp.src_port() == DHCP_SERVER_PORT && udp.dst_port() == DHCP_CLIENT_PORT => {
                    if checksum_caps.udp.rx()
                        && !udp.verify_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr))
                    {
                        trace!("dhcp: udp checksum incorrect");
                        return;
                    }
                    Some(udp.len() as usize)
                }
                _ => None,
            };
            if let Some(udp_len) = udp_len {
                let payload = &mut buf[header_len + UDP_HEADER_LEN..header_len + udp_len];
                self.ifaces
                    .get_mut(iface.index())
                    .dhcpv4_process(&mut self.inner, src_addr, payload);
                return;
            }
        }

        {
            let iface = self.ifaces.get(iface.index());
            if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
                // Discard packets with non-unicast source addresses but allow unspecified
                debug!("non-unicast or unspecified source address");
                return;
            }

            if !iface.has_ip_addr(dst_addr) && !iface.has_multicast_group(dst_addr) && !iface.is_broadcast_v4(dst_addr)
            {
                // Ignore IP packets not directed at us, or broadcast, or any of the multicast groups.
                trace!("Rejecting IPv4 packet; not for us");
                return;
            }

            #[cfg(feature = "medium-ethernet")]
            if let Some(eth_src) = eth_src
                && iface.is_unicast_v4(dst_addr)
            {
                self.inner.neighbor_cache.reset_expiry_if_existing(
                    (iface.handle, IpAddress::Ipv4(src_addr)),
                    HardwareAddress::Ethernet(eth_src),
                    self.inner.now,
                );
            }
            #[cfg(not(feature = "medium-ethernet"))]
            let _ = eth_src;
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(total_len);

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(feature = "raw-ip")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmp | IpProtocol::Udp | IpProtocol::Tcp);
            #[cfg(feature = "multicast")]
            let stack_wants = stack_wants || next_header == IpProtocol::Igmp;
            self.process_raw_ip(iface, IpVersion::Ipv4, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(not(feature = "raw-ip"))]
        let handled_by_raw = false;

        // Strip the IP header.
        buf.pull_front(header_len);

        match next_header {
            IpProtocol::Icmp => self.process_icmpv4(iface, src_addr, dst_addr, buf),
            #[cfg(feature = "multicast")]
            IpProtocol::Igmp => self
                .ifaces
                .get_mut(iface.index())
                .process_igmp(&mut self.inner, dst_addr, buf),
            #[cfg(feature = "udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                IpAddress::Ipv4(src_addr),
                IpAddress::Ipv4(dst_addr),
                header_len,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => self.process_tcp(iface, IpAddress::Ipv4(src_addr), IpAddress::Ipv4(dst_addr), buf),
            _ => {
                trace!("ipv4: protocol {} not supported", next_header);
                // ICMP protocol unreachable (RFC 792): restore the IP header so the
                // whole offending packet can be quoted.
                buf.push_front(header_len);
                self.transmit_icmpv4_error(
                    iface,
                    &mut buf,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::ProtoUnreachable.into(),
                );
            }
        }
    }

    /// Process an ingress TCP segment: validate it and hand it to the matching
    /// socket, transmitting whatever immediate reply the socket state machine
    /// produces (RST, challenge ACK). Connected sockets match first, by full
    /// 4-tuple, then the listeners, which record SYNs to a listened endpoint in
    /// their accept queues and transmit nothing (the SYN|ACK is sent by the
    /// socket that `accept` creates). Unmatched segments are answered with an
    /// RST.
    ///
    /// The socket's own transmissions (data, ACKs of received data) are not sent
    /// here. [`Stack::poll`] drives them right after ingress processing.
    #[cfg(feature = "tcp")]
    fn process_tcp(&mut self, iface: IfaceHandle, src_addr: IpAddress, dst_addr: IpAddress, mut buf: PacketBuf) {
        // Per RFC 1122 §3.2.1.3, the unspecified address must never appear as a source
        // or destination in any IP datagram. Drop such TCP segments early to avoid
        // creating sockets with unspecified peers (which would later panic on egress).
        if src_addr.is_unspecified() || dst_addr.is_unspecified() {
            return;
        }

        let Ok(tcp_packet) = TcpPacket::new_checked(&mut buf) else {
            trace!("tcp: malformed packet");
            return;
        };
        if self.ifaces.get(iface.index()).checksum_caps().tcp.rx() && !tcp_packet.verify_checksum(&src_addr, &dst_addr)
        {
            trace!("tcp: checksum incorrect");
            return;
        }
        let Ok(tcp_repr) = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr) else {
            trace!("tcp: malformed packet");
            return;
        };

        // Connected sockets: exact 4-tuple match. Immediate replies the socket
        // state machine produces (RST, challenge ACK) are transmitted after the
        // loop, once the socket borrow has ended.
        let mut matched = false;
        let mut reply_repr = None;
        for (_, socket) in self.sockets.tcp.iter_mut() {
            if socket.binding_matches(iface) && socket.accepts(&src_addr, &dst_addr, &tcp_repr) {
                matched = true;
                reply_repr = socket.process(self.inner.now, &src_addr, &dst_addr, &tcp_repr);
                break;
            }
        }
        if matched {
            if let Some(reply) = reply_repr {
                self.transmit_tcp_reply(iface, &reply, dst_addr, src_addr);
            }
            return;
        }

        // Listeners: a SYN to a listened endpoint is recorded in the accept
        // queue of the most specific matching listener (exact local address
        // beats wildcard), and an RST aimed at a recorded SYN cancels it.
        // Nothing is replied, the handshake starts when the connection is
        // accepted.
        #[cfg(feature = "tcp-listener")]
        if crate::tcp::process_listeners(&mut self.sockets.tcp_listeners, iface, &src_addr, &dst_addr, &tcp_repr) {
            return;
        }

        // The packet wasn't handled by a socket: send a TCP RST packet.
        // Never reply to a TCP RST packet with another TCP RST packet.
        if tcp_repr.control != TcpControl::Rst {
            let reply = TcpSocketState::rst_reply(&tcp_repr);
            self.transmit_tcp_reply(iface, &reply, dst_addr, src_addr);
        }
    }

    /// Build and transmit an immediate reply to an ingress TCP segment: an RST, or
    /// a challenge ACK from a socket's state machine.
    ///
    /// The reply is routed before it is built, since its checksum is the egress
    /// interface's to compute and that is not necessarily the arrival one. It is
    /// dropped if there is no route, or if the pool is empty.
    #[cfg(feature = "tcp")]
    fn transmit_tcp_reply(
        &mut self,
        arrival: IfaceHandle,
        repr: &TcpRepr<'_>,
        src_addr: IpAddress,
        dst_addr: IpAddress,
    ) {
        let Some((route, checksum_caps)) = self.route_reply(arrival, &dst_addr) else {
            return;
        };
        let Some(buf) = crate::tcp::build_tcp_packet(repr, &src_addr, &dst_addr, &checksum_caps) else {
            return;
        };
        self.transmit_reply(&route, buf, src_addr, dst_addr, IpProtocol::Tcp, 64);
    }

    #[cfg(feature = "ipv4")]
    fn process_icmpv4(&mut self, iface: IfaceHandle, src_addr: Ipv4Address, dst_addr: Ipv4Address, mut buf: PacketBuf) {
        let mut icmp_packet = check!(Icmpv4Packet::new_checked(&mut buf));
        if self.ifaces.get(iface.index()).checksum_caps().icmpv4.rx() && !icmp_packet.verify_checksum() {
            trace!("icmpv4: checksum incorrect");
            return;
        }

        #[cfg(not(feature = "icmp-ping-reply"))]
        let _ = (iface, src_addr, dst_addr);
        #[cfg(not(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp"))))]
        let _ = &mut icmp_packet;

        match (icmp_packet.msg_type(), icmp_packet.msg_code()) {
            // Respond to echo requests.
            #[cfg(feature = "icmp-ping-reply")]
            (Icmpv4Message::EchoRequest, 0) => {
                let reply_src = {
                    let iface = self.ifaces.get(iface.index());
                    // Do not send ICMP replies to non-unicast sources.
                    if !iface.is_unicast_v4(src_addr) {
                        return;
                    }
                    // Reply as normal when src_addr and dst_addr are both unicast; only
                    // reply to broadcasts for echo replies and not other ICMP messages.
                    let dst_is_broadcast = iface.is_broadcast_v4(dst_addr);
                    if dst_addr.x_is_unicast() && !dst_is_broadcast {
                        dst_addr
                    } else if dst_is_broadcast {
                        match iface.ipv4_addr() {
                            Some(addr) => addr,
                            None => return,
                        }
                    } else {
                        return;
                    }
                };

                // Route first: the reply's checksum is the egress interface's to
                // compute, and that interface is not necessarily the arrival one.
                let Some((route, checksum_caps)) = self.route_reply(iface, &IpAddress::Ipv4(src_addr)) else {
                    return;
                };

                // The reply is the request with the message type changed: ident, seq
                // and payload stay put. Reuse the incoming buffer instead of
                // allocating one and copying the payload over.
                if !buf.ensure_headroom(LINK_HEADER_LEN + IPV4_HEADER_LEN) {
                    trace!("icmpv4: not enough headroom for echo reply");
                    return;
                }
                buf.set_meta(crate::driver::PacketMeta::default());
                {
                    let mut reply_icmp = Icmpv4Packet::new_unchecked(&mut buf);
                    reply_icmp.set_msg_type(Icmpv4Message::EchoReply);
                    if checksum_caps.icmpv4.tx() {
                        reply_icmp.fill_checksum();
                    } else {
                        reply_icmp.set_checksum(0);
                    }
                }
                self.transmit_reply(
                    &route,
                    buf,
                    IpAddress::Ipv4(reply_src),
                    IpAddress::Ipv4(src_addr),
                    IpProtocol::Icmp,
                    64,
                );
            }

            // Ignore any echo replies.
            (Icmpv4Message::EchoReply, _) => {}

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
            (msg_type, msg_code) if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
                    self.deliver_icmp_error(error, icmp_packet.data_mut());
                }
            }

            _ => {}
        }
    }

    /// Deliver an ICMP error message to the socket whose packet provoked it.
    ///
    /// `quote` is the offending packet quoted in the error, a packet *we sent*, so
    /// its source identifies the socket's local endpoint and its destination the
    /// remote. UDP demux scores the sockets like ordinary ingress (most specific
    /// match wins). TCP demux is by exact 4-tuple, and the socket additionally
    /// validates the quoted sequence number against its send window, so blindly
    /// spoofed errors cannot reset connections (RFC 5927).
    #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
    fn deliver_icmp_error(&mut self, error: IcmpError, quote: &mut [u8]) {
        let Some(quoted) = parse_quoted_packet(quote) else {
            trace!("icmp error: quote too short to identify a flow, ignoring");
            return;
        };
        let local = IpEndpoint::new(quoted.src_addr, quoted.src_port);
        let remote = IpEndpoint::new(quoted.dst_addr, quoted.dst_port);
        match quoted.protocol {
            #[cfg(feature = "udp")]
            IpProtocol::Udp => crate::udp::process_icmp_error(&mut self.sockets.udp, error, local, remote),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => {
                crate::tcp::process_icmp_error(&mut self.sockets.tcp, error, local, remote, quoted.tcp_seq)
            }
            _ => {}
        }
    }

    /// `ll_src` is the link-layer source address of the frame the packet arrived
    /// in, `None` on a medium without link-layer addresses.
    #[cfg(feature = "ipv6")]
    pub(crate) fn process_ipv6(&mut self, iface: IfaceHandle, ll_src: Option<HardwareAddress>, mut buf: PacketBuf) {
        let ipv6_packet = check!(Ipv6Packet::new_checked(&mut buf));

        if ipv6_packet.version() != 6 {
            return;
        }

        let src_addr = ipv6_packet.src_addr();
        let dst_addr = ipv6_packet.dst_addr();
        let hop_limit = ipv6_packet.hop_limit();
        let next_header = ipv6_packet.next_header();
        let payload_len = ipv6_packet.payload_len() as usize;

        if !src_addr.x_is_unicast() {
            // Discard packets with non-unicast source addresses.
            debug!("non-unicast source address");
            return;
        }

        {
            let iface = self.ifaces.get(iface.index());
            if !iface.has_ip_addr(dst_addr) && !iface.has_multicast_group(dst_addr) && !dst_addr.is_loopback() {
                trace!("Rejecting IPv6 packet; not for us");
                return;
            }

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            if let Some(ll_src) = ll_src
                && dst_addr.x_is_unicast()
            {
                self.inner.neighbor_cache.reset_expiry_if_existing(
                    (iface.handle, IpAddress::Ipv6(src_addr)),
                    ll_src,
                    self.inner.now,
                );
            }
        }

        // Strip any trailing padding added by the link layer.
        buf.set_len(IPV6_HEADER_LEN + payload_len);

        // Hop-by-hop options (RFC 8200 §4.3): walk the options, then continue at the
        // upper-layer header behind the extension header. `l4_offset` is where that
        // header starts, `nh_offset` is the offset of the field naming it, quoted in
        // the "unrecognized next header" error pointer.
        let (next_header, l4_offset, nh_offset) = if next_header == IpProtocol::HopByHop {
            match check!(process_hop_by_hop(&buf[IPV6_HEADER_LEN..])) {
                HopByHopAction::Continue { next_header, ext_len } => {
                    (next_header, IPV6_HEADER_LEN + ext_len, IPV6_HEADER_LEN)
                }
                HopByHopAction::Discard => return,
                HopByHopAction::DiscardSendError {
                    pointer,
                    allow_multicast_dst,
                } => {
                    self.transmit_icmpv6_error(
                        iface,
                        &mut buf,
                        Icmpv6Message::ParamProblem,
                        Icmpv6ParamProblem::UnrecognizedOption.into(),
                        pointer,
                        allow_multicast_dst,
                    );
                    return;
                }
            }
        } else {
            // 6 is the offset of the fixed header's next header field.
            (next_header, IPV6_HEADER_LEN, 6)
        };

        // Offer the whole packet to IP-mode raw sockets. Protocols the stack itself
        // processes are copied to the socket, everything else is consumed by it.
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(feature = "raw-ip")]
        let Some((mut buf, handled_by_raw)) = ({
            let stack_wants = matches!(next_header, IpProtocol::Icmpv6 | IpProtocol::Udp | IpProtocol::Tcp);
            self.process_raw_ip(iface, IpVersion::Ipv6, next_header, stack_wants, buf)
        }) else {
            return;
        };
        #[cfg_attr(not(feature = "udp"), allow(unused_variables))]
        #[cfg(not(feature = "raw-ip"))]
        let handled_by_raw = false;

        // Strip the IP header (and any extension headers).
        buf.pull_front(l4_offset);

        match next_header {
            IpProtocol::Icmpv6 => self.process_icmpv6(iface, ll_src, src_addr, dst_addr, hop_limit, buf),
            #[cfg(feature = "udp")]
            IpProtocol::Udp => self.process_udp(
                iface,
                IpAddress::Ipv6(src_addr),
                IpAddress::Ipv6(dst_addr),
                l4_offset,
                handled_by_raw,
                buf,
            ),
            #[cfg(feature = "tcp")]
            IpProtocol::Tcp => self.process_tcp(iface, IpAddress::Ipv6(src_addr), IpAddress::Ipv6(dst_addr), buf),
            _ => {
                trace!("ipv6: protocol {} not supported", next_header);
                // ICMPv6 parameter problem, unrecognized next header (RFC 4443
                // §3.4): restore the headers so the whole offending packet can be
                // quoted. The pointer names the next header field that held the
                // unrecognized value.
                buf.push_front(l4_offset);
                self.transmit_icmpv6_error(
                    iface,
                    &mut buf,
                    Icmpv6Message::ParamProblem,
                    Icmpv6ParamProblem::UnrecognizedNxtHdr.into(),
                    nh_offset as u32,
                    false,
                );
            }
        }
    }

    #[cfg(feature = "ipv6")]
    fn process_icmpv6(
        &mut self,
        iface: IfaceHandle,
        ll_src: Option<HardwareAddress>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        hop_limit: u8,
        mut buf: PacketBuf,
    ) {
        #[cfg(not(any(feature = "medium-ethernet", feature = "medium-ieee802154")))]
        let _ = (ll_src, hop_limit);
        #[cfg(not(feature = "icmp-ping-reply"))]
        let _ = iface;

        let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
        if self.ifaces.get(iface.index()).checksum_caps().icmpv6.rx()
            && !icmp_packet.verify_checksum(&src_addr, &dst_addr)
        {
            trace!("icmpv6: checksum incorrect");
            return;
        }

        #[cfg(not(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp"))))]
        let _ = &mut icmp_packet;

        match icmp_packet.msg_type() {
            // Respond to echo requests.
            #[cfg(feature = "icmp-ping-reply")]
            Icmpv6Message::EchoRequest => {
                let reply_src = if dst_addr.x_is_unicast() {
                    dst_addr
                } else {
                    self.ifaces
                        .get(iface.index())
                        .get_source_address_ipv6(&src_addr, self.inner.now)
                };

                // Route first: the reply's checksum is the egress interface's to
                // compute, and that interface is not necessarily the arrival one.
                let Some((route, checksum_caps)) = self.route_reply(iface, &IpAddress::Ipv6(src_addr)) else {
                    return;
                };

                // The reply is the request with the message type changed: ident, seq
                // and payload stay put. Reuse the incoming buffer instead of
                // allocating one and copying the payload over.
                if !buf.ensure_headroom(LINK_HEADER_LEN + IPV6_HEADER_LEN) {
                    trace!("icmpv6: not enough headroom for echo reply");
                    return;
                }
                buf.set_meta(crate::driver::PacketMeta::default());
                {
                    let mut reply_icmp = Icmpv6Packet::new_unchecked(&mut buf);
                    reply_icmp.set_msg_type(Icmpv6Message::EchoReply);
                    if checksum_caps.icmpv6.tx() {
                        reply_icmp.fill_checksum(&reply_src, &src_addr);
                    } else {
                        reply_icmp.set_checksum(0);
                    }
                }
                self.transmit_reply(
                    &route,
                    buf,
                    IpAddress::Ipv6(reply_src),
                    IpAddress::Ipv6(src_addr),
                    IpProtocol::Icmpv6,
                    64,
                );
            }

            // Ignore any echo replies.
            Icmpv6Message::EchoReply => {}

            // Deliver error messages to the socket whose packet provoked them.
            #[cfg(all(feature = "icmp-errors", any(feature = "udp", feature = "tcp")))]
            msg_type if msg_type.is_error() => {
                if let Some(error) = IcmpError::from_icmpv6(msg_type, icmp_packet.msg_code()) {
                    self.deliver_icmp_error(error, icmp_packet.payload_mut());
                }
            }

            // NDISC is only processed if the packet arrived with the un-decremented
            // hop limit, and only on mediums with link-layer addresses.
            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Message::NeighborSolicit if hop_limit == 0xff && ll_src.is_some() => self
                .inner
                .process_ndisc_solicit(self.ifaces.get_mut(iface.index()), src_addr, dst_addr, &mut icmp_packet),

            #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
            Icmpv6Message::NeighborAdvert if hop_limit == 0xff && ll_src.is_some() => {
                self.inner
                    .process_ndisc_advert(self.ifaces.get_mut(iface.index()), src_addr, &mut icmp_packet)
            }

            // [RFC 3810 § 6.2], reception checks
            #[cfg(feature = "multicast")]
            Icmpv6Message::MldQuery if hop_limit == 1 && src_addr.is_link_local() => self
                .ifaces
                .get_mut(iface.index())
                .process_mldv2(&mut self.inner, dst_addr, &icmp_packet),

            // RFC 4861 §6.1.2: a router advertisement is only valid from a link-local
            // source, with the un-decremented hop limit.
            #[cfg(feature = "slaac")]
            Icmpv6Message::RouterAdvert
                if hop_limit == 0xff
                    && ll_src.is_some()
                    && src_addr.is_link_local()
                    && (dst_addr == IPV6_LINK_LOCAL_ALL_NODES || dst_addr.is_link_local()) =>
            {
                self.ifaces.get_mut(iface.index()).slaac_process_advertisement(
                    &mut self.inner,
                    src_addr,
                    &mut icmp_packet,
                )
            }

            _ => {}
        }
    }

    /// Advance the solicitation retransmission timers of the neighbors being resolved
    /// on this interface, retransmitting solicitations and failing resolutions that
    /// exhausted their probes.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn poll_neighbor_timers(&mut self, iface: IfaceHandle) {
        let mut cursor = 0;
        while let Some(event) = self
            .inner
            .neighbor_cache
            .poll_retransmit(iface, self.inner.now, &mut cursor)
        {
            match event {
                ProbeEvent::Retransmit(addr) => {
                    debug!("neighbor {} still unresolved, retransmitting solicitation", addr);
                    self.inner.solicit_neighbor(self.ifaces.get_mut(iface.index()), addr);
                }
                ProbeEvent::Failed(addr) => {
                    debug!("neighbor {} resolution failed, dropping queued packets", addr);
                    // RFC 4861 §7.3.3: answer each packet queued on the failed
                    // resolution with an ICMP destination unreachable error.
                    #[cfg(feature = "icmp-errors")]
                    while let Some(packet) = self.inner.pending.pop_matching(&(iface, addr)) {
                        self.deliver_neighbor_failure_error(iface, packet.buf);
                    }
                    #[cfg(not(feature = "icmp-errors"))]
                    while self.inner.pending.pop_matching(&(iface, addr)).is_some() {}
                }
            }
        }
    }

    /// Build an ICMP destination unreachable error for a packet whose neighbor
    /// resolution failed, and deliver it back through local ingress processing.
    ///
    /// Queued packets are locally generated (nothing is forwarded), so the sender
    /// the error must reach is a local socket. The error is fed into ingress,
    /// where the erring TCP/UDP socket, or a raw-socket ping application,
    /// receives it, rather than transmitted to the wire. `orig` is the queued
    /// packet, a whole IP frame.
    #[cfg(all(
        any(feature = "medium-ethernet", feature = "medium-ieee802154"),
        feature = "icmp-errors"
    ))]
    fn deliver_neighbor_failure_error(&mut self, iface: IfaceHandle, mut orig: PacketBuf) {
        match IpVersion::of_packet(&orig) {
            #[cfg(feature = "ipv4")]
            Ok(IpVersion::Ipv4) => {
                let (src_addr, header_len, next_header) = {
                    let packet = Ipv4Packet::new_unchecked(&mut orig);
                    (packet.src_addr(), packet.header_len() as usize, packet.next_header())
                };
                // Never generate an ICMP error about an ICMP error (RFC 1122 §3.2.2).
                if next_header == IpProtocol::Icmp
                    && orig.get(header_len).is_some_and(|&t| Icmpv4Message::from(t).is_error())
                {
                    return;
                }
                let reply_src = {
                    let iface = self.ifaces.get(iface.index());
                    if !iface.is_unicast_v4(src_addr) {
                        return;
                    }
                    match iface.get_source_address_ipv4(&src_addr) {
                        Some(addr) => addr,
                        None => return,
                    }
                };
                // The error is fed back through local ingress processing rather
                // than transmitted, so no device is going to fill its checksums in.
                let checksum_caps = ChecksumCapabilities::default();
                let Some(mut reply) = build_icmpv4_error(
                    &orig,
                    Icmpv4Message::DstUnreachable,
                    Icmpv4DstUnreachable::HostUnreachable.into(),
                    &checksum_caps,
                ) else {
                    return;
                };
                push_ipv4_header(&mut reply, reply_src, src_addr, IpProtocol::Icmp, 64, &checksum_caps);
                self.process_ipv4(iface, None, reply);
            }
            #[cfg(feature = "ipv6")]
            Ok(IpVersion::Ipv6) => {
                let (src_addr, next_header) = {
                    let packet = Ipv6Packet::new_unchecked(&mut orig);
                    (packet.src_addr(), packet.next_header())
                };
                // Never generate an ICMP error about an ICMP error (RFC 4443 §2.4).
                if next_header == IpProtocol::Icmpv6
                    && orig
                        .get(IPV6_HEADER_LEN)
                        .is_some_and(|&t| Icmpv6Message::from(t).is_error())
                {
                    return;
                }
                if !src_addr.x_is_unicast() {
                    return;
                }
                let reply_src = self
                    .ifaces
                    .get(iface.index())
                    .get_source_address_ipv6(&src_addr, self.inner.now);
                // The error is fed back through local ingress processing rather
                // than transmitted, so no device is going to fill its checksums in.
                let Some(mut reply) = build_icmpv6_error(
                    &orig,
                    &reply_src,
                    &src_addr,
                    Icmpv6Message::DstUnreachable,
                    Icmpv6DstUnreachable::AddrUnreachable.into(),
                    0,
                    &ChecksumCapabilities::default(),
                ) else {
                    return;
                };
                push_ipv6_header(&mut reply, reply_src, src_addr, IpProtocol::Icmpv6, 64);
                self.process_ipv6(iface, None, reply);
            }
            Err(_) => {}
        }
    }

    /// Transmit an ICMPv4 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are only sent when both the source and the destination of the
    /// offending packet are unicast (RFC 1122 §3.2.2): none about broadcast or
    /// multicast traffic, and none to non-unicast senders.
    #[cfg(feature = "ipv4")]
    pub(crate) fn transmit_icmpv4_error(
        &mut self,
        iface: IfaceHandle,
        orig: &mut PacketBuf,
        msg_type: Icmpv4Message,
        msg_code: u8,
    ) {
        let (src_addr, dst_addr) = {
            let packet = Ipv4Packet::new_unchecked(orig);
            (packet.src_addr(), packet.dst_addr())
        };
        {
            let iface = self.ifaces.get(iface.index());
            if !iface.is_unicast_v4(src_addr) || !iface.is_unicast_v4(dst_addr) {
                return;
            }
        }
        let Some((route, checksum_caps)) = self.route_reply(iface, &IpAddress::Ipv4(src_addr)) else {
            return;
        };
        let Some(reply) = build_icmpv4_error(orig, msg_type, msg_code, &checksum_caps) else {
            return;
        };
        self.transmit_reply(
            &route,
            reply,
            IpAddress::Ipv4(dst_addr),
            IpAddress::Ipv4(src_addr),
            IpProtocol::Icmp,
            64,
        );
    }

    /// Transmit an ICMPv6 error message in reply to the ingress packet in `orig`
    /// (a whole IP packet, starting at the IP header, quoted in the error).
    ///
    /// Errors are never sent to non-unicast sources, nor about multicast-destined
    /// packets (RFC 4443 §2.4). The exception is an unrecognized hop-by-hop option
    /// whose type demands the error even then (`allow_multicast_dst`).
    #[cfg(feature = "ipv6")]
    pub(crate) fn transmit_icmpv6_error(
        &mut self,
        iface: IfaceHandle,
        orig: &mut PacketBuf,
        msg_type: Icmpv6Message,
        msg_code: u8,
        pointer: u32,
        allow_multicast_dst: bool,
    ) {
        let (src_addr, dst_addr) = {
            let packet = Ipv6Packet::new_unchecked(orig);
            (packet.src_addr(), packet.dst_addr())
        };
        if !src_addr.x_is_unicast() {
            return;
        }
        if dst_addr.is_multicast() && !allow_multicast_dst {
            return;
        }
        let reply_src = if dst_addr.x_is_unicast() {
            dst_addr
        } else {
            self.ifaces
                .get(iface.index())
                .get_source_address_ipv6(&src_addr, self.inner.now)
        };
        let Some((route, checksum_caps)) = self.route_reply(iface, &IpAddress::Ipv6(src_addr)) else {
            return;
        };
        let Some(reply) = build_icmpv6_error(orig, &reply_src, &src_addr, msg_type, msg_code, pointer, &checksum_caps)
        else {
            return;
        };
        self.transmit_reply(
            &route,
            reply,
            IpAddress::Ipv6(reply_src),
            IpAddress::Ipv6(src_addr),
            IpProtocol::Icmpv6,
            64,
        );
    }

    /// Route a locally-generated reply to an ingress packet that arrived on
    /// `arrival`, and report which checksums its egress interface computes.
    ///
    /// Replies are routed like any other egress ([`TxContext::route_reply`]), so
    /// they may leave a different interface than the packet came in on, and it is
    /// that interface, not the arrival one, whose checksum capabilities the reply
    /// is built with. Routing therefore comes before building. `None` if there is
    /// no route to the destination, in which case the reply is dropped.
    fn route_reply(
        &mut self,
        arrival: IfaceHandle,
        dst_addr: &IpAddress,
    ) -> Option<(EgressRoute, ChecksumCapabilities)> {
        let route = match self.tx_context().route_reply(arrival, dst_addr) {
            Some(route) => route,
            None => {
                debug!("no route to {}, dropping reply", dst_addr);
                return None;
            }
        };
        let checksum_caps = self.ifaces.get(route.iface.index()).checksum_caps();
        Some((route, checksum_caps))
    }

    /// Transmit a locally-generated reply, routed by [`route_reply`](Self::route_reply).
    fn transmit_reply(
        &mut self,
        route: &EgressRoute,
        buf: PacketBuf,
        src_addr: IpAddress,
        dst_addr: IpAddress,
        next_header: IpProtocol,
        hop_limit: u8,
    ) {
        self.tx_context()
            .transmit_ip(route, buf, src_addr, dst_addr, next_header, hop_limit);
    }
}

// The link-level machinery: ARP and NDISC, the neighbor cache, and frame
// transmission. These are `StackInner` methods operating on one interface,
// because they serve both ingress (above) and socket egress (`TxContext`).
impl StackInner {
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    fn process_arp(&mut self, iface: &mut IfaceState<'_>, mut buf: PacketBuf) {
        let arp_packet = check!(ArpPacket::new_checked(&mut buf));

        if arp_packet.hardware_type() != ArpHardware::Ethernet
            || arp_packet.protocol_type() != EthernetProtocol::Ipv4
            || arp_packet.hardware_len() != 6
            || arp_packet.protocol_len() != 4
        {
            return;
        }

        let operation = arp_packet.operation();
        let source_hardware_addr = EthernetAddress::from_bytes(arp_packet.source_hardware_addr());
        let source_protocol_addr = Ipv4Address::from(<[u8; 4]>::try_from(arp_packet.source_protocol_addr()).unwrap());
        let target_protocol_addr = Ipv4Address::from(<[u8; 4]>::try_from(arp_packet.target_protocol_addr()).unwrap());

        // Only process ARP packets for us.
        if !iface.has_ip_addr(target_protocol_addr) {
            return;
        }

        // Only process REQUEST and RESPONSE.
        if !matches!(operation, ArpOperation::Request | ArpOperation::Reply) {
            debug!("arp: unknown operation code");
            return;
        }

        // Discard packets with non-unicast source addresses.
        if !source_protocol_addr.x_is_unicast() || !source_hardware_addr.is_unicast() {
            debug!("arp: non-unicast source address");
            return;
        }

        if !iface.in_same_network(&IpAddress::Ipv4(source_protocol_addr)) {
            debug!("arp: source IP address not in same network as us");
            return;
        }

        // Fill the ARP cache from any ARP packet aimed at us (both request or response).
        // We fill from requests too because if someone is requesting our address they
        // are probably going to talk to us, so we avoid having to request their address
        // when we later reply to them.
        self.fill_neighbor(
            iface,
            IpAddress::Ipv4(source_protocol_addr),
            HardwareAddress::Ethernet(source_hardware_addr),
        );

        if operation == ArpOperation::Request {
            let Some(mut reply) = PacketBuf::try_new() else {
                trace!("arp: no packet buffer for reply");
                return;
            };
            reply.reserve(ETHERNET_HEADER_LEN);
            reply.set_len(ARP_BUFFER_LEN);
            {
                let mut arp_reply = ArpPacket::new_unchecked(&mut reply);
                arp_reply.set_hardware_type(ArpHardware::Ethernet);
                arp_reply.set_protocol_type(EthernetProtocol::Ipv4);
                arp_reply.set_hardware_len(6);
                arp_reply.set_protocol_len(4);
                arp_reply.set_operation(ArpOperation::Reply);
                arp_reply.set_source_hardware_addr(iface.ethernet_addr().as_bytes());
                arp_reply.set_source_protocol_addr(&target_protocol_addr.octets());
                arp_reply.set_target_hardware_addr(source_hardware_addr.as_bytes());
                arp_reply.set_target_protocol_addr(&source_protocol_addr.octets());
            }
            self.transmit_ethernet(iface, source_hardware_addr, reply, EthernetProtocol::Arp);
        }
    }

    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    fn process_ndisc_solicit(
        &mut self,
        iface: &mut IfaceState<'_>,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let target_addr = icmp_packet.target_addr();
        let lladdr = check!(ndisc_lladdr_option(icmp_packet, NdiscOptionType::SourceLinkLayerAddr));

        if let Some(lladdr) = lladdr {
            let lladdr = check!(lladdr.parse(iface.medium()));
            if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
                return;
            }
            self.fill_neighbor(iface, IpAddress::Ipv6(src_addr), lladdr);
        }

        // RFC 4861 §7.2.3: the destination is either the target's solicited-node
        // multicast (address resolution) or one of our unicast addresses (a
        // unicast NUD probe). Answer both.
        if (iface.has_solicited_node(dst_addr) || iface.has_ip_addr(dst_addr)) && iface.has_ip_addr(target_addr) {
            // Neighbor advert: NA header (24 bytes) plus the target link-layer
            // address option.
            let Some(mut reply) = PacketBuf::try_new() else {
                trace!("ndisc: no packet buffer for neighbor advert");
                return;
            };
            let opt_len = lladdr_option_len(iface.hardware_addr);
            reply.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
            reply.set_len(24 + opt_len);
            {
                let mut na = Icmpv6Packet::new_unchecked(&mut reply);
                na.set_msg_type(Icmpv6Message::NeighborAdvert);
                na.set_msg_code(0);
                na.clear_reserved();
                na.set_neighbor_flags(NdiscNeighborFlags::SOLICITED);
                na.set_target_addr(target_addr);
                write_lladdr_option(
                    na.payload_mut(),
                    NdiscOptionType::TargetLinkLayerAddr,
                    iface.hardware_addr,
                );
                if iface.checksum_caps().icmpv6.tx() {
                    na.fill_checksum(&target_addr, &src_addr);
                } else {
                    na.set_checksum(0);
                }
            }
            self.transmit_ndisc(iface, reply, target_addr, src_addr);
        }
    }

    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    fn process_ndisc_advert(
        &mut self,
        iface: &mut IfaceState<'_>,
        src_addr: Ipv6Address,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let flags = icmp_packet.neighbor_flags();
        let target_addr = icmp_packet.target_addr();
        let lladdr = check!(ndisc_lladdr_option(icmp_packet, NdiscOptionType::TargetLinkLayerAddr));

        let ip_addr = IpAddress::Ipv6(src_addr);
        if let Some(lladdr) = lladdr {
            let lladdr = check!(lladdr.parse(iface.medium()));
            if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
                return;
            }
            if flags.contains(NdiscNeighborFlags::OVERRIDE)
                || !self.neighbor_cache.lookup(&(iface.handle, ip_addr), self.now).found()
            {
                self.fill_neighbor(iface, ip_addr, lladdr)
            }
        }
    }

    /// Send a solicitation (ARP request / NDISC neighbor solicit) for the given address.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn solicit_neighbor(&mut self, iface: &mut IfaceState<'_>, addr: IpAddress) {
        match addr {
            #[cfg(all(feature = "ipv4", feature = "medium-ethernet"))]
            IpAddress::Ipv4(addr) => self.transmit_arp_request(iface, addr),
            // IPv4 is never dispatched to an 802.15.4 interface (`dispatch_ip`),
            // so no IPv4 resolution ever starts without Ethernet.
            #[cfg(all(feature = "ipv4", not(feature = "medium-ethernet")))]
            IpAddress::Ipv4(_) => unreachable!(),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(addr) => self.transmit_ndisc_solicit(iface, addr),
        }
    }

    /// Fill the neighbor cache, and flush any packets that were queued waiting for
    /// this neighbor to resolve.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub(crate) fn fill_neighbor(
        &mut self,
        iface: &mut IfaceState<'_>,
        addr: IpAddress,
        hardware_addr: HardwareAddress,
    ) {
        let key = (iface.handle, addr);
        self.neighbor_cache.fill(key, hardware_addr, self.now);
        self.flush_pending(iface, &key, hardware_addr);
    }

    /// Transmit the packets parked on `key`, now resolved to `hardware_addr`, in
    /// FIFO order, for as long as the device has room. The rest stay parked, and
    /// `flush_resolved_pending` retries them on the next `poll`.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn flush_pending(&mut self, iface: &mut IfaceState<'_>, key: &NeighborKey, hardware_addr: HardwareAddress) {
        while self.pending.has_matching(key) {
            if !iface.can_transmit_new_packet() {
                trace!("neighbor: device has no room, {} stays parked", key.1);
                return;
            }
            // NOTE(unwrap): checked by `has_matching` above.
            let packet = unwrap!(self.pending.pop_matching(key));
            trace!("neighbor: {} resolved, flushing queued packet", key.1);
            self.transmit_link(iface, hardware_addr, packet.buf, packet.key.1);
        }
    }

    /// Hand an IP packet whose next hop resolved to `hardware_addr` to the
    /// link layer of the interface's medium. `dst_addr` names the IP version.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn transmit_link(
        &mut self,
        iface: &mut IfaceState<'_>,
        hardware_addr: HardwareAddress,
        buf: PacketBuf,
        dst_addr: IpAddress,
    ) {
        #[cfg(not(feature = "medium-ethernet"))]
        let _ = dst_addr;
        match hardware_addr {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(hardware_addr) => {
                let ethertype = match dst_addr {
                    #[cfg(feature = "ipv4")]
                    IpAddress::Ipv4(_) => EthernetProtocol::Ipv4,
                    #[cfg(feature = "ipv6")]
                    IpAddress::Ipv6(_) => EthernetProtocol::Ipv6,
                };
                self.transmit_ethernet(iface, hardware_addr, buf, ethertype)
            }
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(hardware_addr) => self.dispatch_ieee802154(iface, hardware_addr, buf),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => unreachable!(),
        }
    }

    /// Retry the packets parked on this interface whose neighbor is resolved:
    /// they were left parked because the device had no room when the
    /// resolution came in.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    pub(crate) fn flush_resolved_pending(&mut self, iface: &mut IfaceState<'_>) {
        let mut cursor = 0;
        while let Some((index, key)) = self.pending.next_on(iface.handle, cursor) {
            match self.neighbor_cache.lookup(&key, self.now) {
                NeighborAnswer::Found(hardware_addr) => {
                    self.flush_pending(iface, &key, hardware_addr);
                    if self.pending.has_matching(&key) {
                        // Out of room. Everything else waits too.
                        return;
                    }
                    // Every packet on `key` is gone, so what came after the one
                    // at `index` is at `index` now.
                    cursor = index;
                }
                _ => cursor = index + 1,
            }
        }
    }

    /// Look up the destination hardware address for an egress packet, sending a
    /// solicitation (ARP request / NDISC neighbor solicit) if it is not resolved yet.
    ///
    /// `next_hop` is the pre-routed address to resolve on the link, from an
    /// [`EgressRoute`].
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn lookup_hardware_addr(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: &IpAddress,
        next_hop: IpAddress,
    ) -> NeighborLookup {
        if iface.is_broadcast(dst_addr) {
            let hardware_addr = match iface.medium() {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress::BROADCAST),
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };
            return NeighborLookup::Found(hardware_addr);
        }

        if dst_addr.is_multicast() {
            let hardware_addr = match iface.medium() {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => HardwareAddress::Ethernet(match *dst_addr {
                    #[cfg(feature = "ipv4")]
                    IpAddress::Ipv4(addr) => {
                        let b = addr.octets();
                        EthernetAddress::from_bytes(&[0x01, 0x00, 0x5e, b[1] & 0x7F, b[2], b[3]])
                    }
                    #[cfg(feature = "ipv6")]
                    IpAddress::Ipv6(addr) => {
                        let b = addr.octets();
                        EthernetAddress::from_bytes(&[0x33, 0x33, b[12], b[13], b[14], b[15]])
                    }
                }),
                // RFC 4944 §9: IPv6 multicast is broadcast on the link.
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::BROADCAST),
                #[cfg(feature = "medium-ip")]
                Medium::Ip => unreachable!(),
            };

            return NeighborLookup::Found(hardware_addr);
        }

        match self.neighbor_cache.lookup(&(iface.handle, next_hop), self.now) {
            NeighborAnswer::Found(hardware_addr) => return NeighborLookup::Found(hardware_addr),
            // Resolution is already in progress; the retransmission timer owns
            // any further solicitations.
            NeighborAnswer::Pending => return NeighborLookup::Pending { next_hop },
            NeighborAnswer::NotFound => {}
        }

        // Start resolving: create the INCOMPLETE entry and send the first solicitation.
        debug!("address {} not in neighbor cache, sending solicitation", next_hop);
        self.neighbor_cache.start_resolution((iface.handle, next_hop), self.now);
        self.solicit_neighbor(iface, next_hop);

        NeighborLookup::Pending { next_hop }
    }

    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    fn transmit_arp_request(&mut self, iface: &mut IfaceState<'_>, target_addr: Ipv4Address) {
        let Some(source_protocol_addr) = iface.get_source_address_ipv4(&target_addr) else {
            debug!("arp: no source address for request");
            return;
        };

        let Some(mut buf) = PacketBuf::try_new() else {
            // The retransmission timer sends the next one.
            trace!("arp: no packet buffer for request");
            return;
        };
        buf.reserve(ETHERNET_HEADER_LEN);
        buf.set_len(ARP_BUFFER_LEN);
        {
            let mut arp_packet = ArpPacket::new_unchecked(&mut buf);
            arp_packet.set_hardware_type(ArpHardware::Ethernet);
            arp_packet.set_protocol_type(EthernetProtocol::Ipv4);
            arp_packet.set_hardware_len(6);
            arp_packet.set_protocol_len(4);
            arp_packet.set_operation(ArpOperation::Request);
            arp_packet.set_source_hardware_addr(iface.ethernet_addr().as_bytes());
            arp_packet.set_source_protocol_addr(&source_protocol_addr.octets());
            arp_packet.set_target_hardware_addr(EthernetAddress::BROADCAST.as_bytes());
            arp_packet.set_target_protocol_addr(&target_addr.octets());
        }
        self.transmit_ethernet(iface, EthernetAddress::BROADCAST, buf, EthernetProtocol::Arp);
    }

    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    fn transmit_ndisc_solicit(&mut self, iface: &mut IfaceState<'_>, target_addr: Ipv6Address) {
        let src_addr = iface.get_source_address_ipv6(&target_addr, self.now);
        let dst_addr = target_addr.solicited_node();

        // Neighbor solicit: NS header (24 bytes) plus the source link-layer
        // address option.
        let Some(mut buf) = PacketBuf::try_new() else {
            // The retransmission timer sends the next one.
            trace!("ndisc: no packet buffer for neighbor solicit");
            return;
        };
        let opt_len = lladdr_option_len(iface.hardware_addr);
        buf.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
        buf.set_len(24 + opt_len);
        {
            let mut ns = Icmpv6Packet::new_unchecked(&mut buf);
            ns.set_msg_type(Icmpv6Message::NeighborSolicit);
            ns.set_msg_code(0);
            ns.clear_reserved();
            ns.set_target_addr(target_addr);
            write_lladdr_option(
                ns.payload_mut(),
                NdiscOptionType::SourceLinkLayerAddr,
                iface.hardware_addr,
            );
            if iface.checksum_caps().icmpv6.tx() {
                ns.fill_checksum(&src_addr, &dst_addr);
            } else {
                ns.set_checksum(0);
            }
        }
        // The solicited-node destination is multicast, so this never recurses back
        // into neighbor resolution.
        self.transmit_ndisc(iface, buf, src_addr, dst_addr);
    }

    /// Transmit an NDISC message on the given interface.
    ///
    /// NDISC is link-scoped: the packet is never routed, and the next hop is the
    /// destination itself (an on-link neighbor or a multicast group).
    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    pub(crate) fn transmit_ndisc(
        &mut self,
        iface: &mut IfaceState<'_>,
        mut buf: PacketBuf,
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) {
        push_ipv6_header(&mut buf, src_addr, dst_addr, IpProtocol::Icmpv6, 0xff);
        self.transmit_ip(
            iface,
            IpAddress::Ipv6(dst_addr),
            IpAddress::Ipv6(dst_addr),
            buf,
            EthernetProtocol::Ipv6,
        );
    }

    /// Transmit a fully-built IP packet, resolving the destination hardware address
    /// on Ethernet mediums.
    ///
    /// `next_hop` is the pre-routed address to resolve on the link, from an
    /// [`EgressRoute`].
    ///
    /// If the neighbor is not resolved yet, the packet is queued in the interface's
    /// pending queue and flushed when resolution completes.
    /// Transmit a fully-built UDP packet on a given interface as an IPv4 packet from
    /// `src_addr` to `dst_addr`, bypassing routing and source address checks.
    ///
    /// This is how the DHCP client sends from `0.0.0.0` to broadcast on an interface
    /// that has no address yet. A unicast destination that is not on-link is sent
    /// via the routing table's gateway, if any, else directly.
    #[cfg(feature = "dhcpv4")]
    pub(crate) fn transmit_ipv4_on(
        &mut self,
        iface: &mut IfaceState<'_>,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        mut buf: PacketBuf,
    ) {
        push_ipv4_header(
            &mut buf,
            src_addr,
            dst_addr,
            IpProtocol::Udp,
            64,
            &iface.checksum_caps(),
        );
        let dst = IpAddress::Ipv4(dst_addr);
        let next_hop = if !dst.is_unicast() || iface.in_same_network(&dst) {
            dst
        } else {
            self.routes
                .lookup(IfaceBinding::Any, &dst, self.now)
                .map(|route| route.via_router)
                .unwrap_or(dst)
        };
        self.transmit_ip(iface, dst, next_hop, buf, EthernetProtocol::Ipv4);
    }

    /// Transmit a fully-built IP packet on an interface, fragmenting it first if it
    /// is larger than the interface's MTU (IPv4 only).
    pub(crate) fn transmit_ip(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: IpAddress,
        next_hop: IpAddress,
        buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        let total_ip_len = buf.len();

        if total_ip_len > iface.ip_mtu() {
            match ethertype {
                // If we have an IPv4 packet, then we need to check if we need to fragment it.
                #[cfg(feature = "ipv4-fragmentation")]
                EthernetProtocol::Ipv4 => self.fragment_ipv4(iface, dst_addr, next_hop, buf),
                #[cfg(not(feature = "ipv4-fragmentation"))]
                EthernetProtocol::Ipv4 => {
                    debug!("Enable the `ipv4-fragmentation` feature for fragmentation support. Dropping");
                }
                // We don't support IPv6 fragmentation yet.
                _ => {
                    debug!("IPv6 fragmentation support is unimplemented. Dropping.");
                }
            }
            return;
        }

        self.dispatch_ip(iface, dst_addr, next_hop, buf, ethertype)
    }

    /// Hand an IP packet that fits the interface's MTU to the link layer.
    pub(crate) fn dispatch_ip(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: IpAddress,
        next_hop: IpAddress,
        buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        #[cfg(not(any(feature = "medium-ethernet", feature = "medium-ieee802154")))]
        let _ = (dst_addr, next_hop, ethertype);
        #[cfg(not(feature = "medium-ethernet"))]
        let _ = ethertype;

        match iface.medium() {
            #[cfg(feature = "medium-ip")]
            Medium::Ip => self.transmit_raw(iface, buf),
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => match self.lookup_hardware_addr(iface, &dst_addr, next_hop) {
                NeighborLookup::Found(hardware_addr) => {
                    self.transmit_ethernet(iface, hardware_addr.ethernet_or_panic(), buf, ethertype)
                }
                NeighborLookup::Pending { next_hop } => {
                    debug!("neighbor {} pending, queing packet", next_hop);
                    self.pending.push((iface.handle, next_hop), buf, self.now);
                }
            },
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                // The medium is IPv6-only.
                #[cfg(feature = "ipv4")]
                if let IpAddress::Ipv4(_) = dst_addr {
                    debug!("dropping IPv4 packet routed to an IEEE 802.15.4 interface");
                    return;
                }
                match self.lookup_hardware_addr(iface, &dst_addr, next_hop) {
                    NeighborLookup::Found(hardware_addr) => {
                        self.dispatch_ieee802154(iface, hardware_addr.ieee802154_or_panic(), buf)
                    }
                    NeighborLookup::Pending { next_hop } => {
                        debug!("neighbor {} pending, queing packet", next_hop);
                        self.pending.push((iface.handle, next_hop), buf, self.now);
                    }
                }
            }
        }
    }

    #[cfg(feature = "medium-ethernet")]
    fn transmit_ethernet(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_hw: EthernetAddress,
        mut buf: PacketBuf,
        ethertype: EthernetProtocol,
    ) {
        buf.push_front(ETHERNET_HEADER_LEN);
        let mut frame = EthernetFrame::new_unchecked(&mut buf);
        frame.set_dst_addr(dst_hw);
        frame.set_src_addr(iface.ethernet_addr());
        frame.set_ethertype(ethertype);
        self.transmit_raw(iface, buf);
    }

    pub(crate) fn transmit_raw(&mut self, iface: &mut IfaceState<'_>, #[allow(unused_mut)] mut buf: PacketBuf) {
        #[cfg(feature = "packet-log")]
        {
            trace!("sent on iface {}", iface.handle.index());
            let medium = iface.medium();
            crate::packet_log::log_packet(&mut buf, packet_log_layer(medium));
        }
        if iface.driver.transmit(buf).is_err() {
            warn!("iface {}: device refused a frame, dropping it", iface.handle.index());
        }
    }
}

/// The outermost header of a frame on an interface of this medium.
#[cfg(feature = "packet-log")]
fn packet_log_layer(medium: Medium) -> crate::packet_log::Layer {
    match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => crate::packet_log::Layer::Ethernet,
        #[cfg(feature = "medium-ip")]
        Medium::Ip => crate::packet_log::Layer::Ip,
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => crate::packet_log::Layer::Ieee802154,
    }
}

/// Prepend an IPv4 header to a fully-built L4 payload.
///
/// The header checksum is only computed if the egress device doesn't do it
/// itself; it is written as zero otherwise, since devices might rely on it.
#[cfg(feature = "ipv4")]
#[inline(never)] // helps code size
pub(crate) fn push_ipv4_header(
    buf: &mut PacketBuf,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
    next_header: IpProtocol,
    hop_limit: u8,
    checksum_caps: &ChecksumCapabilities,
) {
    let payload_len = buf.len();
    buf.push_front(IPV4_HEADER_LEN);
    let mut packet = Ipv4Packet::new_unchecked(buf);
    packet.set_version(4);
    packet.set_header_len(IPV4_HEADER_LEN as u8);
    packet.set_dscp(0);
    packet.set_ecn(0);
    packet.set_total_len((IPV4_HEADER_LEN + payload_len) as u16);
    packet.set_ident(0);
    packet.clear_flags();
    packet.set_more_frags(false);
    packet.set_dont_frag(true);
    packet.set_frag_offset(0);
    packet.set_hop_limit(hop_limit);
    packet.set_next_header(next_header);
    packet.set_src_addr(src_addr);
    packet.set_dst_addr(dst_addr);
    if checksum_caps.ipv4.tx() {
        packet.fill_checksum();
    } else {
        packet.set_checksum(0);
    }
}

/// Prepend an IPv6 header to a fully-built L4 payload.
#[cfg(feature = "ipv6")]
pub(crate) fn push_ipv6_header(
    buf: &mut PacketBuf,
    src_addr: Ipv6Address,
    dst_addr: Ipv6Address,
    next_header: IpProtocol,
    hop_limit: u8,
) {
    let payload_len = buf.len();
    buf.push_front(IPV6_HEADER_LEN);
    let mut packet = Ipv6Packet::new_unchecked(buf);
    packet.set_version(6);
    packet.set_traffic_class(0);
    packet.set_flow_label(0);
    packet.set_payload_len(payload_len as u16);
    packet.set_next_header(next_header);
    packet.set_hop_limit(hop_limit);
    packet.set_src_addr(src_addr);
    packet.set_dst_addr(dst_addr);
}

/// ICMP error messages have a fixed 8-byte header (type, code, checksum, and a
/// 4-byte type-specific field), followed by the quoted packet.
const ICMP_ERROR_HEADER_LEN: usize = 8;

/// Build an ICMPv4 error message, quoting as much of `orig` (a whole IP packet)
/// as fits within the minimum MTU (RFC 1812 §4.3.2.3).
#[cfg(feature = "ipv4")]
fn build_icmpv4_error(
    orig: &[u8],
    msg_type: Icmpv4Message,
    msg_code: u8,
    checksum_caps: &ChecksumCapabilities,
) -> Option<PacketBuf> {
    let quote_len = orig.len().min(IPV4_MIN_MTU - IPV4_HEADER_LEN - ICMP_ERROR_HEADER_LEN);
    let mut reply = PacketBuf::try_new()?;
    reply.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
    reply.set_len(ICMP_ERROR_HEADER_LEN + quote_len);
    {
        let mut icmp = Icmpv4Packet::new_unchecked(&mut reply);
        icmp.set_msg_type(msg_type);
        icmp.set_msg_code(msg_code);
        icmp.clear_unused();
        icmp.data_mut().copy_from_slice(&orig[..quote_len]);
        if checksum_caps.icmpv4.tx() {
            icmp.fill_checksum();
        } else {
            icmp.set_checksum(0);
        }
    }
    Some(reply)
}

/// Build an ICMPv6 error message, quoting as much of `orig` (a whole IP packet)
/// as fits within the minimum MTU (RFC 4443 §2.4). `src_addr` and `dst_addr` are
/// the addresses the error will be sent between, for the checksum. `pointer` is
/// written for parameter problem messages.
#[cfg(feature = "ipv6")]
fn build_icmpv6_error(
    orig: &[u8],
    src_addr: &Ipv6Address,
    dst_addr: &Ipv6Address,
    msg_type: Icmpv6Message,
    msg_code: u8,
    pointer: u32,
    checksum_caps: &ChecksumCapabilities,
) -> Option<PacketBuf> {
    let quote_len = orig.len().min(IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_ERROR_HEADER_LEN);
    let mut reply = PacketBuf::try_new()?;
    reply.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
    reply.set_len(ICMP_ERROR_HEADER_LEN + quote_len);
    {
        let mut icmp = Icmpv6Packet::new_unchecked(&mut reply);
        icmp.set_msg_type(msg_type);
        icmp.set_msg_code(msg_code);
        if msg_type == Icmpv6Message::ParamProblem {
            icmp.set_param_problem_ptr(pointer);
        } else {
            icmp.clear_reserved();
        }
        icmp.payload_mut().copy_from_slice(&orig[..quote_len]);
        if checksum_caps.icmpv6.tx() {
            icmp.fill_checksum(src_addr, dst_addr);
        } else {
            icmp.set_checksum(0);
        }
    }
    Some(reply)
}

/// The outcome of processing a hop-by-hop options header.
#[cfg(feature = "ipv6")]
enum HopByHopAction {
    /// All options accepted, continue at the upper-layer header.
    Continue { next_header: IpProtocol, ext_len: usize },
    /// An unrecognized option requires the packet to be discarded silently.
    Discard,
    /// An unrecognized option requires the packet to be discarded and a parameter
    /// problem error sent, pointing at the offending option.
    DiscardSendError { pointer: u32, allow_multicast_dst: bool },
}

/// Walk a hop-by-hop options header (`payload` starts at the extension header).
///
/// Recognized options (padding, router alert) are skipped. Unrecognized ones are
/// acted on per the two high bits of their type (RFC 8200 §4.2).
#[cfg(feature = "ipv6")]
fn process_hop_by_hop(payload: &[u8]) -> crate::wire::Result<HopByHopAction> {
    let ext = Ipv6ExtHeader::new_checked(payload)?;
    for option in Ipv6OptionsIter::new(ext.data()) {
        let (offset, option_type, _data) = option?;
        match option_type {
            Ipv6OptionType::Pad1 | Ipv6OptionType::PadN | Ipv6OptionType::RouterAlert => {}
            unrecognized => {
                // The option sits 2 bytes into the extension header, which itself
                // starts right after the fixed IPv6 header.
                let pointer = (IPV6_HEADER_LEN + 2 + offset) as u32;
                match unrecognized.failure_action() {
                    Ipv6OptionFailureAction::Skip => {}
                    Ipv6OptionFailureAction::Discard => return Ok(HopByHopAction::Discard),
                    Ipv6OptionFailureAction::DiscardSendError => {
                        return Ok(HopByHopAction::DiscardSendError {
                            pointer,
                            allow_multicast_dst: true,
                        });
                    }
                    Ipv6OptionFailureAction::DiscardSendErrorIfUnicast => {
                        return Ok(HopByHopAction::DiscardSendError {
                            pointer,
                            allow_multicast_dst: false,
                        });
                    }
                }
            }
        }
    }
    Ok(HopByHopAction::Continue {
        next_header: ext.next_header(),
        ext_len: ext.header_len(),
    })
}

/// Scan the NDISC options of a neighbor solicitation/advertisement for the (source or
/// target) link-layer address option.
/// The length of an NDISC link-layer address option carrying `addr`: type
/// and length bytes plus the address, padded to a multiple of 8 (8 for an
/// Ethernet address, 16 for an extended 802.15.4 address, RFC 4944 §8).
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
pub(crate) fn lladdr_option_len(addr: HardwareAddress) -> usize {
    (2 + addr.as_bytes().len()).div_ceil(8) * 8
}

/// Write an NDISC link-layer address option into `opt`, which must be
/// [`lladdr_option_len`] bytes long. The padding bytes are zeroed.
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
pub(crate) fn write_lladdr_option(opt: &mut [u8], option_type: NdiscOptionType, addr: HardwareAddress) {
    opt.fill(0);
    let mut opt = NdiscOption::new_unchecked(opt);
    opt.set_option_type(option_type);
    opt.set_data_len((lladdr_option_len(addr) / 8) as u8);
    opt.set_link_layer_addr(RawHardwareAddress::from(addr));
}

#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
fn ndisc_lladdr_option(
    icmp_packet: &mut Icmpv6Packet<'_>,
    option_type: NdiscOptionType,
) -> crate::wire::Result<Option<RawHardwareAddress>> {
    let mut lladdr = None;
    let options = icmp_packet.payload_mut();
    let mut offset = 0;
    while offset < options.len() {
        let opt = NdiscOption::new_checked(&mut options[offset..])?;
        let opt_len = opt.data_len() as usize * 8;
        if opt_len == 0 {
            trace!("ndisc: option with zero length");
            return Err(crate::wire::Error);
        }
        if opt.option_type() == option_type {
            lladdr = Some(opt.link_layer_addr());
        }
        offset += opt_len;
    }
    Ok(lladdr)
}

#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "ipv6",
    feature = "raw-ethernet",
    feature = "raw-ip",
    feature = "udp",
    feature = "tcp"
))]
pub(crate) mod test {

    use super::*;
    use crate::driver::Checksum;
    #[cfg(feature = "slaac")]
    use crate::iface::slaac::{SlaacConfig, SlaacState};
    use crate::iface::{AddrOrigin, IfaceAddr};
    use crate::neighbor::MAX_MULTICAST_SOLICIT;
    use crate::raw::RawMode;
    #[cfg(feature = "slaac")]
    use crate::route::RouteOrigin;
    use crate::tcp::State as TcpState;
    #[cfg(feature = "slaac")]
    use crate::test_device::Link;
    use crate::test_device::{Queue, Room, Sent, TestDevice};
    use crate::time::Duration;
    use crate::udp::RecvError as UdpRecvError;
    #[allow(unused_imports)]
    use std::vec::Vec;

    #[test]
    fn test_alloc_ephemeral_port() {
        let mut rand = Rand::new(42);

        // Unconstrained: any port in the ephemeral range.
        let port = alloc_ephemeral_port(&mut rand, |_| false).unwrap();
        assert!(port >= EPHEMERAL_PORT_MIN);

        // The probe walks past used ports (wrapping) to the single free one.
        let free = EPHEMERAL_PORT_MIN + 1234;
        assert_eq!(alloc_ephemeral_port(&mut rand, |p| p != free), Some(free));

        // Every port in use: allocation fails.
        assert_eq!(alloc_ephemeral_port(&mut rand, |_| true), None);
    }

    const OUR_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const OUR_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const OUR_V6: Ipv6Address = Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1);
    const REMOTE_V6: Ipv6Address = Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2);

    /// A stack with one interface of the given medium, owning [`OUR_V4`]/24 and
    /// [`OUR_V6`]/64.
    fn test_stack(medium: Medium) -> (Stack<'static>, Queue, Sent) {
        let (stack, rx, tx, _room) = test_stack_with_room(medium);
        (stack, rx, tx)
    }

    /// [`test_stack`], also handing out the device's transmit room control.
    fn test_stack_with_room(medium: Medium) -> (Stack<'static>, Queue, Sent, Room) {
        test_stack_with_mtu(medium, 1500)
    }

    /// [`test_stack`], with a device that claims to handle the given checksums itself.
    fn test_stack_with_checksum(medium: Medium, checksum: ChecksumCapabilities) -> (Stack<'static>, Queue, Sent) {
        let (stack, rx, tx, _room) = test_stack_inner(medium, 1500, checksum);
        (stack, rx, tx)
    }

    /// [`test_stack_with_room`], with a device of the given MTU.
    fn test_stack_with_mtu(medium: Medium, mtu: usize) -> (Stack<'static>, Queue, Sent, Room) {
        test_stack_inner(medium, mtu, ChecksumCapabilities::default())
    }

    fn test_stack_inner(
        medium: Medium,
        mtu: usize,
        checksum: ChecksumCapabilities,
    ) -> (Stack<'static>, Queue, Sent, Room) {
        let driver = TestDevice::new(medium).with_mtu(mtu).with_checksum(checksum);
        let (rx, tx, room) = (driver.rx.clone(), driver.tx.clone(), driver.room.clone());
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(
            &mut stack,
            match medium {
                Medium::Ethernet => HardwareAddress::Ethernet(OUR_HW),
                Medium::Ip => HardwareAddress::Ip,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::Extended([0x02; 8])),
            },
        );
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)])
            .unwrap();
        // Drain the solicited-node multicast reports the new addresses trigger, so
        // the tests only see the frames they provoke.
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();
        (stack, rx, tx, room)
    }

    /// OUR_HW 02:00:00:00:00:01 -> fe80::ff:fe00:1 (modified EUI-64 flips the U/L bit back).
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    const OUR_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x1);

    #[test]
    #[cfg(feature = "medium-ethernet")]
    fn test_iface_reports_device_state() {
        let driver = TestDevice::new(Medium::Ethernet);
        let link = driver.link.clone();
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));

        // The hardware address is read from the device at add time.
        assert_eq!(stack.iface(handle).hardware_addr(), HardwareAddress::Ethernet(OUR_HW));

        // The link state is read from the device live.
        assert_eq!(stack.iface(handle).link_state(), crate::driver::LinkState::Up);
        link.set(crate::driver::LinkState::Down);
        assert_eq!(stack.iface(handle).link_state(), crate::driver::LinkState::Down);
    }

    #[test]
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    fn test_auto_link_local() {
        let ll = IfaceAddr {
            cidr: IpCidr::new(OUR_LINK_LOCAL.into(), 64),
            origin: AddrOrigin::LinkLocal,
            preferred_until: None,
        };
        let (mut stack, _rx, _tx) = test_stack(Medium::Ethernet);
        let handle = IfaceHandle::new(0);

        // Present after add_iface, survives set_ip_addrs.
        assert!(stack.iface(handle).ip_addrs().contains(&ll));
        assert!(stack.iface(handle).has_ip_addr(OUR_LINK_LOCAL));

        // Follows the hardware address.
        let generation = stack.iface(handle).config_generation();
        stack
            .iface(handle)
            .set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x02])));
        assert!(!stack.iface(handle).has_ip_addr(OUR_LINK_LOCAL));
        assert!(
            stack
                .iface(handle)
                .has_ip_addr(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2))
        );
        assert_ne!(stack.iface(handle).config_generation(), generation);

        // Can be removed by hand, and a user-set link-local is kept by set_ip_addrs.
        stack
            .iface(handle)
            .remove_ip_addr(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2));
        assert!(
            !stack
                .iface(handle)
                .ip_addrs()
                .iter()
                .any(|a| a.origin == AddrOrigin::LinkLocal)
        );
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V6.into(), 64)])
            .unwrap();
        assert_eq!(
            stack.iface(handle).ip_addrs(),
            &[IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64))]
        );

        // No link-local on an IP-medium interface.
        let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
        assert!(
            !stack
                .iface(handle)
                .ip_addrs()
                .iter()
                .any(|a| a.origin == AddrOrigin::LinkLocal)
        );
    }

    /// An Ethernet frame carrying a router advertisement from `router_hw`/`router_ll`
    /// to all nodes: hop limit 255, source link-layer option, one prefix information
    /// option for `prefix`/64 with the A and L flags.
    #[cfg(feature = "slaac")]
    fn router_advert(
        router_hw: EthernetAddress,
        router_ll: Ipv6Address,
        router_lifetime: Duration,
        prefix: Ipv6Address,
        valid_lifetime: Duration,
        preferred_lifetime: Duration,
    ) -> Vec<u8> {
        let mut icmp = vec![0; 16 + 8 + 32];
        {
            let mut ra = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            ra.set_msg_type(Icmpv6Message::RouterAdvert);
            ra.set_msg_code(0);
            ra.set_current_hop_limit(64);
            ra.set_router_flags(NdiscRouterFlags::OTHER);
            ra.set_router_lifetime(router_lifetime);
            ra.set_reachable_time(Duration::ZERO);
            ra.set_retrans_time(Duration::ZERO);
            let options = ra.payload_mut();
            {
                let mut opt = NdiscOption::new_unchecked(&mut options[..8]);
                opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
                opt.set_data_len(1);
                opt.set_link_layer_addr(RawHardwareAddress::from(router_hw));
            }
            {
                let mut opt = NdiscOption::new_unchecked(&mut options[8..]);
                opt.set_option_type(NdiscOptionType::PrefixInformation);
                opt.set_data_len(4);
                opt.set_prefix_len(64);
                opt.set_prefix_flags(NdiscPrefixInfoFlags::ON_LINK | NdiscPrefixInfoFlags::ADDRCONF);
                opt.set_valid_lifetime(valid_lifetime);
                opt.set_preferred_lifetime(preferred_lifetime);
                opt.clear_prefix_reserved();
                opt.set_prefix(prefix);
            }
            ra.fill_checksum(&router_ll, &IPV6_LINK_LOCAL_ALL_NODES);
        }
        let mut ip = ipv6_packet(router_ll, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol::Icmpv6, &icmp);
        Ipv6Packet::new_unchecked(&mut ip[..]).set_hop_limit(255);

        let mut frame = vec![0; ETHERNET_HEADER_LEN];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame[..]);
            eth.set_dst_addr(EthernetAddress([0x33, 0x33, 0, 0, 0, 1]));
            eth.set_src_addr(router_hw);
            eth.set_ethertype(EthernetProtocol::Ipv6);
        }
        frame.extend_from_slice(&ip);
        frame
    }

    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac() {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let our_addr = IpCidr::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into(), 64);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        assert_eq!(stack.iface(iface).slaac(), Some(&SlaacState::default()));
        let generation = stack.iface(iface).config_generation();

        // The first poll solicits routers, from the link-local address to all
        // routers, with our link-layer address attached.
        let deadline = stack.poll(Instant::from_secs(1));
        assert_eq!(tx.borrow().len(), 1);
        {
            let frame = &tx.borrow()[0];
            let mut eth_bytes = frame.clone();
            let eth = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
            assert_eq!(eth.dst_addr(), EthernetAddress([0x33, 0x33, 0, 0, 0, 2]));
            assert_eq!(eth.src_addr(), OUR_HW);
            let mut ip_bytes = frame[ETHERNET_HEADER_LEN..].to_vec();
            assert_eq!(Ipv6Packet::new_unchecked(&mut ip_bytes[..]).hop_limit(), 255);
            let (msg_type, _, _, options) = parse_icmpv6_reply(
                &frame[ETHERNET_HEADER_LEN..],
                OUR_LINK_LOCAL,
                IPV6_LINK_LOCAL_ALL_ROUTERS,
            );
            assert_eq!(msg_type, Icmpv6Message::RouterSolicit);
            assert_eq!(options, [&[1, 1][..], OUR_HW.as_bytes()].concat());
        }
        // Retransmitted every 4 s, three times in total.
        assert_eq!(deadline, Instant::from_secs(5));
        stack.poll(Instant::from_secs(5));
        assert_eq!(tx.borrow().len(), 2);

        // A router answers: the address, the default route and the router's
        // link-layer address are all installed, and solicitation stops.
        let now = Instant::from_secs(6);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        let deadline = stack.poll(now);
        assert_eq!(tx.borrow().len(), 2);
        assert_eq!(deadline, now + Duration::from_secs(1800));
        // The address carries the advertised preferred lifetime, so a consumer can
        // tell a fresh address from one whose prefix is being retired.
        assert!(stack.iface(iface).ip_addrs().contains(&IfaceAddr {
            cidr: our_addr,
            origin: AddrOrigin::Slaac,
            preferred_until: Some(now + Duration::from_secs(3600)),
        }));
        let route = stack.routes().get_default_ipv6_route().unwrap();
        assert_eq!(route.via_router, IpAddress::Ipv6(router_ll));
        assert_eq!(route.iface, iface);
        assert_eq!(route.origin, RouteOrigin::Slaac);
        assert_eq!(route.expires_at, Some(now + Duration::from_secs(1800)));
        assert_ne!(stack.iface(iface).config_generation(), generation);
        let state = *stack.iface(iface).slaac().unwrap();
        assert!(state.routers_seen);
        assert!(!state.managed);
        assert!(state.other_config);
        stack.poll(Instant::from_secs(9));
        assert_eq!(tx.borrow().len(), 2);

        // Off-link traffic goes via the router, whose address is already resolved.
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();
        stack
            .udp_socket(udp)
            .send_slice(b"hi", (Ipv6Address::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1), 1000))
            .unwrap();
        assert_eq!(tx.borrow().len(), 3);
        {
            let frame = &tx.borrow()[2];
            let mut eth_bytes = frame.clone();
            let eth = EthernetFrame::new_unchecked(&mut eth_bytes[..]);
            assert_eq!(eth.dst_addr(), router_hw);
            let mut ip_bytes = frame[ETHERNET_HEADER_LEN..].to_vec();
            assert_eq!(
                IpAddress::Ipv6(Ipv6Packet::new_unchecked(&mut ip_bytes[..]).src_addr()),
                our_addr.address()
            );
        }

        // A refresh extends the lifetimes.
        let now = Instant::from_secs(600);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        let deadline = stack.poll(now);
        assert_eq!(deadline, now + Duration::from_secs(1800));
        let route = stack.routes().get_default_ipv6_route().unwrap();
        assert_eq!(route.expires_at, Some(now + Duration::from_secs(1800)));

        // The route expires first, then the address.
        let generation = stack.iface(iface).config_generation();
        let deadline = stack.poll(now + Duration::from_secs(1801));
        assert!(stack.routes().get_default_ipv6_route().is_none());
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert_ne!(stack.iface(iface).config_generation(), generation);
        assert_eq!(deadline, now + Duration::from_secs(7200));
        let deadline = stack.poll(now + Duration::from_secs(7201));
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert_eq!(deadline, Instant::MAX);

        // A router can withdraw with zero lifetimes.
        let now = now + Duration::from_secs(7300);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(now);
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_some());
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::ZERO,
            prefix,
            Duration::ZERO,
            Duration::ZERO,
        ));
        stack.poll(now + Duration::from_secs(1));
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_none());

        // Turning SLAAC off removes what it installed, and nothing else.
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(now + Duration::from_secs(2));
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        stack.iface(iface).set_slaac(None);
        assert!(stack.iface(iface).slaac().is_none());
        assert!(!stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_none());
        assert!(stack.iface(iface).has_ip_addr(OUR_V6));
        assert!(stack.iface(iface).has_ip_addr(OUR_LINK_LOCAL));
    }

    /// An address the application assigned by hand is not SLAAC's to touch, even when
    /// a prefix forms exactly that address. It keeps its origin, gains no advertised
    /// lifetime, is not deprecated when the prefix is retired, and outlives it.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_leaves_a_manual_address_alone() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        // Exactly the address SLAAC forms from `prefix` on this interface.
        let our_addr = IpCidr::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into(), 64);

        // Without `alloc` the address table is bounded (`iface-addr-count-N`, four by
        // default) and `test_stack` already assigns two addresses. Clear them so the
        // prefixes below have room; the link-local address is kept regardless.
        let no_addrs: [IpCidr; 0] = [];
        stack.iface(iface).set_ip_addrs(no_addrs).unwrap();

        stack.iface(iface).add_ip_addr(our_addr).unwrap();
        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));

        let now = Instant::from_secs(6);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(now);

        assert_eq!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .filter(|a| a.cidr == our_addr)
                .count(),
            1,
            "slaac must not install a second copy of an address that is already assigned"
        );
        assert!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .any(|a| a.cidr == our_addr && a.origin == AddrOrigin::Manual && a.preferred_until.is_none()),
            "the address stays the application's, and gains no advertised lifetime"
        );

        // The router retires the prefix. That deprecates nothing here.
        let now = Instant::from_secs(12);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::ZERO,
        ));
        stack.poll(now);
        assert!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .any(|a| a.cidr == our_addr && a.is_preferred(now)),
            "a retired prefix must not deprecate an address slaac does not own"
        );

        // ...and the prefix expiring does not take it away either.
        let now = Instant::from_secs(7300);
        stack.poll(now);
        assert!(
            stack.iface(iface).has_ip_addr(our_addr.address()),
            "expiry must leave an address slaac does not own assigned"
        );
    }

    /// A prefix on its way out is advertised with a preferred lifetime of zero
    /// while it stays valid, so the address formed from it is still assigned and
    /// still matches an on-prefix destination more closely than anything else.
    /// RFC 6724 orders rule 3 above rule 8 precisely so that it stops being used
    /// as a source anyway.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_deprecated_address_is_not_a_source() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let outgoing = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let incoming = Ipv6Address::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0);
        let outgoing_addr = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1);
        let incoming_addr = Ipv6Address::new(0x2001, 0xdb9, 0, 0, 0, 0xff, 0xfe00, 0x1);
        // On the outgoing prefix, so rule 8 on its own always answers `outgoing_addr`.
        let dst = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2);

        // Without `alloc` the address table is bounded (`iface-addr-count-N`, four by
        // default) and `test_stack` already assigns two addresses. Clear them so the
        // prefixes below have room; the link-local address is kept regardless.
        let no_addrs: [IpCidr; 0] = [];
        stack.iface(iface).set_ip_addrs(no_addrs).unwrap();

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));

        // Both prefixes are live, and the one the network is leaving is preferred.
        let now = Instant::from_secs(6);
        for prefix in [outgoing, incoming] {
            rx.borrow_mut().push_back(router_advert(
                router_hw,
                router_ll,
                Duration::from_secs(1800),
                prefix,
                Duration::from_secs(7200),
                Duration::from_secs(3600),
            ));
        }
        stack.poll(now);
        assert!(stack.iface(iface).ip_addrs().iter().all(|a| a.is_preferred(now)));
        assert_eq!(
            stack.ifaces.get(iface.index()).get_source_address_ipv6(&dst, now),
            outgoing_addr
        );

        // The router retires the outgoing prefix: no longer preferred, still valid.
        let now = Instant::from_secs(12);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            outgoing,
            Duration::from_secs(7200),
            Duration::ZERO,
        ));
        stack.poll(now);

        // The address is still assigned, because it is still valid...
        assert!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .any(|a| a.cidr.address() == IpAddress::Ipv6(outgoing_addr) && !a.is_preferred(now)),
            "a deprecated address stays assigned until its valid lifetime ends"
        );
        // ...and it is no longer what the stack puts in the source field.
        assert_eq!(
            stack.ifaces.get(iface.index()).get_source_address_ipv6(&dst, now),
            incoming_addr
        );
    }

    /// RFC 6724 Section 5 applies its rules in priority order: the first rule that
    /// tells two candidates apart decides, and the ones below it never run. Rule 1
    /// matches a source address that is the destination itself, so it settles the
    /// comparison before rule 3 gets a say, and a deprecated address still wins when
    /// it is the destination.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_source_address_rule_1_beats_rule_3() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let outgoing = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let incoming = Ipv6Address::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0);
        let outgoing_addr = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1);

        let no_addrs: [IpCidr; 0] = [];
        stack.iface(iface).set_ip_addrs(no_addrs).unwrap();
        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));

        // Both prefixes are live.
        let now = Instant::from_secs(6);
        for prefix in [outgoing, incoming] {
            rx.borrow_mut().push_back(router_advert(
                router_hw,
                router_ll,
                Duration::from_secs(1800),
                prefix,
                Duration::from_secs(7200),
                Duration::from_secs(3600),
            ));
        }
        stack.poll(now);

        // The router retires the outgoing prefix: no longer preferred, still valid.
        let now = Instant::from_secs(12);
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            outgoing,
            Duration::from_secs(7200),
            Duration::ZERO,
        ));
        stack.poll(now);
        assert!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .any(|a| a.cidr.address() == IpAddress::Ipv6(outgoing_addr) && !a.is_preferred(now)),
            "the outgoing prefix's address has to be deprecated for this test to mean anything"
        );

        // Talking to the deprecated address itself. Rule 1 matches it exactly, so rule 3
        // must not go on to prefer the address that replaced it.
        assert_eq!(
            stack
                .ifaces
                .get(iface.index())
                .get_source_address_ipv6(&outgoing_addr, now),
            outgoing_addr,
            "rule 3 must not override rule 1"
        );
    }

    /// A router advertisement that is not from a link-local source is ignored.
    /// [`test_stack`], also handing out control of the link state the device reports.
    #[cfg(all(feature = "slaac", feature = "medium-ethernet"))]
    fn test_stack_with_link(medium: Medium) -> (Stack<'static>, Queue, Sent, Link) {
        let driver = TestDevice::new(medium);
        let (rx, tx, link) = (driver.rx.clone(), driver.tx.clone(), driver.link.clone());
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)])
            .unwrap();
        // Drain the solicited-node multicast reports the new addresses trigger.
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();
        (stack, rx, tx, link)
    }

    /// Take an interface that has settled into `Maintaining` through a link bounce, leaving
    /// it just after the link comes back. Polling while down is what lets the stack observe
    /// the falling edge.
    #[cfg(all(feature = "slaac", feature = "medium-ethernet"))]
    fn bounce_link(stack: &mut Stack<'static>, tx: &Sent, link: &Link, at: i64) {
        link.set(crate::driver::LinkState::Down);
        stack.poll(Instant::from_secs(at));
        tx.borrow_mut().clear();
        link.set(crate::driver::LinkState::Up);
        stack.poll(Instant::from_secs(at + 1));
    }

    /// RFC 4861 section 6.3.7 stops solicitation once a router answers, but only "until the
    /// next time one of the above events occurs".
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_resolicits_after_link_bounce() {
        let (mut stack, rx, tx, link) = test_stack_with_link(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        stack.poll(Instant::from_secs(1));

        // A router answers, so solicitation stops.
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(6));
        tx.borrow_mut().clear();
        stack.poll(Instant::from_secs(20));
        assert!(tx.borrow().is_empty(), "a settled interface must not keep soliciting");

        // The link drops and comes back: ask the network again.
        bounce_link(&mut stack, &tx, &link, 30);
        assert_eq!(tx.borrow().len(), 1, "the link coming back must trigger a solicitation");
        let frame = tx.borrow()[0].clone();
        let (msg_type, _, _, _) = parse_icmpv6_reply(
            &frame[ETHERNET_HEADER_LEN..],
            OUR_LINK_LOCAL,
            IPV6_LINK_LOCAL_ALL_ROUTERS,
        );
        assert_eq!(msg_type, Icmpv6Message::RouterSolicit);
    }

    /// Solicitations are held back while the link is down. `ndisc_rs_egress` counts one as
    /// sent whether or not the driver accepted the frame, so soliciting into a down link
    /// would spend the budget on nothing and leave the interface silent once it came back.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_does_not_solicit_on_a_down_link() {
        let (mut stack, _rx, tx, link) = test_stack_with_link(Medium::Ethernet);
        let iface = IfaceHandle::new(0);

        link.set(crate::driver::LinkState::Down);
        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        for at in [1, 5, 9, 13] {
            stack.poll(Instant::from_secs(at));
        }
        assert!(tx.borrow().is_empty(), "a down link must not be solicited");

        // The budget was not spent while down, so all three still go out once it is back.
        link.set(crate::driver::LinkState::Up);
        for at in [20, 24, 28, 32] {
            stack.poll(Instant::from_secs(at));
        }
        assert_eq!(tx.borrow().len(), 3, "the full budget survived the outage");
        let frame = tx.borrow()[0].clone();
        let (msg_type, _, _, _) = parse_icmpv6_reply(
            &frame[ETHERNET_HEADER_LEN..],
            OUR_LINK_LOCAL,
            IPV6_LINK_LOCAL_ALL_ROUTERS,
        );
        assert_eq!(msg_type, Icmpv6Message::RouterSolicit);
    }

    /// Every link-up solicits at once, even mid-interval: the link coming back can
    /// mean a new network, and holding the solicitation for the rest of
    /// `RTR_SOLICITATION_INTERVAL` just delays learning it.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_link_up_solicits_at_once() {
        let (mut stack, rx, tx, link) = test_stack_with_link(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        stack.poll(Instant::from_secs(1));
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(6));

        // First bounce: settled long enough that the retry timer has passed, so this
        // solicits at once.
        bounce_link(&mut stack, &tx, &link, 30);
        assert_eq!(tx.borrow().len(), 1);

        // Flapping again straight away solicits again straight away.
        link.set(crate::driver::LinkState::Down);
        stack.poll(Instant::from_secs(32));
        link.set(crate::driver::LinkState::Up);
        stack.poll(Instant::from_secs(33));
        assert_eq!(tx.borrow().len(), 2, "each link-up sends a fresh solicitation");

        // The remaining budget is spent on the retry timer as usual.
        stack.poll(Instant::from_secs(37));
        assert_eq!(tx.borrow().len(), 3, "retries after the edge keep to the interval");
    }

    /// Re-soliciting is not the same as tearing SLAAC down: what a router already told us
    /// stays valid until its lifetime says otherwise, so the addresses and routes have to
    /// survive the bounce. Discarding them is `set_slaac(None)`, a different operation.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_link_bounce_keeps_configuration() {
        let (mut stack, rx, tx, link) = test_stack_with_link(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let our_addr = IpCidr::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into(), 64);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(6));
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_some());

        bounce_link(&mut stack, &tx, &link, 30);

        assert!(
            stack
                .iface(iface)
                .ip_addrs()
                .iter()
                .any(|a| a.cidr == our_addr && a.origin == AddrOrigin::Slaac),
            "a link bounce must not discard an address whose lifetime is still running"
        );
        let route = stack.routes().get_default_ipv6_route().unwrap();
        assert_eq!(route.origin, RouteOrigin::Slaac, "the default route must survive too");
    }

    /// The manual path, for a driver that cannot report link state.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_restart_by_hand() {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let router_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
        let prefix = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
        let our_addr = IpCidr::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into(), 64);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        // Solicit first: an advertisement only settles the state machine from
        // `Discovering`, so it has to have asked before the answer arrives.
        stack.poll(Instant::from_secs(1));
        rx.borrow_mut().push_back(router_advert(
            router_hw,
            router_ll,
            Duration::from_secs(1800),
            prefix,
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(6));
        tx.borrow_mut().clear();
        stack.poll(Instant::from_secs(20));
        assert!(tx.borrow().is_empty(), "a settled interface must not keep soliciting");

        // The link never changed, so only an explicit call can restart discovery.
        let now = Instant::from_secs(30);
        stack.iface(iface).restart_slaac();
        stack.poll(now);
        assert_eq!(tx.borrow().len(), 1, "an explicit restart must solicit");
        let frame = tx.borrow()[0].clone();
        let (msg_type, _, _, _) = parse_icmpv6_reply(
            &frame[ETHERNET_HEADER_LEN..],
            OUR_LINK_LOCAL,
            IPV6_LINK_LOCAL_ALL_ROUTERS,
        );
        assert_eq!(msg_type, Icmpv6Message::RouterSolicit);
        // And it re-checks rather than discards, same as the link-up path.
        assert!(stack.iface(iface).has_ip_addr(our_addr.address()));
        assert!(stack.routes().get_default_ipv6_route().is_some());
    }

    /// With SLAAC off there is nothing to restart, so the call is a no-op.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_restart_without_slaac_is_a_noop() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);

        stack.iface(iface).restart_slaac();
        stack.poll(Instant::from_secs(1));
        assert!(tx.borrow().is_empty(), "no SLAAC, nothing to solicit");
    }

    /// Giving up after the solicitation budget is spent is the other dead end: a host that
    /// started while no router was up never asked again.
    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_resolicits_after_giving_up() {
        let (mut stack, _rx, tx, link) = test_stack_with_link(Medium::Ethernet);
        let iface = IfaceHandle::new(0);

        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        // Nothing answers. The three solicitations RFC 4861 allows go out 4s apart, and then
        // the budget is spent: the interface is left in `Discovering` with nothing to send.
        for at in [1, 5, 9, 13, 20] {
            stack.poll(Instant::from_secs(at));
        }
        assert_eq!(
            tx.borrow().len(),
            3,
            "MAX_RTR_SOLICITATIONS solicitations, then silence"
        );
        tx.borrow_mut().clear();
        stack.poll(Instant::from_secs(25));
        assert!(tx.borrow().is_empty(), "the solicitation budget is spent");

        bounce_link(&mut stack, &tx, &link, 30);
        assert_eq!(tx.borrow().len(), 1, "the link coming back must restart discovery");
    }

    #[test]
    #[cfg(feature = "slaac")]
    fn test_slaac_ignores_invalid_advert() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        stack.iface(iface).set_slaac(Some(SlaacConfig::default()));
        rx.borrow_mut().push_back(router_advert(
            EthernetAddress([0x02, 0, 0, 0, 0, 0x02]),
            Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xbad),
            Duration::from_secs(1800),
            Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            Duration::from_secs(7200),
            Duration::from_secs(3600),
        ));
        stack.poll(Instant::from_secs(1));
        assert!(!stack.iface(iface).slaac().unwrap().routers_seen);
        assert!(stack.routes().get_default_ipv6_route().is_none());
    }

    /// Inject a packet into the device and poll the stack to process it.
    pub(crate) fn inject(stack: &mut Stack, rx: &Queue, bytes: Vec<u8>) {
        rx.borrow_mut().push_back(bytes);
        stack.poll(Instant::ZERO);
    }

    /// A whole IPv4 packet, header checksum filled in.
    fn ipv4_packet(src_addr: Ipv4Address, dst_addr: Ipv4Address, protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV4_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + payload.len()) as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
            ip.fill_checksum();
        }
        bytes[IPV4_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    /// A whole IPv6 packet.
    pub(crate) fn ipv6_packet(
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        protocol: IpProtocol,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = vec![0; IPV6_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len(payload.len() as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
        }
        bytes[IPV6_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    /// A UDP datagram (UDP header + payload), checksum filled in.
    pub(crate) fn udp_datagram(
        src_addr: IpAddress,
        src_port: u16,
        dst_addr: IpAddress,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = vec![0; UDP_HEADER_LEN + payload.len()];
        {
            let mut udp = UdpPacket::new_unchecked(&mut bytes[..]);
            udp.set_src_port(src_port);
            udp.set_dst_port(dst_port);
            udp.set_len((UDP_HEADER_LEN + payload.len()) as u16);
            udp.payload_mut().copy_from_slice(payload);
            udp.fill_checksum(&src_addr, &dst_addr);
        }
        bytes
    }

    /// Parse a transmitted IPv4 frame as an ICMPv4 message, verifying addresses and
    /// both checksums, and return `(type, code, quoted packet)`.
    fn parse_icmpv4_reply(frame: &[u8], src_addr: Ipv4Address, dst_addr: Ipv4Address) -> (Icmpv4Message, u8, Vec<u8>) {
        let mut bytes = frame.to_vec();
        let ip = Ipv4Packet::new_checked(&mut bytes[..]).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.src_addr(), src_addr);
        assert_eq!(ip.dst_addr(), dst_addr);
        assert_eq!(ip.next_header(), IpProtocol::Icmp);
        let header_len = ip.header_len() as usize;
        let mut icmp_bytes = bytes[header_len..].to_vec();
        let icmp = Icmpv4Packet::new_checked(&mut icmp_bytes[..]).unwrap();
        assert!(icmp.verify_checksum());
        (icmp.msg_type(), icmp.msg_code(), icmp.data().to_vec())
    }

    /// Parse a transmitted IPv6 frame as an ICMPv6 message, verifying addresses and
    /// the checksum, and return `(type, code, pointer, quoted packet)`.
    fn parse_icmpv6_reply(
        frame: &[u8],
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) -> (Icmpv6Message, u8, u32, Vec<u8>) {
        let mut bytes = frame.to_vec();
        let ip = Ipv6Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(ip.src_addr(), src_addr);
        assert_eq!(ip.dst_addr(), dst_addr);
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
        let mut icmp_bytes = bytes[IPV6_HEADER_LEN..].to_vec();
        let icmp = Icmpv6Packet::new_checked(&mut icmp_bytes[..]).unwrap();
        assert!(icmp.verify_checksum(&src_addr, &dst_addr));
        (
            icmp.msg_type(),
            icmp.msg_code(),
            icmp.param_problem_ptr(),
            icmp.payload().to_vec(),
        )
    }

    #[test]
    fn test_icmpv4_proto_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::ProtoUnreachable.into());
        assert_eq!(quote, packet);
    }

    /// A stack with two IP-medium interfaces: the first owns [`OUR_V4`]/24,
    /// the second 10.0.0.1/24, and both own fe80::1/64.
    fn test_stack_two_ifaces() -> (Stack<'static>, [Queue; 2], [Sent; 2]) {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let mut rxs = Vec::new();
        let mut txs = Vec::new();
        for addr in [IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V4_B.into(), 24)] {
            let driver = TestDevice::new(Medium::Ip);
            let (rx, tx) = (driver.rx.clone(), driver.tx.clone());
            let handle = driver.install(&mut stack, HardwareAddress::Ip);
            stack
                .iface(handle)
                .set_ip_addrs([addr, IpCidr::new(LINK_LOCAL_V6.into(), 64)])
                .unwrap();
            rxs.push(rx);
            txs.push(tx);
        }
        (stack, rxs.try_into().unwrap(), txs.try_into().unwrap())
    }

    const OUR_V4_B: Ipv4Address = Ipv4Address::new(10, 0, 0, 1);
    const REMOTE_V4_B: Ipv4Address = Ipv4Address::new(10, 0, 0, 2);
    const LINK_LOCAL_V6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const LINK_LOCAL_REMOTE_V6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    /// Replies are routed like any other egress: a packet whose sender is on-link
    /// for another interface gets its reply out of that interface, not the one it
    /// arrived on (asymmetric routing).
    #[test]
    fn test_reply_routed_out_other_iface() {
        let (mut stack, rx, tx) = test_stack_two_ifaces();
        // Unknown protocol from the second interface's subnet, arriving on the first.
        let packet = ipv4_packet(REMOTE_V4_B, OUR_V4, IpProtocol(99), b"hello");
        inject(&mut stack, &rx[0], packet.clone());

        assert!(tx[0].borrow().is_empty());
        let tx = tx[1].borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4_B);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::ProtoUnreachable.into());
        assert_eq!(quote, packet);
    }

    /// A reply to an IPv6 link-local source is link-scoped: it goes back out the
    /// arrival interface, even when another interface has a matching on-link
    /// prefix (here, both interfaces own an fe80::/64 address).
    #[test]
    fn test_reply_to_link_local_stays_on_arrival_iface() {
        let (mut stack, rx, tx) = test_stack_two_ifaces();
        let mut icmp = vec![0; 8 + 5];
        {
            let mut echo = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            echo.set_msg_type(Icmpv6Message::EchoRequest);
            echo.set_msg_code(0);
            echo.set_echo_ident(0x1234);
            echo.set_echo_seq_no(1);
            echo.payload_mut().copy_from_slice(b"hello");
            echo.fill_checksum(&LINK_LOCAL_REMOTE_V6, &LINK_LOCAL_V6);
        }
        let packet = ipv6_packet(LINK_LOCAL_REMOTE_V6, LINK_LOCAL_V6, IpProtocol::Icmpv6, &icmp);
        // Arriving on the second interface: an on-link scan would pick the first.
        inject(&mut stack, &rx[1], packet);

        assert!(tx[0].borrow().is_empty());
        let tx = tx[1].borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, _, _, payload) = parse_icmpv6_reply(&tx[0], LINK_LOCAL_V6, LINK_LOCAL_REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::EchoReply);
        assert_eq!(payload, b"hello");
    }

    /// An echo request comes back as a reply with the identifier, sequence number
    /// and payload unchanged. The payload is a full MTU's worth: the reply is built
    /// in the request's own buffer, which has to fit the headers too.
    #[test]
    fn test_icmpv4_echo_reply() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let payload: Vec<u8> = (0..1472u16).map(|i| i as u8).collect();
        let request = icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 7, &payload);
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Icmp, &request),
        );

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, data) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::EchoReply);
        assert_eq!(msg_code, 0);
        assert_eq!(data, payload);
        assert_eq!(
            tx[0][IPV4_HEADER_LEN..],
            icmpv4_echo(Icmpv4Message::EchoReply, 0x1234, 7, &payload)[..]
        );
    }

    /// Same for ICMPv6.
    #[test]
    fn test_icmpv6_echo_reply() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let payload: Vec<u8> = (0..1452u16).map(|i| i as u8).collect();
        let request = icmpv6_echo(Icmpv6Message::EchoRequest, 0x1234, 7, &payload, REMOTE_V6, OUR_V6);
        inject(
            &mut stack,
            &rx,
            ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Icmpv6, &request),
        );

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, _, data) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::EchoReply);
        assert_eq!(msg_code, 0);
        assert_eq!(data, payload);
        assert_eq!(
            tx[0][IPV6_HEADER_LEN..],
            icmpv6_echo(Icmpv6Message::EchoReply, 0x1234, 7, &payload, OUR_V6, REMOTE_V6)[..]
        );
    }

    #[test]
    fn test_icmpv4_no_error_to_broadcast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // Unknown protocol on a broadcast-destined packet: no error may be sent.
        let bcast = Ipv4Address::new(192, 168, 1, 255);
        let packet = ipv4_packet(REMOTE_V4, bcast, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    #[test]
    fn test_icmpv4_port_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let datagram = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), 7, b"echo?");
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        {
            let tx = tx.borrow();
            assert_eq!(tx.len(), 1);
            let (msg_type, msg_code, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
            assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
            assert_eq!(msg_code, Icmpv4DstUnreachable::PortUnreachable.into());
            assert_eq!(quote, packet);
        }

        // With a socket bound to the port, the datagram is delivered instead.
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(7, IpListenEndpoint::UNSPECIFIED).unwrap();
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"echo?");
    }

    #[test]
    fn test_icmpv4_port_unreachable_suppressed_by_raw_socket() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // An application handling UDP through a raw socket suppresses the error.
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol::Udp),
            })
            .unwrap();

        let datagram = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), 7, b"echo?");
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        assert!(tx.borrow().is_empty());
        assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &packet[..]);
    }

    #[test]
    fn test_icmpv6_unknown_next_header() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, pointer, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::ParamProblem);
        assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedNxtHdr.into());
        // The pointer names the fixed header's next header field.
        assert_eq!(pointer, 6);
        assert_eq!(quote, packet);
    }

    #[test]
    fn test_icmpv6_no_error_to_multicast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // Unknown protocol on a multicast-destined packet: no error may be sent.
        let packet = ipv6_packet(REMOTE_V6, IPV6_LINK_LOCAL_ALL_NODES, IpProtocol(99), b"hello");
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    #[test]
    fn test_icmpv6_port_unreachable() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let datagram = udp_datagram(REMOTE_V6.into(), 4000, OUR_V6.into(), 7, b"echo?");
        let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Udp, &datagram);
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, _, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv6DstUnreachable::PortUnreachable.into());
        assert_eq!(quote, packet);
    }

    /// A hop-by-hop options header carrying the given options (padded to a
    /// multiple of 8 by the caller), followed by the given payload.
    fn hbh_payload(next_header: IpProtocol, options: &[u8], payload: &[u8]) -> Vec<u8> {
        assert_eq!((options.len() + 2) % 8, 0);
        let mut bytes = vec![u8::from(next_header), ((options.len() + 2) / 8 - 1) as u8];
        bytes.extend_from_slice(options);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn test_icmpv6_hop_by_hop_passthrough() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(7, IpListenEndpoint::UNSPECIFIED).unwrap();

        // PadN + an unknown option whose action is "skip" (high bits 00): the
        // packet continues to UDP and is delivered, headers intact.
        let datagram = udp_datagram(REMOTE_V6.into(), 4000, OUR_V6.into(), 7, b"echo?");
        let options = [0x01, 0x01, 0x00, 0x02, 0x01, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, &datagram),
        );
        inject(&mut stack, &rx, packet);

        let mut socket = stack.udp_socket(handle);
        let recv = socket.recv().unwrap();
        assert_eq!(&*recv, b"echo?");
        assert_eq!(recv.meta().endpoint, IpEndpoint::new(REMOTE_V6.into(), 4000));
    }

    #[test]
    fn test_icmpv6_hop_by_hop_unrecognized_option() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);

        // High bits 01: discard silently.
        let options = [0x41, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());

        // High bits 10: discard and send a parameter problem, pointing at the
        // offending option (40-byte header + 2 bytes into the extension header).
        let options = [0x81, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            OUR_V6,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet.clone());
        {
            let tx = tx.borrow();
            assert_eq!(tx.len(), 1);
            let (msg_type, msg_code, pointer, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
            assert_eq!(msg_type, Icmpv6Message::ParamProblem);
            assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedOption.into());
            assert_eq!(pointer, 42);
            assert_eq!(quote, packet);
        }
    }

    #[test]
    fn test_icmpv6_hop_by_hop_unrecognized_option_multicast() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);

        // High bits 11: discard, and send the error only if the destination was
        // not multicast, which it is here, so nothing may be sent.
        let options = [0xc1, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            IPV6_LINK_LOCAL_ALL_NODES,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());

        // High bits 10: the error is sent even for a multicast destination, with
        // the source picked from the interface.
        let options = [0x81, 0x04, 0x00, 0x00, 0x00, 0x00];
        let packet = ipv6_packet(
            REMOTE_V6,
            IPV6_LINK_LOCAL_ALL_NODES,
            IpProtocol::HopByHop,
            &hbh_payload(IpProtocol::Udp, &options, b""),
        );
        inject(&mut stack, &rx, packet.clone());
        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        let (msg_type, msg_code, _, quote) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
        assert_eq!(msg_type, Icmpv6Message::ParamProblem);
        assert_eq!(msg_code, Icmpv6ParamProblem::UnrecognizedOption.into());
        assert_eq!(quote, packet);
    }

    #[test]
    fn test_icmp_error_quote_truncated() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        // A big offending packet: the quote is capped so the error fits the
        // minimum MTU (576 for IPv4: 20-byte header + 8-byte ICMP header + quote).
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol(99), &[0xab; 1000]);
        inject(&mut stack, &rx, packet.clone());

        let tx = tx.borrow();
        let (_, _, quote) = parse_icmpv4_reply(&tx[0], OUR_V4, REMOTE_V4);
        assert_eq!(quote.len(), IPV4_MIN_MTU - IPV4_HEADER_LEN - 8);
        assert_eq!(quote, packet[..quote.len()]);
    }

    #[test]
    fn test_neighbor_failure_dst_unreachable() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);

        // A raw socket listening for ICMPv4, the erring application.
        let raw_handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(raw_handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol::Icmp),
            })
            .unwrap();

        // Send a datagram to an on-link address that will never resolve: the
        // packet is queued and an ARP request goes out.
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let udp_handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(udp_handle)
            .bind(5555, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        stack
            .udp_socket(udp_handle)
            .send_slice(b"anyone?", (dead, 1000))
            .unwrap();
        assert_eq!(tx.borrow().len(), 1); // the first ARP request

        // Let the resolution run out of probes.
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        // Every transmission was an ARP request: the error is not sent to the
        // wire, it is delivered back through local ingress...
        assert_eq!(tx.borrow().len(), MAX_MULTICAST_SOLICIT as usize);

        // ...where the raw socket receives it: host unreachable, from us to us,
        // quoting the queued UDP packet.
        let error = stack.raw_socket(raw_handle).recv().unwrap();
        let (msg_type, msg_code, quote) = parse_icmpv4_reply(&error, OUR_V4, OUR_V4);
        assert_eq!(msg_type, Icmpv4Message::DstUnreachable);
        assert_eq!(msg_code, Icmpv4DstUnreachable::HostUnreachable.into());

        let mut quoted = quote.clone();
        let ip = Ipv4Packet::new_checked(&mut quoted[..]).unwrap();
        assert_eq!(ip.src_addr(), OUR_V4);
        assert_eq!(ip.dst_addr(), dead);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
    }

    /// A whole IPv4 packet carrying an ICMPv4 error message quoting `quote`.
    fn icmpv4_error_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        msg_type: Icmpv4Message,
        msg_code: u8,
        quote: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + quote.len()];
        {
            let mut packet = Icmpv4Packet::new_unchecked(&mut icmp[..]);
            packet.set_msg_type(msg_type);
            packet.set_msg_code(msg_code);
            packet.clear_unused();
            packet.data_mut().copy_from_slice(quote);
            packet.fill_checksum();
        }
        ipv4_packet(src_addr, dst_addr, IpProtocol::Icmp, &icmp)
    }

    /// A whole IPv6 packet carrying an ICMPv6 error message quoting `quote`.
    fn icmpv6_error_packet(
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
        msg_type: Icmpv6Message,
        msg_code: u8,
        quote: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + quote.len()];
        {
            let mut packet = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            packet.set_msg_type(msg_type);
            packet.set_msg_code(msg_code);
            packet.clear_reserved();
            packet.payload_mut().copy_from_slice(quote);
            packet.fill_checksum(&src_addr, &dst_addr);
        }
        ipv6_packet(src_addr, dst_addr, IpProtocol::Icmpv6, &icmp)
    }

    /// End to end: the driver stamps a received frame and the metadata travels up the
    /// stack into the socket that receives it. A socket's send metadata travels back
    /// down into the driver, and the transmit timestamp it asked for comes back out of
    /// band, tagged with the packet's id.
    #[cfg(feature = "packetmeta-timestamp")]
    #[test]
    fn test_packet_meta_end_to_end() {
        use crate::driver::{PacketMeta, Timestamp, TxTimestamp};

        const RX_STAMP: Timestamp = Timestamp::from_seconds_and_nanos(4, 500);
        const TX_STAMP: Timestamp = Timestamp::from_seconds_and_nanos(9, 250);

        // A device that timestamps everything it receives, and everything it is
        // asked to timestamp on transmit.
        let mut rx_meta = PacketMeta::default();
        rx_meta.id = 0x1111;
        rx_meta.timestamp = Some(RX_STAMP);
        let driver = TestDevice::new(Medium::Ip)
            .with_rx_meta(rx_meta)
            .with_tx_stamp(TX_STAMP);
        let (rx, sent) = (driver.rx.clone(), driver.tx_meta.clone());
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let iface = driver.install(&mut stack, HardwareAddress::Ip);
        stack.iface(iface).add_ip_addr(IpCidr::new(OUR_V4.into(), 24)).unwrap();

        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(319, IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        // Ingress: driver → ethernet/IP/UDP demux → socket queue → recv.
        let datagram = udp_datagram(REMOTE_V4.into(), 319, OUR_V4.into(), 319, b"sync");
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram),
        );
        let packet = stack.udp_socket(handle).recv().unwrap();
        assert_eq!(&*packet, b"sync");
        assert_eq!(packet.meta().meta.id, 0x1111);
        assert_eq!(packet.meta().meta.timestamp, Some(RX_STAMP));

        // Egress: socket → driver, with a transmit timestamp requested.
        let mut meta: crate::udp::UdpMetadata = IpEndpoint::new(REMOTE_V4.into(), 319).into();
        meta.meta.id = 0x2222;
        meta.meta.request_timestamp = true;
        stack.udp_socket(handle).send_slice(b"delay_req", meta).unwrap();
        assert_eq!(sent.borrow().len(), 1);
        assert_eq!(sent.borrow()[0].id, 0x2222);
        assert!(sent.borrow()[0].request_timestamp);

        // ... and the timestamp comes back out of band, tagged with the id.
        assert_eq!(
            stack.iface(iface).poll_tx_timestamp(),
            Some(TxTimestamp {
                id: 0x2222,
                timestamp: TX_STAMP,
            })
        );
        assert_eq!(stack.iface(iface).poll_tx_timestamp(), None);
    }

    #[test]
    fn test_udp_icmp_error_delivery() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, (REMOTE_V4, 53)).unwrap();
        stack.udp_socket(handle).send_slice(b"query", (REMOTE_V4, 53)).unwrap();
        let sent = tx.borrow().last().unwrap().clone();

        // A port unreachable arrives, quoting the datagram we sent.
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::PortUnreachable.into(),
            &sent,
        );
        inject(&mut stack, &rx, error);

        // recv reports it once, clearing it.
        match stack.udp_socket(handle).recv() {
            Err(UdpRecvError::IcmpError { error, remote }) => {
                assert_eq!(error, IcmpError::PortUnreachable);
                assert_eq!(remote, IpEndpoint::new(REMOTE_V4.into(), 53));
            }
            other => panic!("expected icmp error, got {:?}", other),
        }
        assert_eq!(stack.udp_socket(handle).take_icmp_error(), None);
        assert!(matches!(stack.udp_socket(handle).recv(), Err(UdpRecvError::Exhausted)));
    }

    #[test]
    fn test_udp_icmp_error_no_match() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(5000, IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        // An error quoting a flow from another local port: not for this socket.
        let quote = ipv4_packet(
            OUR_V4,
            REMOTE_V4,
            IpProtocol::Udp,
            &udp_datagram(OUR_V4.into(), 6000, REMOTE_V4.into(), 53, b"x"),
        );
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::PortUnreachable.into(),
            &quote,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.udp_socket(handle).take_icmp_error(), None);
    }

    #[test]
    fn test_udp_icmp_error_delivery_v6() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, (REMOTE_V6, 53)).unwrap();
        stack.udp_socket(handle).send_slice(b"query", (REMOTE_V6, 53)).unwrap();
        let sent = tx.borrow().last().unwrap().clone();

        let error = icmpv6_error_packet(
            REMOTE_V6,
            OUR_V6,
            Icmpv6Message::DstUnreachable,
            Icmpv6DstUnreachable::PortUnreachable.into(),
            &sent,
        );
        inject(&mut stack, &rx, error);

        assert_eq!(
            stack.udp_socket(handle).take_icmp_error(),
            Some((IcmpError::PortUnreachable, IpEndpoint::new(REMOTE_V6.into(), 53)))
        );
    }

    #[test]
    fn test_neighbor_failure_reported_to_udp_socket() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(5555, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        stack.udp_socket(handle).send_slice(b"anyone?", (dead, 1000)).unwrap();

        // Let the ARP resolution run out of probes. The local destination
        // unreachable error lands on the socket, and nothing but the ARP
        // requests ever reaches the wire.
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(
            stack.udp_socket(handle).take_icmp_error(),
            Some((IcmpError::HostUnreachable, IpEndpoint::new(dead.into(), 1000)))
        );
        assert_eq!(tx.borrow().len(), MAX_MULTICAST_SOLICIT as usize);
    }

    #[test]
    fn test_tcp_connect_aborted_by_icmp_error() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
        stack.poll(Instant::ZERO);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);
        let syn = tx.borrow().last().unwrap().clone();

        // A host unreachable quoting our SYN aborts the nascent connection.
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &syn,
        );
        inject(&mut stack, &rx, error);

        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Closed);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );
    }

    #[test]
    fn test_tcp_established_icmp_error_is_soft() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
        stack.poll(Instant::ZERO);
        let syn = tx.borrow().last().unwrap().clone();

        // Complete the handshake with a crafted SYN|ACK.
        let (local_port, syn_seq) = {
            let mut bytes = syn.clone();
            let tcp = TcpPacket::new_checked(&mut bytes[IPV4_HEADER_LEN..]).unwrap();
            (tcp.src_port(), tcp.seq_number())
        };
        let mut segment = vec![0u8; TCP_HEADER_LEN];
        {
            let mut tcp = TcpPacket::new_unchecked(&mut segment[..]);
            tcp.set_src_port(80);
            tcp.set_dst_port(local_port);
            tcp.set_seq_number(TcpSeqNumber(10000));
            tcp.set_ack_number(syn_seq + 1);
            tcp.set_header_len(TCP_HEADER_LEN as u8);
            tcp.set_syn(true);
            tcp.set_ack(true);
            tcp.set_window_len(64000);
            tcp.fill_checksum(&REMOTE_V4.into(), &OUR_V4.into());
        }
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Tcp, &segment),
        );
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);

        // An error quoting an in-flight data segment is soft: recorded, not fatal.
        stack.tcp_socket(handle).send_slice(b"hello").unwrap();
        stack.poll(Instant::ZERO);
        let data_segment = tx.borrow().last().unwrap().clone();
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &data_segment,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );

        // An error quoting an out-of-window sequence number is a blind spoof:
        // ignored entirely.
        let mut forged = data_segment.clone();
        {
            let mut tcp = TcpPacket::new_unchecked(&mut forged[IPV4_HEADER_LEN..]);
            tcp.set_seq_number(TcpSeqNumber(999_999_999));
        }
        let error = icmpv4_error_packet(
            REMOTE_V4,
            OUR_V4,
            Icmpv4Message::DstUnreachable,
            Icmpv4DstUnreachable::HostUnreachable.into(),
            &forged,
        );
        inject(&mut stack, &rx, error);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Established);
        assert_eq!(stack.tcp_socket(handle).take_icmp_error(), None);
    }

    #[test]
    fn test_neighbor_failure_aborts_tcp_connect() {
        let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
        let dead = Ipv4Address::new(192, 168, 1, 99);
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
        stack.tcp_socket(handle).connect((dead, 80), 0).unwrap();

        // The SYN is queued on the unresolvable neighbor. When resolution fails, the
        // local destination unreachable error aborts the connect.
        stack.poll(Instant::ZERO);
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::Closed);
        assert_eq!(
            stack.tcp_socket(handle).take_icmp_error(),
            Some(IcmpError::HostUnreachable)
        );
        // Nothing but ARP requests ever reached the wire.
        for frame in tx.borrow().iter() {
            let mut bytes = frame.clone();
            let eth = EthernetFrame::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(eth.ethertype(), EthernetProtocol::Arp);
        }
    }

    /// An ICMPv4 echo request or reply, checksum filled in.
    fn icmpv4_echo(msg_type: Icmpv4Message, ident: u16, seq_no: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 8 + payload.len()];
        {
            let mut icmp = Icmpv4Packet::new_unchecked(&mut bytes[..]);
            icmp.set_msg_type(msg_type);
            icmp.set_msg_code(0);
            icmp.set_echo_ident(ident);
            icmp.set_echo_seq_no(seq_no);
            icmp.data_mut().copy_from_slice(payload);
            icmp.fill_checksum();
        }
        bytes
    }

    /// An ICMPv6 echo request or reply, checksum filled in.
    pub(crate) fn icmpv6_echo(
        msg_type: Icmpv6Message,
        ident: u16,
        seq_no: u16,
        payload: &[u8],
        src_addr: Ipv6Address,
        dst_addr: Ipv6Address,
    ) -> Vec<u8> {
        let mut bytes = vec![0; 8 + payload.len()];
        {
            let mut icmp = Icmpv6Packet::new_unchecked(&mut bytes[..]);
            icmp.set_msg_type(msg_type);
            icmp.set_msg_code(0);
            icmp.set_echo_ident(ident);
            icmp.set_echo_seq_no(seq_no);
            icmp.payload_mut().copy_from_slice(payload);
            icmp.fill_checksum(&src_addr, &dst_addr);
        }
        bytes
    }

    /// The ethertype of a transmitted Ethernet frame.
    fn ethertype_of(frame: &[u8]) -> EthernetProtocol {
        let mut bytes = frame.to_vec();
        EthernetFrame::new_checked(&mut bytes[..]).unwrap().ethertype()
    }

    #[test]
    fn test_iface_ip_addrs() {
        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        let iface = IfaceHandle::new(0);
        let new_addr = Ipv4Address::new(10, 0, 0, 1);

        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [
                IfaceAddr::manual(IpCidr::new(OUR_V4.into(), 24)),
                IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64))
            ]
        );
        assert!(stack.iface(iface).has_ip_addr(OUR_V4));
        assert!(!stack.iface(iface).has_ip_addr(new_addr));

        // An echo request to an address we don't have is ignored.
        let echo = ipv4_packet(
            REMOTE_V4,
            new_addr,
            IpProtocol::Icmp,
            &icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 1, &[]),
        );
        inject(&mut stack, &rx, echo.clone());
        assert!(tx.borrow().is_empty());

        // A new address is appended, and ingress starts accepting it right away.
        assert_eq!(
            stack.iface(iface).add_ip_addr(IpCidr::new(new_addr.into(), 8)).unwrap(),
            None
        );
        assert!(stack.iface(iface).has_ip_addr(new_addr));
        inject(&mut stack, &rx, echo.clone());
        assert_eq!(tx.borrow().len(), 1);
        let (msg_type, ..) = parse_icmpv4_reply(&tx.borrow()[0], new_addr, REMOTE_V4);
        assert_eq!(msg_type, Icmpv4Message::EchoReply);

        // Re-adding an address already assigned updates its prefix in place,
        // returning the CIDR it had.
        assert_eq!(
            stack
                .iface(iface)
                .add_ip_addr(IpCidr::new(new_addr.into(), 24))
                .unwrap(),
            Some(IpCidr::new(new_addr.into(), 8))
        );
        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [
                IfaceAddr::manual(IpCidr::new(OUR_V4.into(), 24)),
                IfaceAddr::manual(IpCidr::new(OUR_V6.into(), 64)),
                IfaceAddr::manual(IpCidr::new(new_addr.into(), 24)),
            ]
        );

        // Removing hands back the CIDR it was assigned with, once.
        assert_eq!(
            stack.iface(iface).remove_ip_addr(new_addr),
            Some(IpCidr::new(new_addr.into(), 24))
        );
        assert_eq!(stack.iface(iface).remove_ip_addr(new_addr), None);
        assert!(!stack.iface(iface).has_ip_addr(new_addr));

        // ...and ingress stops accepting it.
        tx.borrow_mut().clear();
        inject(&mut stack, &rx, echo);
        assert!(tx.borrow().is_empty());

        // Wholesale replacement.
        stack
            .iface(iface)
            .set_ip_addrs([IpCidr::new(new_addr.into(), 8)])
            .unwrap();
        assert_eq!(
            stack.iface(iface).ip_addrs(),
            [IfaceAddr::manual(IpCidr::new(new_addr.into(), 8))]
        );
        assert!(!stack.iface(iface).has_ip_addr(OUR_V4));
    }

    #[test]
    #[should_panic]
    fn test_iface_reject_non_unicast_ip_addr() {
        let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
        stack
            .iface(IfaceHandle::new(0))
            .add_ip_addr(IpCidr::new(Ipv4Address::new(224, 0, 0, 1).into(), 24))
            .unwrap();
    }

    /// An ARP request for [`OUR_V4`] from `remote_hw`/`remote_ip`, as an Ethernet
    /// frame. Processing it teaches the stack the sender's mapping.
    #[cfg(feature = "medium-ethernet")]
    fn arp_request_from(remote_hw: EthernetAddress, remote_ip: Ipv4Address) -> Vec<u8> {
        let mut request = vec![0; ETHERNET_HEADER_LEN + ARP_BUFFER_LEN];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut request[..]);
            eth.set_dst_addr(EthernetAddress::BROADCAST);
            eth.set_src_addr(remote_hw);
            eth.set_ethertype(EthernetProtocol::Arp);
            let mut arp = ArpPacket::new_unchecked(&mut request[ETHERNET_HEADER_LEN..]);
            arp.set_hardware_type(ArpHardware::Ethernet);
            arp.set_protocol_type(EthernetProtocol::Ipv4);
            arp.set_hardware_len(6);
            arp.set_protocol_len(4);
            arp.set_operation(ArpOperation::Request);
            arp.set_source_hardware_addr(remote_hw.as_bytes());
            arp.set_source_protocol_addr(&remote_ip.octets());
            arp.set_target_hardware_addr(&[0; 6]);
            arp.set_target_protocol_addr(&OUR_V4.octets());
        }
        request
    }

    /// A device with no room holds socket sends back with `DeviceBusy`, and never
    /// loses a packet: the same send goes through once there is room.
    #[test]
    #[cfg(all(feature = "raw-ethernet", feature = "ipv4", feature = "udp", feature = "raw-ip"))]
    fn test_device_full_holds_sends_back() {
        let (mut stack, rx, tx, room) = test_stack_with_room(Medium::Ethernet);
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        inject(&mut stack, &rx, arp_request_from(remote_hw, REMOTE_V4));
        tx.borrow_mut().clear();

        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();
        let raw = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(raw)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();
        let raw_ip = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(raw_ip)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();
        let mut frame = vec![0; ETHERNET_HEADER_LEN + 4];
        EthernetFrame::new_unchecked(&mut frame[..]).set_ethertype(EthernetProtocol::Ipv4);
        let packet = ipv4_packet(OUR_V4, REMOTE_V4, IpProtocol::Udp, &[0; 8]);

        room.set(Some(0));
        assert_eq!(
            stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)),
            Err(crate::udp::SendError::DeviceBusy)
        );
        assert_eq!(
            stack.raw_socket(raw).send_slice(&frame),
            Err(crate::raw::SendError::DeviceBusy)
        );
        assert_eq!(
            stack.raw_socket(raw_ip).send_slice(&packet),
            Err(crate::raw::SendError::DeviceBusy)
        );
        assert!(tx.borrow().is_empty());

        room.set(Some(3));
        stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
        stack.raw_socket(raw).send_slice(&frame).unwrap();
        stack.raw_socket(raw_ip).send_slice(&packet).unwrap();
        assert_eq!(tx.borrow().len(), 3);
        assert_eq!(room.get(), Some(0));
    }

    /// Packets parked on a neighbor resolution stay parked if the device has no
    /// room when the resolution comes in, and go out on a later poll.
    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4", feature = "udp"))]
    fn test_device_full_keeps_packets_parked() {
        let (mut stack, rx, tx, room) = test_stack_with_room(Medium::Ethernet);
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();

        // Two datagrams park on the unresolved neighbor. Only the ARP request
        // reaches the wire.
        room.set(Some(2));
        stack.udp_socket(udp).send_slice(b"one", (REMOTE_V4, 1000)).unwrap();
        stack.udp_socket(udp).send_slice(b"two", (REMOTE_V4, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(ethertype_of(&tx.borrow()[0]), EthernetProtocol::Arp);

        // The neighbor resolves while the device is full: nothing is flushed and
        // nothing is lost. (The ARP reply we owe is best-effort and is dropped.)
        room.set(Some(0));
        inject(&mut stack, &rx, arp_request_from(remote_hw, REMOTE_V4));
        assert_eq!(tx.borrow().len(), 1);

        // Room for one: the first parked datagram goes out, the second waits.
        room.set(Some(1));
        stack.poll(Instant::ZERO);
        assert_eq!(tx.borrow().len(), 2);
        assert_eq!(ethertype_of(&tx.borrow()[1]), EthernetProtocol::Ipv4);
        assert!(tx.borrow()[1].ends_with(b"one"));

        room.set(None);
        stack.poll(Instant::ZERO);
        assert_eq!(tx.borrow().len(), 3);
        assert!(tx.borrow()[2].ends_with(b"two"));
    }

    /// TCP holds a segment back while the device is full, leaving the socket as
    /// if it had never tried, and does not ask to be polled again for it: the
    /// device wakes the poll task when it has room.
    #[test]
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4", feature = "tcp"))]
    fn test_device_full_holds_tcp_segment_back() {
        let (mut stack, rx, tx, room) = test_stack_with_room(Medium::Ethernet);
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        inject(&mut stack, &rx, arp_request_from(remote_hw, REMOTE_V4));
        tx.borrow_mut().clear();

        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();

        room.set(Some(0));
        for secs in 0..5 {
            assert_eq!(stack.poll(Instant::from_secs(secs)), Instant::MAX);
        }
        assert!(tx.borrow().is_empty());
        assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);

        // With room, the SYN goes out once, and the retransmit timer is armed
        // only now.
        room.set(Some(1));
        let deadline = stack.poll(Instant::from_secs(5));
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(ethertype_of(&tx.borrow()[0]), EthernetProtocol::Ipv4);
        assert!(deadline > Instant::from_secs(5) && deadline < Instant::MAX);
        assert_eq!(stack.poll(Instant::from_secs(5)), deadline);
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_iface_addr_change_invalidates_link_state() {
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        let iface = IfaceHandle::new(0);
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);

        // Learn the remote's hardware address from an ARP request for us.
        inject(&mut stack, &rx, arp_request_from(remote_hw, REMOTE_V4));
        assert_eq!(tx.borrow().len(), 1); // the ARP reply
        assert_eq!(ethertype_of(&tx.borrow()[0]), EthernetProtocol::Arp);

        // The neighbor is now resolved: a datagram to it goes out immediately.
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();
        stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 2);
        assert_eq!(ethertype_of(&tx.borrow()[1]), EthernetProtocol::Ipv4);

        // Queue a packet on a neighbor that will never answer.
        let dead = Ipv4Address::new(192, 168, 1, 99);
        stack.udp_socket(udp).send_slice(b"anyone?", (dead, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 3);
        assert_eq!(ethertype_of(&tx.borrow()[2]), EthernetProtocol::Arp);

        // Changing the interface's addresses invalidates both: the queued packet
        // is dropped (no solicitation is ever retransmitted for it)...
        stack
            .iface(iface)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)])
            .unwrap();
        for secs in 1..=4 {
            stack.poll(Instant::ZERO + Duration::from_secs(secs));
        }
        assert_eq!(tx.borrow().len(), 3);

        // ...and the learned mapping is gone, so the next datagram to the remote
        // has to resolve it again.
        stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
        assert_eq!(tx.borrow().len(), 4);
        assert_eq!(ethertype_of(&tx.borrow()[3]), EthernetProtocol::Arp);
    }

    /// An Ethernet frame carrying a neighbor solicitation from `remote_hw`/`remote_ll`
    /// for `target`, sent to `dst_addr`, with a source link-layer address option.
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    fn neighbor_solicit(
        remote_hw: EthernetAddress,
        remote_ll: Ipv6Address,
        dst_addr: Ipv6Address,
        target: Ipv6Address,
    ) -> Vec<u8> {
        let mut icmp = vec![0; 24 + 8];
        {
            let mut ns = Icmpv6Packet::new_unchecked(&mut icmp[..]);
            ns.set_msg_type(Icmpv6Message::NeighborSolicit);
            ns.set_msg_code(0);
            ns.clear_reserved();
            ns.set_target_addr(target);
            {
                let mut opt = NdiscOption::new_unchecked(ns.payload_mut());
                opt.set_option_type(NdiscOptionType::SourceLinkLayerAddr);
                opt.set_data_len(1);
                opt.set_link_layer_addr(RawHardwareAddress::from(remote_hw));
            }
            ns.fill_checksum(&remote_ll, &dst_addr);
        }
        let mut ip = ipv6_packet(remote_ll, dst_addr, IpProtocol::Icmpv6, &icmp);
        Ipv6Packet::new_unchecked(&mut ip[..]).set_hop_limit(255);

        let mut frame = vec![0; ETHERNET_HEADER_LEN];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame[..]);
            eth.set_dst_addr(OUR_HW);
            eth.set_src_addr(remote_hw);
            eth.set_ethertype(EthernetProtocol::Ipv6);
        }
        frame.extend_from_slice(&ip);
        frame
    }

    /// A neighbor solicitation is answered whether its destination is the target's
    /// solicited-node multicast address (address resolution) or one of our unicast
    /// addresses (a NUD probe), RFC 4861 §7.2.3.
    #[test]
    #[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
    fn test_ndisc_solicit_multicast_and_unicast() {
        let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
        let remote_ll = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);

        for dst_addr in [OUR_LINK_LOCAL.solicited_node(), OUR_LINK_LOCAL] {
            let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
            inject(
                &mut stack,
                &rx,
                neighbor_solicit(remote_hw, remote_ll, dst_addr, OUR_LINK_LOCAL),
            );

            let tx = tx.borrow();
            assert_eq!(tx.len(), 1, "no advert for a solicitation to {dst_addr}");
            let mut bytes = tx[0][ETHERNET_HEADER_LEN..].to_vec();
            let ip = Ipv6Packet::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(ip.src_addr(), OUR_LINK_LOCAL);
            assert_eq!(ip.dst_addr(), remote_ll);
            let mut icmp_bytes = bytes[IPV6_HEADER_LEN..].to_vec();
            let na = Icmpv6Packet::new_checked(&mut icmp_bytes[..]).unwrap();
            assert!(na.verify_checksum(&OUR_LINK_LOCAL, &remote_ll));
            assert_eq!(na.msg_type(), Icmpv6Message::NeighborAdvert);
            assert_eq!(na.target_addr(), OUR_LINK_LOCAL);
            assert!(na.neighbor_flags().contains(NdiscNeighborFlags::SOLICITED));
        }

        // A solicitation whose target is not our address is not answered, even
        // when addressed to our unicast address.
        let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
        inject(
            &mut stack,
            &rx,
            neighbor_solicit(remote_hw, remote_ll, OUR_LINK_LOCAL, remote_ll),
        );
        assert!(tx.borrow().is_empty());
    }

    // ===== IPv4 fragmentation and reassembly =====

    #[cfg(feature = "ipv4-fragmentation")]
    use crate::wire::IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;

    #[cfg(any(feature = "ipv4-fragmentation", feature = "ipv4-reassembly"))]
    const REMOTE_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);

    /// The link-layer header an interface of this medium puts in front of an IP packet.
    #[cfg(feature = "ipv4-fragmentation")]
    fn link_header_len(medium: Medium) -> usize {
        match medium {
            Medium::Ethernet => ETHERNET_HEADER_LEN,
            Medium::Ip => 0,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => unreachable!(),
        }
    }

    /// An IP packet as it arrives on an interface of this medium: as-is on an IP
    /// medium, in an Ethernet frame from [`REMOTE_HW`] to us on Ethernet.
    #[cfg(feature = "ipv4-reassembly")]
    fn ingress_frame(medium: Medium, ethertype: EthernetProtocol, packet: &[u8]) -> Vec<u8> {
        match medium {
            Medium::Ip => packet.to_vec(),
            Medium::Ethernet => {
                let mut frame = vec![0; ETHERNET_HEADER_LEN + packet.len()];
                {
                    let mut eth = EthernetFrame::new_unchecked(&mut frame[..]);
                    eth.set_dst_addr(OUR_HW);
                    eth.set_src_addr(REMOTE_HW);
                    eth.set_ethertype(ethertype);
                }
                frame[ETHERNET_HEADER_LEN..].copy_from_slice(packet);
                frame
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => unreachable!(),
        }
    }

    /// One fragment of an IPv4 packet as on-the-wire bytes, header checksum filled in.
    #[cfg(feature = "ipv4-reassembly")]
    #[allow(clippy::too_many_arguments)]
    fn ipv4_fragment(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        protocol: IpProtocol,
        ident: u16,
        more_frags: bool,
        frag_offset_octets: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = ipv4_packet(src_addr, dst_addr, protocol, payload);
        {
            let mut pkt = Ipv4Packet::new_unchecked(&mut bytes[..]);
            pkt.set_ident(ident);
            pkt.set_dont_frag(false);
            pkt.set_more_frags(more_frags);
            pkt.set_frag_offset(frag_offset_octets);
            // Recompute checksum after changing fragmentation fields.
            pkt.fill_checksum();
        }
        bytes
    }

    /// Check the frames a fragmented IPv4 packet went out as: every one fits the
    /// device MTU, carries the same identification, and the payloads are 8-aligned
    /// except the last one's and add up to `payload_len`. Returns the payload.
    #[cfg(feature = "ipv4-fragmentation")]
    fn check_fragments(frames: &[Vec<u8>], medium: Medium, mtu: usize, payload_len: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        let mut ident = None;
        for (i, frame) in frames.iter().enumerate() {
            assert!(
                frame.len() <= mtu,
                "frame of {} octets exceeds the MTU of {}",
                frame.len(),
                mtu
            );
            let mut bytes = frame[link_header_len(medium)..].to_vec();
            let ip = Ipv4Packet::new_checked(&mut bytes[..]).unwrap();
            assert!(ip.verify_checksum());
            assert_eq!(ip.frag_offset() as usize, payload.len());
            assert_eq!(ip.more_frags(), i + 1 < frames.len());
            if frames.len() > 1 {
                assert!(!ip.dont_frag());
                assert_eq!(*ident.get_or_insert(ip.ident()), ip.ident());
            }
            // Verify the payload size is aligned.
            if ip.more_frags() {
                assert!(ip.payload().len().is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT));
            }
            payload.extend_from_slice(ip.payload());
        }
        // The fragment offset should be the complete payload length once transmission is complete.
        assert_eq!(payload.len(), payload_len);
        payload
    }

    /// An IPv4 packet of any size goes out in frames no larger than the device MTU.
    #[test]
    #[cfg(feature = "ipv4-fragmentation")]
    fn test_packet_len() {
        for medium in [Medium::Ip, Medium::Ethernet] {
            let mtu = 576;
            let (mut stack, rx, tx, _room) = test_stack_with_mtu(medium, mtu);
            if medium == Medium::Ethernet {
                inject(&mut stack, &rx, arp_request_from(REMOTE_HW, REMOTE_V4));
            }
            let ip_mtu = stack.iface(IfaceHandle::new(0)).ip_mtu();

            for ip_packet_len in [
                100,
                ip_mtu,
                ip_mtu + 1,
                crate::driver::config::PACKET_BUF_SIZE - LINK_HEADER_LEN,
            ] {
                tx.borrow_mut().clear();

                let ip_packet_payload_len = ip_packet_len - IPV4_HEADER_LEN;
                let udp_packet_payload_len = ip_packet_payload_len - UDP_HEADER_LEN;

                let udp_packet_payload = vec![1; udp_packet_payload_len];
                let datagram = udp_datagram(OUR_V4.into(), 12345, REMOTE_V4.into(), 54321, &udp_packet_payload);

                let mut buf = PacketBuf::try_new().unwrap();
                buf.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
                buf.set_len(datagram.len());
                buf.copy_from_slice(&datagram);

                let mut cx = stack.tx_context();
                let route = cx.route(IfaceBinding::Any, &REMOTE_V4.into()).unwrap();
                cx.transmit_ip(&route, buf, OUR_V4.into(), REMOTE_V4.into(), IpProtocol::Udp, 64);

                let frames = tx.borrow();
                assert!(!frames.is_empty(), "ip_packet_len: {}", ip_packet_len);
                assert_eq!(frames.len() > 1, ip_packet_len > ip_mtu);
                let payload = check_fragments(&frames, medium, mtu, ip_packet_payload_len);
                assert_eq!(payload, datagram);
            }
        }
    }

    /// Raw IPv4 packets of any size are sent, fragmented on 8-octet boundaries when
    /// larger than the MTU. While the fragments of one are still going out, the
    /// device is busy for the sockets.
    #[test]
    #[cfg(all(feature = "raw-ip", feature = "ipv4-fragmentation"))]
    fn test_raw_socket_tx_fragmentation() {
        for medium in [Medium::Ip, Medium::Ethernet] {
            // An MTU whose IP payload is not a multiple of the fragment alignment on
            // either medium. This check ensures a valid test in which we actually do
            // adjust for alignment.
            let mtu = 600;
            let (mut stack, _rx, tx, room) = test_stack_with_mtu(medium, mtu);
            let ip_mtu = stack.iface(IfaceHandle::new(0)).ip_mtu();
            let unaligned_length = ip_mtu - IPV4_HEADER_LEN;
            assert!(!unaligned_length.is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT));

            let handle = stack.add_raw_socket().unwrap();
            stack
                .raw_socket(handle)
                .bind(RawMode::Ip {
                    version: Some(IpVersion::Ipv4),
                    protocol: Some(IpProtocol(92)),
                })
                .unwrap();

            let tx_packet_sizes = [
                ip_mtu * 3 / 4, // Smaller than MTU
                ip_mtu * 5 / 4, // Larger than MTU, requires fragmentation
                ip_mtu * 9 / 4, // Much larger, requires two fragments
            ];

            for packet_size in tx_packet_sizes {
                tx.borrow_mut().clear();
                let payload_len = packet_size - IPV4_HEADER_LEN;
                let payload = vec![0u8; payload_len];
                let packet = ipv4_packet(
                    Ipv4Address::new(192, 168, 1, 3),
                    Ipv4Address::BROADCAST,
                    IpProtocol(92),
                    &payload,
                );

                // Let one frame out at a time, to look at the fragmenter in between.
                room.set(Some(1));
                stack.raw_socket(handle).send_slice(&packet).unwrap();
                assert_eq!(tx.borrow().len(), 1);

                // Perform payload size checks if fragmentation is required.
                if packet_size <= ip_mtu {
                    assert!(stack.ifaces.get(0).fragmenter.is_empty());
                    assert_eq!(tx.borrow()[0].len(), link_header_len(medium) + packet_size);
                    continue;
                }

                // Verify that the fragment offset is correct.
                let remainder = unaligned_length % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT;
                let expected_fragment_offset = ip_mtu - IPV4_HEADER_LEN - remainder;
                let frag_offset = stack.ifaces.get(0).fragmenter.ipv4.frag_offset;
                assert_eq!(frag_offset as usize, expected_fragment_offset);

                // The remaining fragments have first claim on the device: a socket
                // is held back even when the device itself has room.
                room.set(Some(1));
                assert_eq!(
                    stack.raw_socket(handle).send_slice(&packet),
                    Err(crate::raw::SendError::DeviceBusy)
                );
                assert_eq!(tx.borrow().len(), 1);

                // Check subsequent fragment sizes if applicable.
                if packet_size / ip_mtu == 2 {
                    // Two fragments are left. The intermediate fragment must be aligned.
                    stack.poll(Instant::ZERO);
                    assert_eq!(tx.borrow().len(), 2);
                    assert!(!stack.ifaces.get(0).fragmenter.is_empty());
                    room.set(Some(1));
                }
                // Process the final fragment. It is the remainder of the data and does not have to be aligned.
                stack.poll(Instant::ZERO);
                assert!(stack.ifaces.get(0).fragmenter.is_empty());
                assert_eq!(tx.borrow().len(), packet_size.div_ceil(ip_mtu));

                let frames = tx.borrow();
                let sent = check_fragments(&frames, medium, mtu, payload_len);
                assert_eq!(sent, payload);
            }
        }
    }

    /// The fragments of an incoming IPv4 packet are reassembled before the packet
    /// is offered to the raw sockets, which see only the whole packet.
    #[test]
    #[cfg(all(feature = "raw-ip", feature = "ipv4-reassembly"))]
    fn test_raw_socket_rx_fragmentation() {
        for medium in [Medium::Ip, Medium::Ethernet] {
            let (mut stack, rx, _tx) = test_stack(medium);

            // Raw socket bound to IPv4 and a custom protocol.
            let handle = stack.add_raw_socket().unwrap();
            stack
                .raw_socket(handle)
                .bind(RawMode::Ip {
                    version: Some(IpVersion::Ipv4),
                    protocol: Some(IpProtocol(99)),
                })
                .unwrap();

            // Build two IPv4 fragments that together form one packet.
            let src_addr = REMOTE_V4;
            let dst_addr = OUR_V4;
            let proto = IpProtocol(99);
            let ident: u16 = 0x1234;

            let total_payload_len = 30usize;
            let first_payload_len = 24usize; // must be a multiple of 8
            let last_payload_len = total_payload_len - first_payload_len;

            let frag1_bytes = ipv4_fragment(
                src_addr,
                dst_addr,
                proto,
                ident,
                true,
                0,
                &vec![0xAA; first_payload_len],
            );
            let frag2_bytes = ipv4_fragment(
                src_addr,
                dst_addr,
                proto,
                ident,
                false,
                first_payload_len as u16,
                &vec![0xBB; last_payload_len],
            );

            // First fragment alone should not be delivered to the raw socket.
            inject(
                &mut stack,
                &rx,
                ingress_frame(medium, EthernetProtocol::Ipv4, &frag1_bytes),
            );
            assert!(!stack.raw_socket(handle).can_recv());

            // After the last fragment, the reassembled packet should be delivered.
            inject(
                &mut stack,
                &rx,
                ingress_frame(medium, EthernetProtocol::Ipv4, &frag2_bytes),
            );

            // Validate the raw socket received one defragmented packet with correct payload.
            assert!(stack.raw_socket(handle).can_recv());
            let mut data = stack
                .raw_socket(handle)
                .recv()
                .expect("raw socket should have a packet");
            let packet = Ipv4Packet::new_checked(&mut data[..]).unwrap();
            assert!(packet.verify_checksum());
            assert_eq!(packet.src_addr(), src_addr);
            assert_eq!(packet.dst_addr(), dst_addr);
            assert_eq!(packet.next_header(), proto);
            assert!(!packet.more_frags());
            assert_eq!(packet.frag_offset(), 0);
            assert_eq!(packet.total_len() as usize, IPV4_HEADER_LEN + total_payload_len);

            let payload = packet.payload();
            assert_eq!(payload.len(), total_payload_len);
            assert!(payload[..first_payload_len].iter().all(|&b| b == 0xAA));
            assert!(payload[first_payload_len..].iter().all(|&b| b == 0xBB));

            assert!(!stack.raw_socket(handle).can_recv());
        }
    }

    /// A datagram larger than the MTU goes out fragmented and, fed back in with
    /// the fragments out of order, is reassembled and delivered to the UDP socket
    /// whole.
    #[test]
    #[cfg(all(
        feature = "raw-ip",
        feature = "udp",
        feature = "ipv4-fragmentation",
        feature = "ipv4-reassembly"
    ))]
    fn test_ipv4_fragmentation_roundtrip() {
        let mtu = 576;
        let (mut stack, rx, tx) = {
            let (stack, rx, tx, _room) = test_stack_with_mtu(Medium::Ip, mtu);
            (stack, rx, tx)
        };

        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(5555, IpListenEndpoint::UNSPECIFIED).unwrap();

        // A raw socket can send from any source address: build the datagram as
        // if the remote had sent it to us, so the fragments can be fed back in.
        let raw = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(raw)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: None,
            })
            .unwrap();
        let payload: Vec<u8> = (0..1400u32).map(|i| i as u8).collect();
        let datagram = udp_datagram(REMOTE_V4.into(), 1000, OUR_V4.into(), 5555, &payload);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);
        stack.raw_socket(raw).send_slice(&packet).unwrap();

        let frames = tx.borrow().clone();
        assert_eq!(frames.len(), 3);
        assert_eq!(check_fragments(&frames, Medium::Ip, mtu, datagram.len()), datagram);

        // Nothing arrives until the last fragment does.
        for frame in frames.iter().rev() {
            assert!(!stack.udp_socket(udp).can_recv());
            inject(&mut stack, &rx, frame.clone());
        }
        let mut got = vec![0; 2048];
        let (len, meta) = stack.udp_socket(udp).recv_slice(&mut got).unwrap();
        assert_eq!(&got[..len], &payload[..]);
        assert_eq!(meta.endpoint, IpEndpoint::new(REMOTE_V4.into(), 1000));
        assert!(!stack.udp_socket(udp).can_recv());
    }

    /// Fragments of a packet that never completes are dropped when the reassembly
    /// timeout expires, and `poll` asks to be called then.
    #[test]
    #[cfg(all(feature = "raw-ip", feature = "ipv4-reassembly"))]
    fn test_ipv4_reassembly_timeout() {
        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::Ipv4),
                protocol: Some(IpProtocol(99)),
            })
            .unwrap();
        stack.set_reassembly_timeout(Duration::from_secs(10));
        assert_eq!(stack.reassembly_timeout(), Duration::from_secs(10));

        let proto = IpProtocol(99);
        let frag1 = ipv4_fragment(REMOTE_V4, OUR_V4, proto, 0x1234, true, 0, &[0xAA; 24]);
        let frag2 = ipv4_fragment(REMOTE_V4, OUR_V4, proto, 0x1234, false, 24, &[0xBB; 6]);

        // The first fragment starts the timeout.
        assert_eq!(stack.poll(Instant::ZERO), Instant::MAX);
        rx.borrow_mut().push_back(frag1.clone());
        assert_eq!(stack.poll(Instant::from_secs(1)), Instant::from_secs(11));
        assert!(!stack.raw_socket(handle).can_recv());

        // Past the timeout the fragment is forgotten: the last fragment alone does
        // not complete the packet, it starts a new reassembly instead.
        assert_eq!(stack.poll(Instant::from_secs(12)), Instant::MAX);
        rx.borrow_mut().push_back(frag2.clone());
        assert_eq!(stack.poll(Instant::from_secs(12)), Instant::from_secs(22));
        assert!(!stack.raw_socket(handle).can_recv());

        // Within the timeout, both fragments make the packet.
        rx.borrow_mut().push_back(frag1);
        assert_eq!(stack.poll(Instant::from_secs(13)), Instant::MAX);
        assert!(stack.raw_socket(handle).can_recv());
        assert_eq!(stack.raw_socket(handle).recv().unwrap().len(), IPV4_HEADER_LEN + 30);
    }

    #[test]
    #[cfg(feature = "ipv4-fragmentation")]
    fn test_ipv4_fragment_size() {
        let (stack, _, _) = test_stack(Medium::Ip);
        for i in 0..IPV4_FRAGMENT_PAYLOAD_ALIGNMENT {
            assert!(
                stack
                    .ifaces
                    .get(0)
                    .max_ipv4_fragment_size(IPV4_HEADER_LEN + i)
                    .is_multiple_of(IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
            );
        }
    }
    // ===== Checksum offload =====

    /// Which direction each `Checksum` variant covers.
    #[test]
    fn test_checksum_directions() {
        assert!(Checksum::Both.rx() && Checksum::Both.tx());
        assert!(Checksum::Rx.rx() && !Checksum::Rx.tx());
        assert!(!Checksum::Tx.rx() && Checksum::Tx.tx());
        assert!(!Checksum::None.rx() && !Checksum::None.tx());
        // The default is doing everything in software.
        assert_eq!(Checksum::default(), Checksum::Both);
        assert_eq!(ChecksumCapabilities::default().udp, Checksum::Both);
        assert_eq!(ChecksumCapabilities::ignored().udp, Checksum::None);
    }

    /// Corrupt the checksum field at `offset` of `packet`.
    fn corrupt_checksum(packet: &mut [u8], offset: usize) {
        packet[offset] ^= 0xff;
        packet[offset + 1] ^= 0xff;
    }

    /// The checksum field at `offset` of `packet`.
    fn checksum_at(packet: &[u8], offset: usize) -> u16 {
        u16::from_be_bytes([packet[offset], packet[offset + 1]])
    }

    /// Offset of the checksum field within an IPv4 header, an ICMP message, and a
    /// UDP or TCP header.
    const IPV4_CHECKSUM: usize = 10;
    const ICMP_CHECKSUM: usize = 2;
    const UDP_CHECKSUM: usize = 6;
    const TCP_CHECKSUM: usize = 16;

    /// A device that verifies the IPv4 header checksum itself: a packet with a bad
    /// one is processed anyway. With the default capabilities it is dropped.
    #[test]
    fn test_checksum_offload_rx_ipv4() {
        let request = icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 7, b"ping");
        let mut packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Icmp, &request);
        corrupt_checksum(&mut packet, IPV4_CHECKSUM);

        let mut caps = ChecksumCapabilities::default();
        caps.ipv4 = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);

        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    /// Same for the ICMPv4 checksum.
    #[test]
    fn test_checksum_offload_rx_icmpv4() {
        let mut request = icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 7, b"ping");
        corrupt_checksum(&mut request, ICMP_CHECKSUM);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Icmp, &request);

        let mut caps = ChecksumCapabilities::default();
        caps.icmpv4 = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);

        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    /// Same for the ICMPv6 checksum.
    #[test]
    fn test_checksum_offload_rx_icmpv6() {
        let mut request = icmpv6_echo(Icmpv6Message::EchoRequest, 0x1234, 7, b"ping", REMOTE_V6, OUR_V6);
        corrupt_checksum(&mut request, ICMP_CHECKSUM);
        let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Icmpv6, &request);

        let mut caps = ChecksumCapabilities::default();
        caps.icmpv6 = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);

        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    /// Same for the UDP checksum: the datagram reaches the socket regardless.
    #[test]
    fn test_checksum_offload_rx_udp() {
        let mut datagram = udp_datagram(REMOTE_V4.into(), 5000, OUR_V4.into(), 5000, b"hello");
        corrupt_checksum(&mut datagram, UDP_CHECKSUM);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram);

        let mut caps = ChecksumCapabilities::default();
        caps.udp = Checksum::None;
        let (mut stack, rx, _tx) = test_stack_with_checksum(Medium::Ip, caps);
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(5000, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(&*stack.udp_socket(handle).recv().unwrap(), b"hello");

        let (mut stack, rx, _tx) = test_stack(Medium::Ip);
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(5000, IpListenEndpoint::UNSPECIFIED)
            .unwrap();
        inject(&mut stack, &rx, packet);
        assert!(!stack.udp_socket(handle).can_recv());
    }

    /// Same for the TCP checksum: a segment to no socket is answered with an RST
    /// regardless, where the stack would otherwise have dropped it.
    #[test]
    fn test_checksum_offload_rx_tcp() {
        let mut segment = {
            let repr = TcpRepr {
                src_port: 1234,
                dst_port: 80,
                control: TcpControl::Syn,
                seq_number: TcpSeqNumber(0),
                ack_number: None,
                window_len: 1000,
                window_scale: None,
                max_seg_size: None,
                #[cfg(feature = "tcp-sack")]
                sack_permitted: false,
                #[cfg(feature = "tcp-sack")]
                sack_ranges: [None; 3],
                #[cfg(feature = "tcp-timestamps")]
                timestamp: None,
                payload: &[],
                payload2: &[],
            };
            let mut bytes = vec![0; repr.buffer_len()];
            let mut packet = TcpPacket::new_unchecked(&mut bytes[..]);
            repr.emit(
                &mut packet,
                &REMOTE_V4.into(),
                &OUR_V4.into(),
                &ChecksumCapabilities::default(),
            );
            bytes
        };
        corrupt_checksum(&mut segment, TCP_CHECKSUM);
        let packet = ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Tcp, &segment);

        let mut caps = ChecksumCapabilities::default();
        caps.tcp = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        inject(&mut stack, &rx, packet.clone());
        assert_eq!(tx.borrow().len(), 1);

        let (mut stack, rx, tx) = test_stack(Medium::Ip);
        inject(&mut stack, &rx, packet);
        assert!(tx.borrow().is_empty());
    }

    /// A device that computes the IPv4 header checksum itself gets the field
    /// zeroed, not filled in.
    #[test]
    fn test_checksum_offload_tx_ipv4() {
        let mut caps = ChecksumCapabilities::default();
        caps.ipv4 = Checksum::None;
        let (mut stack, _rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, (REMOTE_V4, 5000)).unwrap();
        stack
            .udp_socket(handle)
            .send_slice(b"hello", (REMOTE_V4, 5000))
            .unwrap();

        let tx = tx.borrow();
        assert_eq!(checksum_at(&tx[0], IPV4_CHECKSUM), 0);
        // The UDP checksum is not offloaded, so it is still computed.
        assert!(
            UdpPacket::new_checked(&mut tx[0][IPV4_HEADER_LEN..].to_vec()[..])
                .unwrap()
                .verify_checksum(&REMOTE_V4.into(), &OUR_V4.into())
        );
    }

    /// Same for the UDP checksum.
    #[test]
    fn test_checksum_offload_tx_udp() {
        let mut caps = ChecksumCapabilities::default();
        caps.udp = Checksum::None;
        let (mut stack, _rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, (REMOTE_V4, 5000)).unwrap();
        stack
            .udp_socket(handle)
            .send_slice(b"hello", (REMOTE_V4, 5000))
            .unwrap();

        let tx = tx.borrow();
        assert_eq!(checksum_at(&tx[0], IPV4_HEADER_LEN + UDP_CHECKSUM), 0);
        // The IPv4 header checksum is not offloaded, so it is still computed.
        assert!(
            Ipv4Packet::new_checked(&mut tx[0].clone()[..])
                .unwrap()
                .verify_checksum()
        );
    }

    /// Same for the TCP checksum, on the SYN a connect sends.
    #[test]
    fn test_checksum_offload_tx_tcp() {
        let mut caps = ChecksumCapabilities::default();
        caps.tcp = Checksum::None;
        let (mut stack, _rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        let handle = stack
            .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
            .unwrap();
        stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
        stack.poll(Instant::ZERO);

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        assert_eq!(checksum_at(&tx[0], IPV4_HEADER_LEN + TCP_CHECKSUM), 0);
    }

    /// Same for the ICMPv4 checksum, on an echo reply (built in the request's own
    /// buffer) and on an ICMP error (built from scratch).
    #[test]
    fn test_checksum_offload_tx_icmpv4() {
        let mut caps = ChecksumCapabilities::default();
        caps.icmpv4 = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);

        let request = icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 7, b"ping");
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Icmp, &request),
        );
        assert_eq!(checksum_at(&tx.borrow()[0], IPV4_HEADER_LEN + ICMP_CHECKSUM), 0);
        tx.borrow_mut().clear();

        // A protocol unreachable error, quoting a packet of an unknown protocol.
        inject(
            &mut stack,
            &rx,
            ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol(0xfe), b"payload"),
        );
        assert_eq!(checksum_at(&tx.borrow()[0], IPV4_HEADER_LEN + ICMP_CHECKSUM), 0);
    }

    /// Same for the ICMPv6 checksum, on an echo reply and on a neighbor
    /// solicitation the stack sends on its own.
    #[test]
    fn test_checksum_offload_tx_icmpv6() {
        let mut caps = ChecksumCapabilities::default();
        caps.icmpv6 = Checksum::None;
        let (mut stack, rx, tx) = test_stack_with_checksum(Medium::Ip, caps);
        let request = icmpv6_echo(Icmpv6Message::EchoRequest, 0x1234, 7, b"ping", REMOTE_V6, OUR_V6);
        inject(
            &mut stack,
            &rx,
            ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::Icmpv6, &request),
        );
        assert_eq!(checksum_at(&tx.borrow()[0], IPV6_HEADER_LEN + ICMP_CHECKSUM), 0);

        // The neighbor solicitation an Ethernet interface sends to resolve a peer.
        let (mut stack, _rx, tx) = test_stack_with_checksum(Medium::Ethernet, caps);
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind(5000, (REMOTE_V6, 5000)).unwrap();
        stack
            .udp_socket(handle)
            .send_slice(b"hello", (REMOTE_V6, 5000))
            .unwrap();

        let tx = tx.borrow();
        assert_eq!(tx.len(), 1);
        assert_eq!(
            checksum_at(&tx[0], ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + ICMP_CHECKSUM),
            0
        );
    }
}
