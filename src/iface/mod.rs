//! Network interfaces.
//!
//! An interface is a [`Driver`] added to a [`Stack`], together with its
//! configuration: hardware address, IP addresses, and whatever address
//! autoconfiguration is turned on for it.
//!
//! The two autoconfiguration methods are [`dhcpv4`] and [`slaac`], each turned
//! on per interface and driven by [`Stack::poll`].
//!
//! An interface can also hand out addresses itself, as a [`dhcpv4_server`].

#[cfg(feature = "dhcpv4")]
pub mod dhcpv4;
#[cfg(feature = "dhcpv4-server")]
pub mod dhcpv4_server;
#[cfg(feature = "slaac")]
pub mod slaac;

#[cfg(feature = "multicast")]
pub use crate::multicast::MulticastError;

use crate::config::{IFACE_ADDR_COUNT, IFACE_COUNT};
use crate::driver::config::PACKET_BUF_SIZE;
use crate::driver::{Capabilities, ChecksumCapabilities, Driver, LinkState};
#[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
use crate::fragmentation::Fragmenter;
use crate::stack::{Stack, StackInner};
use crate::storage::{Full, MaybeBox, Slab, Vec};
use crate::time::Instant;
use crate::wire::*;

define_handle! {
    /// A handle to an interface added to a [`Stack`].
    IfaceHandle(crate::config::iface_index)
}

/// Type of medium of an interface.
///
/// This is the stack's own medium type: which variants exist depends on the
/// enabled `medium-*` features. Drivers report the feature-independent
/// [`crate::driver::Medium`] instead; the stack converts when the interface is
/// added, and rejects media the build does not support.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Medium {
    /// Ethernet medium. Devices of this type send and receive Ethernet frames.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,

    /// IP medium. Devices of this type send and receive IP frames, without an
    /// Ethernet header. MAC addresses are not used.
    #[cfg(feature = "medium-ip")]
    Ip,

    /// IEEE 802.15.4 medium. Devices of this type send and receive 802.15.4
    /// MAC frames carrying 6LoWPAN.
    ///
    /// [`Capabilities::max_transmission_unit`] is the whole MAC frame
    /// without the FCS: 125 for a 127-byte PHY frame with a 2-byte FCS.
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154,
}

impl From<Medium> for crate::driver::Medium {
    fn from(medium: Medium) -> Self {
        match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => crate::driver::Medium::Ethernet,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => crate::driver::Medium::Ip,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => crate::driver::Medium::Ieee802154,
        }
    }
}

impl Medium {
    /// The stack's own medium for the one a driver reports, or `None` if the
    /// build does not have its `medium-*` feature.
    pub(crate) fn from_driver(medium: crate::driver::Medium) -> Option<Self> {
        match medium {
            #[cfg(feature = "medium-ethernet")]
            crate::driver::Medium::Ethernet => Some(Medium::Ethernet),
            #[cfg(feature = "medium-ip")]
            crate::driver::Medium::Ip => Some(Medium::Ip),
            #[cfg(feature = "medium-ieee802154")]
            crate::driver::Medium::Ieee802154 => Some(Medium::Ieee802154),
            _ => None,
        }
    }
}

/// Where an interface address came from.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddrOrigin {
    /// Assigned by the application.
    Manual,
    /// Learned from a DHCPv4 lease.
    #[cfg(feature = "dhcpv4")]
    Dhcpv4,
    /// The IPv6 link-local address the stack derives from the hardware address.
    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    LinkLocal,
    /// Formed by SLAAC from a router-advertised prefix.
    #[cfg(feature = "slaac")]
    Slaac,
}

/// An IP address assigned to an interface.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IfaceAddr {
    /// The address and its prefix.
    pub cidr: IpCidr,
    /// Where the address came from.
    pub origin: AddrOrigin,
    /// When the address stops being preferred and becomes deprecated
    /// (RFC 4862 section 5.5.4). `None` means "forever".
    ///
    /// Only SLAAC sets this: a router advertises a preferred lifetime alongside
    /// the valid one, and shortens it to zero to signal that a prefix is on its
    /// way out while addresses formed from it still work.
    pub preferred_until: Option<Instant>,
}

impl IfaceAddr {
    /// An address assigned by the application.
    pub(crate) const fn manual(cidr: IpCidr) -> Self {
        Self {
            cidr,
            origin: AddrOrigin::Manual,
            preferred_until: None,
        }
    }

    /// Whether the address is still preferred, i.e. not deprecated.
    ///
    /// A deprecated address keeps working for connections that already use it,
    /// but is avoided when a source address is chosen for a new one.
    pub fn is_preferred(&self, now: Instant) -> bool {
        self.preferred_until.is_none_or(|until| until > now)
    }
}

/// The IPv6 link-local address derived from a hardware address (RFC 4291 §2.5.1,
/// modified EUI-64; RFC 4944 §6 for an extended 802.15.4 address).
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
pub(crate) fn link_local_addr(hardware_addr: HardwareAddress) -> Option<IfaceAddr> {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xfe;
    bytes[1] = 0x80;
    bytes[8..].copy_from_slice(&hardware_addr.as_eui_64()?);
    Some(IfaceAddr {
        cidr: IpCidr::new(Ipv6Address::from(bytes).into(), 64),
        origin: AddrOrigin::LinkLocal,
        preferred_until: None,
    })
}

/// An interface added to the stack, with its configuration.
pub(crate) struct IfaceState<'d> {
    pub(crate) handle: IfaceHandle,
    pub(crate) driver: MaybeBox<'d, dyn Driver + 'd>,
    /// The driver's medium, converted and checked when the interface is added.
    pub(crate) medium: Medium,
    /// The driver's capabilities, read when the interface is added.
    pub(crate) caps: Capabilities,
    pub(crate) hardware_addr: HardwareAddress,
    pub(crate) ip_addrs: Vec<IfaceAddr, IFACE_ADDR_COUNT>,
    /// Bumped whenever the interface's addresses or routes change.
    pub(crate) config_generation: u32,
    /// Woken on a link state change and on a configuration change.
    #[cfg(feature = "async")]
    pub(crate) waker: crate::waker::WakerRegistration,
    #[cfg(feature = "dhcpv4")]
    pub(crate) dhcpv4: Option<self::dhcpv4::Client>,
    #[cfg(feature = "dhcpv4-server")]
    pub(crate) dhcpv4_server: Option<self::dhcpv4_server::Server>,
    #[cfg(feature = "slaac")]
    pub(crate) slaac: Option<self::slaac::Slaac>,
    /// Link state at the previous poll, for spotting a change.
    pub(crate) last_link_state: crate::driver::LinkState,
    #[cfg(feature = "multicast")]
    pub(crate) multicast: crate::multicast::State,
    #[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
    pub(crate) fragmenter: Fragmenter,
    #[cfg(feature = "medium-ieee802154")]
    pub(crate) sixlowpan: crate::sixlowpan::State,
}

/// An interface borrowed from a [`Stack`], returned by [`Stack::iface`].
pub struct Iface<'a, 'd> {
    #[cfg_attr(
        not(any(feature = "medium-ethernet", feature = "medium-ieee802154")),
        allow(dead_code)
    )]
    pub(crate) inner: &'a mut StackInner,
    pub(crate) ifaces: &'a mut Slab<IfaceState<'d>, IFACE_COUNT>,
    pub(crate) index: usize,
}

impl<'d> Iface<'_, 'd> {
    #[inline]
    pub(crate) fn state(&self) -> &IfaceState<'d> {
        self.ifaces.get(self.index)
    }

    #[inline]
    pub(crate) fn state_mut(&mut self) -> &mut IfaceState<'d> {
        self.ifaces.get_mut(self.index)
    }

    /// The capabilities reported by the device.
    pub fn capabilities(&self) -> Capabilities {
        self.state().caps.clone()
    }

    /// The interface's driver.
    pub fn driver_mut(&mut self) -> &mut dyn Driver {
        &mut *self.state_mut().driver
    }

    /// The link state reported by the device.
    pub fn link_state(&mut self) -> LinkState {
        self.state_mut().driver.link_state()
    }

    /// The interface's IP-layer MTU: the device MTU minus the link-layer header,
    /// clamped to what a [`PacketBuf`](crate::driver::PacketBuf) can carry.
    pub fn ip_mtu(&self) -> usize {
        self.state().ip_mtu()
    }

    /// Poll the device for the timestamp of an already-transmitted packet, sent with
    /// [`PacketMeta::request_timestamp`](crate::driver::PacketMeta::request_timestamp) set.
    ///
    /// Returns `None` if no timestamp is available right now, which is also all a
    /// device without transmit timestamping support ever returns. See
    /// [`Driver::poll_tx_timestamp`] for what a caller must tolerate: timestamps
    /// arrive an arbitrary time after the packet was sent, possibly out of order, and
    /// possibly never.
    #[cfg(feature = "packetmeta-timestamp")]
    pub fn poll_tx_timestamp(&mut self) -> Option<crate::driver::TxTimestamp> {
        self.state_mut().driver.poll_tx_timestamp()
    }

    /// The hardware address of the interface.
    ///
    /// Initially the address the device reported when the interface was added.
    /// [`set_hardware_addr`](Self::set_hardware_addr) overrides it.
    pub fn hardware_addr(&self) -> HardwareAddress {
        self.state().hardware_addr
    }

    /// Set the hardware address of the interface.
    ///
    /// The stack starts using it for the frames it sends and for ingress filtering
    /// immediately. It does not announce the change on the link, so peers keep the
    /// old address in their neighbor caches until it expires. Send a gratuitous ARP
    /// or unsolicited neighbor advertisement from a raw socket if that matters.
    ///
    /// An IEEE 802.15.4 interface must use an extended address. A short address
    /// is accepted, but the stack can not put it in NDISC link-layer address
    /// options, so neighbor discovery does not work with one.
    ///
    /// # Panics
    /// Panics if the address is not of the kind the device's medium uses.
    pub fn set_hardware_addr(&mut self, addr: HardwareAddress) {
        let medium = self.state().medium();
        assert_eq!(
            addr.medium(),
            medium,
            "hardware address does not match the interface's medium"
        );
        self.state_mut().hardware_addr = addr;
        #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
        {
            let ip_addrs = &mut self.state_mut().ip_addrs;
            let had = ip_addrs.iter().any(|a| a.origin == AddrOrigin::LinkLocal);
            ip_addrs.retain(|a| a.origin != AddrOrigin::LinkLocal);
            if let Some(ll) = link_local_addr(addr) {
                if ip_addrs.push(ll).is_err() {
                    warn!("iface: address table full, link-local address not assigned");
                }
                self.invalidate();
            } else if had {
                self.invalidate();
            }
        }
    }

    /// The IP addresses assigned to the interface, with their origin.
    pub fn ip_addrs(&self) -> &[IfaceAddr] {
        &self.state().ip_addrs
    }

    /// Check whether the given address is assigned to the interface.
    pub fn has_ip_addr(&self, addr: impl Into<IpAddress>) -> bool {
        self.state().has_ip_addr(addr)
    }

    /// Assign an IP address to the interface.
    ///
    /// If the same address is already assigned, its prefix is updated and the
    /// previous CIDR returned. Otherwise the address is appended and `None` is
    /// returned. Source address selection prefers the first address matching the
    /// destination's subnet, so ordering only matters between addresses of the same
    /// subnet.
    ///
    /// # Panics
    /// Panics if the address is not unicast.
    ///
    /// Errors:
    /// - `Full` if the interface has no room for another address. Only possible
    ///   without the `alloc` feature, where the limit is
    ///   [`IFACE_ADDR_COUNT`].
    pub fn add_ip_addr(&mut self, cidr: IpCidr) -> core::result::Result<Option<IpCidr>, Full> {
        assert!(
            cidr.address().is_unicast(),
            "only unicast addresses can be assigned to an interface"
        );

        let ip_addrs = &mut self.state_mut().ip_addrs;
        match ip_addrs.iter().position(|old| old.cidr.address() == cidr.address()) {
            Some(index) if ip_addrs[index].cidr == cidr => Ok(Some(cidr)),
            Some(index) => {
                let old = core::mem::replace(&mut ip_addrs[index], IfaceAddr::manual(cidr));
                self.invalidate();
                Ok(Some(old.cidr))
            }
            None => {
                ip_addrs.push(IfaceAddr::manual(cidr)).map_err(|_| Full)?;
                self.state_mut().config_changed();
                Ok(None)
            }
        }
    }

    /// Unassign an IP address from the interface, returning the CIDR it was
    /// assigned with, or `None` if it was not assigned.
    pub fn remove_ip_addr(&mut self, addr: impl Into<IpAddress>) -> Option<IpCidr> {
        let addr = addr.into();
        let ip_addrs = &mut self.state_mut().ip_addrs;
        let index = ip_addrs.iter().position(|a| a.cidr.address() == addr)?;
        let removed = ip_addrs.remove(index);
        self.invalidate();
        Some(removed.cidr)
    }

    /// Replace the interface's entire set of IP addresses.
    ///
    /// Equivalent to removing every address and adding the given ones. The
    /// automatic IPv6 link-local address is kept.
    ///
    /// # Panics
    /// Panics if any of the addresses is not unicast.
    ///
    /// Errors:
    /// - `Full` if the addresses do not fit. Only possible without the `alloc`
    ///   feature, where the limit is [`IFACE_ADDR_COUNT`].
    ///   The interface is left unchanged.
    pub fn set_ip_addrs(&mut self, new_addrs: impl IntoIterator<Item = IpCidr>) -> core::result::Result<(), Full> {
        #[allow(unused_mut)]
        let mut addrs: Vec<IfaceAddr, IFACE_ADDR_COUNT> = Vec::new();
        addrs.try_extend(new_addrs.into_iter().map(IfaceAddr::manual))?;
        assert!(
            addrs.iter().all(|a| a.cidr.address().is_unicast()),
            "only unicast addresses can be assigned to an interface"
        );
        #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
        for a in self.state().ip_addrs.iter() {
            if a.origin == AddrOrigin::LinkLocal && !addrs.iter().any(|n| n.cidr.address() == a.cidr.address()) {
                addrs.push(*a).map_err(|_| Full)?;
            }
        }

        let ip_addrs = &mut self.state_mut().ip_addrs;
        if *ip_addrs == addrs {
            return Ok(());
        }
        *ip_addrs = addrs;
        self.invalidate();
        Ok(())
    }

    /// Purge state associated to this interface.
    fn invalidate(&mut self) {
        let handle = IfaceHandle::new(self.index);
        self.inner.purge_iface_link_state(handle);
        self.state_mut().config_changed();
    }

    /// A counter that goes up every time the interface's configuration changes
    /// for any reason (manual changes, DHCP, SLAAC)
    ///
    /// Compare it with a saved value to find out whether anything changed since.
    pub fn config_generation(&self) -> u32 {
        self.state().config_generation
    }

    /// Register a waker to be woken when the interface changes state.
    ///
    /// It is woken when the link goes up or down, and when
    /// [`config_generation`](Self::config_generation) changes: addresses or routes
    /// added or removed, whether by hand or by DHCPv4 or SLAAC.
    ///
    /// Only one waker is kept. Registering another replaces it. A woken waker must
    /// be registered again to be woken again. Wakes are allowed to be spurious.
    #[cfg(feature = "async")]
    pub fn register_waker(&mut self, waker: &core::task::Waker) {
        self.state_mut().waker.register(waker)
    }

    /// Turn the DHCPv4 client on, with the given configuration, or off with `None`.
    ///
    /// While on, the client runs from [`Stack::poll`]. When it gets a lease the
    /// leased address and the default route via the leased router are installed on
    /// the interface, and removed again when the lease is lost or the client is
    /// turned off. Turning it on when it is already on restarts it with the new
    /// configuration.
    ///
    /// # Panics
    /// Panics if the interface is not an Ethernet interface.
    #[cfg(feature = "dhcpv4")]
    pub fn set_dhcpv4(&mut self, config: Option<self::dhcpv4::DhcpConfig>) {
        assert!(
            matches!(self.state().hardware_addr, HardwareAddress::Ethernet(_)),
            "the DHCPv4 client needs an Ethernet interface"
        );
        let Iface { inner, ifaces, index } = self;
        let iface = ifaces.get_mut(*index);
        iface.dhcpv4_reset(inner);
        iface.dhcpv4 = config.map(self::dhcpv4::Client::new);
    }

    /// Turn IPv6 stateless address autoconfiguration on, with the given
    /// configuration, or off with `None`.
    ///
    /// While on, the stack sends router solicitations from [`Stack::poll`]. Every
    /// prefix a router advertises for autoconfiguration becomes an address on the
    /// interface (the prefix plus the EUI-64 of the hardware address), and every
    /// advertising router becomes a default route. Both are removed when their
    /// lifetime runs out or when SLAAC is turned off. Turning it on when it is
    /// already on restarts it.
    ///
    /// # Panics
    /// Panics if the interface is not an Ethernet or IEEE 802.15.4 interface.
    #[cfg(feature = "slaac")]
    pub fn set_slaac(&mut self, config: Option<self::slaac::SlaacConfig>) {
        assert!(
            self.state().has_link_layer(),
            "SLAAC needs an Ethernet or IEEE 802.15.4 interface"
        );
        let Iface { inner, ifaces, index } = self;
        let iface = ifaces.get_mut(*index);
        iface.slaac_reset(inner);
        iface.slaac = config.map(self::slaac::Slaac::new);
    }

    /// Solicit routers again, keeping the addresses and routes already configured.
    ///
    /// [`Stack::poll`] does this when the link comes back up; call it directly for a
    /// driver that cannot report link state. Does nothing if SLAAC is off.
    #[cfg(feature = "slaac")]
    pub fn restart_slaac(&mut self) {
        if let Some(slaac) = self.state_mut().slaac.as_mut() {
            slaac.restart();
        }
    }

    /// What SLAAC has learned from the routers on the link, or `None` if SLAAC is off.
    #[cfg(feature = "slaac")]
    pub fn slaac(&self) -> Option<&self::slaac::SlaacState> {
        self.state().slaac.as_ref().map(|s| s.state())
    }

    /// The lease the DHCPv4 client currently holds, if any.
    #[cfg(feature = "dhcpv4")]
    pub fn dhcpv4_lease(&self) -> Option<&self::dhcpv4::DhcpLease> {
        self.state().dhcpv4.as_ref().and_then(|client| client.lease())
    }

    /// Drop the DHCPv4 lease, if any, and look for a server again.
    ///
    /// [`Stack::poll`] does this when the link comes back up; call it directly for a
    /// driver that cannot report link state. Does nothing if the client is off.
    #[cfg(feature = "dhcpv4")]
    pub fn restart_dhcpv4(&mut self) {
        let Iface { inner, ifaces, index } = self;
        ifaces.get_mut(*index).dhcpv4_reset(inner);
    }

    /// Turn the DHCPv4 server on, with the given configuration, or off with `None`.
    ///
    /// While on, the stack answers DHCP requests arriving on this interface,
    /// handing out addresses from the configured pool.
    ///
    /// You must configure at least one IPv4 address on the interface, and the
    /// pool must be inside its subnet.
    ///
    /// Turning the server off, or on again with a new configuration, drops all
    /// leases.
    ///
    /// # Panics
    /// Panics if the interface is not an Ethernet interface, or if the pool is
    /// backwards (`pool_start` above `pool_end`).
    #[cfg(feature = "dhcpv4-server")]
    pub fn set_dhcpv4_server(&mut self, config: Option<self::dhcpv4_server::DhcpServerConfig>) {
        assert!(
            matches!(self.state().hardware_addr, HardwareAddress::Ethernet(_)),
            "the DHCPv4 server needs an Ethernet interface"
        );
        if let Some(config) = &config {
            assert!(
                config.pool_start.to_bits() <= config.pool_end.to_bits(),
                "the DHCP pool ends before it starts"
            );
        }
        self.state_mut().dhcpv4_server = config.map(self::dhcpv4_server::Server::new);
    }

    /// The DHCP server's lease table. Empty if the server is off.
    ///
    /// All entries are returned, whether their lease is running or already over.
    /// Check each entry's [`state`](self::dhcpv4_server::DhcpServerLease::state)
    /// and [`expires_at`](self::dhcpv4_server::DhcpServerLease::expires_at).
    #[cfg(feature = "dhcpv4-server")]
    pub fn dhcpv4_server_leases(&self) -> &[self::dhcpv4_server::DhcpServerLease] {
        match &self.state().dhcpv4_server {
            Some(server) => server.leases(),
            None => &[],
        }
    }

    /// Remove the DHCP server lease of the given address, freeing it for other
    /// clients. Returns whether there was one.
    ///
    /// The client is not told: it keeps using the address until it next renews.
    #[cfg(feature = "dhcpv4-server")]
    pub fn remove_dhcpv4_server_lease(&mut self, address: Ipv4Address) -> bool {
        match &mut self.state_mut().dhcpv4_server {
            Some(server) => server.remove_lease(address),
            None => false,
        }
    }
}

/// Iterator over the interfaces of a [`Stack`], returned by [`Stack::ifaces`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.ifaces();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.hardware_addr());
/// }
/// # }
/// ```
pub struct IfaceIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> IfaceIter<'_, 'd> {
    /// Get the next interface, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(IfaceHandle, Iface<'_, 'd>)> {
        let index = self.stack.ifaces.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = IfaceHandle::new(index);
        Some((handle, self.stack.iface(handle)))
    }
}

impl IfaceState<'_> {
    /// The interface's medium.
    #[allow(dead_code)]
    pub(crate) fn medium(&self) -> Medium {
        self.medium
    }

    /// Which checksums the device computes and verifies itself, so the stack
    /// doesn't do it in software.
    #[allow(dead_code)] // unused depending on which protocols are enabled
    pub(crate) fn checksum_caps(&self) -> ChecksumCapabilities {
        self.caps.checksum
    }

    /// Whether the interface's medium has link-layer addresses, and so does
    /// neighbor discovery (Ethernet and IEEE 802.15.4).
    #[allow(dead_code)]
    pub(crate) fn has_link_layer(&self) -> bool {
        match self.medium() {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => true,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => true,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => false,
        }
    }

    /// The interface's IEEE 802.15.4 address.
    ///
    /// Panics on another medium; only the 802.15.4 paths call it, and
    /// `add_iface` checks the address matches the medium.
    #[cfg(feature = "medium-ieee802154")]
    pub(crate) fn ieee802154_addr(&self) -> Ieee802154Address {
        self.hardware_addr.ieee802154_or_panic()
    }

    /// The interface's Ethernet address.
    ///
    /// Panics on a non-Ethernet interface; only the Ethernet paths call it, and
    /// `add_iface` checks the address matches the medium.
    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn ethernet_addr(&self) -> EthernetAddress {
        self.hardware_addr.ethernet_or_panic()
    }

    /// Note that the interface's configuration changed: bump the generation and
    /// wake whoever is waiting for it.
    ///
    /// Also keeps the solicited-node multicast groups in step with the addresses,
    /// since every address change passes through here.
    pub(crate) fn config_changed(&mut self) {
        #[cfg(all(
            feature = "multicast",
            any(feature = "medium-ethernet", feature = "medium-ieee802154"),
            feature = "ipv6"
        ))]
        if self.has_link_layer() {
            self.update_solicited_node_groups();
        }
        self.config_generation = self.config_generation.wrapping_add(1);
        #[cfg(feature = "async")]
        self.waker.wake();
    }

    /// The interface's IP-layer MTU: the device MTU minus the Ethernet header on
    /// Ethernet mediums, clamped to what a `PacketBuf` can carry once the
    /// link-layer headroom egress reserves ([`LINK_HEADER_LEN`]) is taken out.
    pub(crate) fn ip_mtu(&self) -> usize {
        let caps = &self.caps;
        let mtu = match self.medium() {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => caps.max_transmission_unit - ETHERNET_HEADER_LEN,
            #[cfg(feature = "medium-ip")]
            Medium::Ip => caps.max_transmission_unit,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => crate::sixlowpan::ip_mtu(caps.max_transmission_unit),
        };
        mtu.min(PACKET_BUF_SIZE - LINK_HEADER_LEN)
    }

    /// Whether the device can take one more frame right now.
    #[cfg(any(
        feature = "udp",
        feature = "tcp",
        feature = "_raw",
        feature = "ipv4-fragmentation",
        feature = "sixlowpan-fragmentation",
        feature = "medium-ethernet",
        feature = "medium-ieee802154"
    ))]
    pub(crate) fn can_transmit(&mut self) -> bool {
        self.driver.can_transmit()
    }

    /// Whether a new packet can be handed to the interface right now.
    ///
    /// Unlike [`can_transmit`](Self::can_transmit), this is `false` while the
    /// fragments of a packet are still going out: they have first claim on the
    /// device, and a new packet would take their room, or need the fragmenter
    /// itself.
    #[cfg(any(
        feature = "udp",
        feature = "tcp",
        feature = "_raw",
        feature = "medium-ethernet",
        feature = "medium-ieee802154"
    ))]
    pub(crate) fn can_transmit_new_packet(&mut self) -> bool {
        #[cfg(any(feature = "ipv4-fragmentation", feature = "sixlowpan-fragmentation"))]
        if !self.fragmenter.is_empty() {
            return false;
        }
        self.can_transmit()
    }

    /// The assigned addresses, without their origin.
    pub(crate) fn cidrs(&self) -> impl Iterator<Item = &IpCidr> + '_ {
        self.ip_addrs.iter().map(|a| &a.cidr)
    }

    #[inline(never)] // helps code size
    pub(crate) fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.cidrs().any(|probe| probe.address() == addr)
    }

    #[inline(never)] // helps code size
    pub(crate) fn in_same_network(&self, addr: &IpAddress) -> bool {
        self.cidrs().any(|cidr| cidr.contains_addr(addr))
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(all(feature = "ipv4", any(feature = "icmp-ping-reply", feature = "multicast")))]
    pub(crate) fn ipv4_addr(&self) -> Option<Ipv4Address> {
        self.cidrs().find_map(|addr| match *addr {
            IpCidr::Ipv4(cidr) => Some(cidr.address()),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    /// Get an IPv4 source address based on a destination address.
    ///
    /// This function tries to find the first IPv4 address from the interface
    /// that is in the same subnet as the destination address. If no such
    /// address is found, the first IPv4 address from the interface is returned.
    // Used by ARP, the sockets, and the neighbor-failure ICMP error.
    #[cfg(all(
        feature = "ipv4",
        any(
            feature = "medium-ethernet",
            feature = "udp",
            feature = "tcp",
            all(feature = "medium-ieee802154", feature = "icmp-errors")
        )
    ))]
    pub(crate) fn get_source_address_ipv4(&self, dst_addr: &Ipv4Address) -> Option<Ipv4Address> {
        let mut first_ipv4 = None;
        for cidr in self.cidrs() {
            #[allow(irrefutable_let_patterns)]
            if let IpCidr::Ipv4(cidr) = cidr {
                // Return immediately if we find an address in the same subnet
                if cidr.contains_addr(dst_addr) {
                    return Some(cidr.address());
                }

                // Remember the first IPv4 address as fallback
                if first_ipv4.is_none() {
                    first_ipv4 = Some(cidr.address());
                }
            }
        }
        first_ipv4
    }

    /// Get a source address for the given destination address.
    #[cfg(any(feature = "udp", feature = "tcp"))]
    pub(crate) fn get_source_address(&self, dst_addr: &IpAddress, #[allow(unused)] now: Instant) -> Option<IpAddress> {
        match dst_addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(addr) => self.get_source_address_ipv4(addr).map(IpAddress::Ipv4),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(addr) => Some(IpAddress::Ipv6(self.get_source_address_ipv6(addr, now))),
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154", feature = "udp"))]
    pub(crate) fn is_broadcast(&self, address: &IpAddress) -> bool {
        match address {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(address) => self.is_broadcast_v4(*address),
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(_) => false,
        }
    }

    /// Checks if an address is broadcast, taking into account ipv4 subnet-local
    /// broadcast addresses.
    #[cfg(feature = "ipv4")]
    pub(crate) fn is_broadcast_v4(&self, address: Ipv4Address) -> bool {
        if address.is_broadcast() {
            return true;
        }

        self.cidrs()
            .filter_map(|own_cidr| match own_cidr {
                IpCidr::Ipv4(own_ip) => Some(own_ip.broadcast()?),
                #[cfg(feature = "ipv6")]
                IpCidr::Ipv6(_) => None,
            })
            .any(|broadcast_address| address == broadcast_address)
    }

    /// Checks if an ipv4 address is unicast, taking into account subnet broadcast addresses
    #[cfg(feature = "ipv4")]
    #[inline(never)] // helps code size
    pub(crate) fn is_unicast_v4(&self, address: Ipv4Address) -> bool {
        address.x_is_unicast() && !self.is_broadcast_v4(address)
    }

    /// Determine if the given `Ipv6Address` is the solicited node
    /// multicast address for a IPv6 addresses assigned to the interface.
    /// See [RFC 4291 § 2.7.1] for more details.
    ///
    /// [RFC 4291 § 2.7.1]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    #[cfg(feature = "ipv6")]
    pub(crate) fn has_solicited_node(&self, addr: Ipv6Address) -> bool {
        self.cidrs().any(|cidr| {
            match *cidr {
                IpCidr::Ipv6(cidr) if cidr.address() != Ipv6Address::LOCALHOST => {
                    // Take the lower order 24 bits of the IPv6 address and
                    // append those bits to FF02:0:0:0:0:1:FF00::/104.
                    addr.is_solicited_node_multicast() && addr.octets()[13..] == cidr.address().octets()[13..]
                }
                _ => false,
            }
        })
    }

    /// Check whether the interface listens to given destination multicast IP address.
    pub(crate) fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();

        #[cfg(feature = "multicast")]
        if self.multicast.has_multicast_group(addr) {
            return true;
        }

        match addr {
            #[cfg(feature = "ipv4")]
            IpAddress::Ipv4(key) => key == IPV4_MULTICAST_ALL_SYSTEMS,
            #[cfg(feature = "ipv6")]
            IpAddress::Ipv6(key) => key == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(key),
        }
    }

    /// Get the first link-local IPv6 address of the interface, if present.
    #[cfg(any(feature = "slaac", all(feature = "ipv6", feature = "multicast")))]
    pub(crate) fn link_local_ipv6_address(&self) -> Option<Ipv6Address> {
        self.cidrs().find_map(|cidr| match *cidr {
            IpCidr::Ipv6(cidr) if cidr.address().is_link_local() => Some(cidr.address()),
            _ => None,
        })
    }

    /// Return the IPv6 address that is a candidate source address for the given destination
    /// address, based on RFC 6724.
    ///
    /// # Panics
    /// This function panics if the destination address is unspecified.
    #[cfg(feature = "ipv6")]
    pub(crate) fn get_source_address_ipv6(&self, dst_addr: &Ipv6Address, now: Instant) -> Ipv6Address {
        assert!(!dst_addr.is_unspecified());

        // See RFC 6724 Section 4: Candidate source address
        fn is_candidate_source_address(dst_addr: &Ipv6Address, src_addr: &Ipv6Address) -> bool {
            // For all multicast and link-local destination addresses, the candidate address MUST
            // only be an address from the same link.
            if dst_addr.is_link_local() && !src_addr.is_link_local() {
                return false;
            }

            if dst_addr.is_multicast()
                && matches!(dst_addr.x_multicast_scope(), Ipv6MulticastScope::LinkLocal)
                && src_addr.is_multicast()
                && !matches!(src_addr.x_multicast_scope(), Ipv6MulticastScope::LinkLocal)
            {
                return false;
            }

            // Unspecified addresses and multicast address can not be in the candidate source address
            // list. Except when the destination multicast address has a link-local scope, then the
            // source address can also be link-local multicast.
            if src_addr.is_unspecified() || src_addr.is_multicast() {
                return false;
            }

            true
        }

        // See RFC 6724 Section 2.2: Common Prefix Length
        fn common_prefix_length(dst_addr: &Ipv6Cidr, src_addr: &Ipv6Address) -> usize {
            let addr = dst_addr.address();
            let mut bits = 0;
            for (l, r) in addr.octets().iter().zip(src_addr.octets().iter()) {
                if l == r {
                    bits += 8;
                } else {
                    bits += (l ^ r).leading_zeros();
                    break;
                }
            }

            bits = bits.min(dst_addr.prefix_len() as u32);

            bits as usize
        }

        // An IPv6 candidate, kept together with the address it came from so that
        // rule 3 can see which candidates the stack has deprecated.
        fn ipv6_candidate(addr: &IfaceAddr) -> Option<(&IfaceAddr, &Ipv6Cidr)> {
            match &addr.cidr {
                #[cfg(feature = "ipv4")]
                IpCidr::Ipv4(_) => None,
                IpCidr::Ipv6(cidr) => Some((addr, cidr)),
            }
        }

        // If the destination address is a loopback address, or when there are no IPv6 addresses in
        // the interface, then the loopback address is the only candidate source address.
        if dst_addr.is_loopback() {
            return Ipv6Address::LOCALHOST;
        }
        let Some((mut candidate, mut candidate_cidr)) = self.ip_addrs.iter().find_map(ipv6_candidate) else {
            return Ipv6Address::LOCALHOST;
        };

        // See RFC 6724 Section 5: Source Address Selection. The rules are a priority
        // ordering, so the first one that tells the two candidates apart decides it and
        // the rules below it never run. Returning out of each rule in turn is what keeps
        // that ordering; a chain of separate overwrites would instead let a lower rule
        // undo what a higher one had already settled.
        fn prefer(
            (candidate, candidate_cidr): (&IfaceAddr, &Ipv6Cidr),
            (addr, cidr): (&IfaceAddr, &Ipv6Cidr),
            dst_addr: &Ipv6Address,
            now: Instant,
        ) -> bool {
            // Rule 1: prefer the address that is the same as the output destination address.
            if cidr.address() == *dst_addr {
                return true;
            }
            if candidate_cidr.address() == *dst_addr {
                return false;
            }

            // Rule 2: prefer appropriate scope.
            let candidate_scope = candidate_cidr.address().x_multicast_scope() as u8;
            let addr_scope = cidr.address().x_multicast_scope() as u8;
            let dst_scope = dst_addr.x_multicast_scope() as u8;
            if candidate_scope != addr_scope {
                return if addr_scope < candidate_scope {
                    addr_scope >= dst_scope
                } else {
                    candidate_scope < dst_scope
                };
            }

            // Rule 3: avoid deprecated addresses. A router retires a prefix by
            // advertising it with a preferred lifetime of zero while it stays valid,
            // so through a prefix rotation the outgoing address is still assigned and
            // still shares its leading bits with the destinations it used to reach.
            // RFC 6724 orders this rule above rule 8 for that reason: a preferred
            // address wins even when a deprecated one matches more closely. It sits
            // below rules 1 and 2, so it cannot hand back an address of the wrong
            // scope, nor pass over the destination address itself.
            if candidate.is_preferred(now) != addr.is_preferred(now) {
                return addr.is_preferred(now);
            }

            // Rule 4: prefer home addresses (TODO)
            // Rule 5: prefer outgoing interfaces (TODO)
            // Rule 5.5: prefer addresses in a prefix advertises by the next-hop (TODO).
            // Rule 6: prefer matching label (TODO)
            // Rule 7: prefer temporary addresses (TODO)
            // Rule 8: use longest matching prefix
            common_prefix_length(cidr, dst_addr) > common_prefix_length(candidate_cidr, dst_addr)
        }

        for (addr, cidr) in self.ip_addrs.iter().filter_map(ipv6_candidate) {
            if !is_candidate_source_address(dst_addr, &cidr.address()) {
                continue;
            }

            if prefer((candidate, candidate_cidr), (addr, cidr), dst_addr, now) {
                (candidate, candidate_cidr) = (addr, cidr);
            }
        }

        candidate_cidr.address()
    }
}
