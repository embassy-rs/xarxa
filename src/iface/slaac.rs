//! IPv6 stateless address autoconfiguration (SLAAC), built into the interface.
//!
//! Turn it on per interface with [`Iface::set_slaac`](super::Iface::set_slaac).
//! The stack then sends router solicitations, and from the router advertisements
//! it receives it forms addresses (EUI-64 from the hardware address) and installs
//! default routes on the interface. Both expire with the lifetimes the router
//! advertised.
//!
//! Needs the `slaac` feature.

use xarxa_driver::config::PACKET_BUF_DRIVER_HEADROOM;

use crate::config::{SLAAC_PREFIX_COUNT, SLAAC_ROUTER_COUNT};
use crate::storage::Vec;

use super::{AddrOrigin, IfaceAddr, IfaceState};
use crate::driver::{LinkState, PacketBuf};
use crate::route::{Route as IfaceRoute, RouteOrigin};
use crate::stack::StackInner;
use crate::time::{Clock, Duration, Instant};
use crate::wire::{
    HardwareAddress, IPV6_HEADER_LEN, IPV6_LINK_LOCAL_ALL_ROUTERS, Icmpv6Message, Icmpv6Packet, IpCidr, Ipv6Addr,
    Ipv6Cidr, LINK_HEADER_LEN, NdiscOption, NdiscOptionType, NdiscPrefixInfoFlags, NdiscRouterFlags,
    RawHardwareAddress, ipv6::AddressExt,
};

const MAX_RTR_SOLICITATIONS: u8 = 3;
const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
const IPV6_DEFAULT: Ipv6Cidr = Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0);

/// SLAAC configuration, passed to [`Iface::set_slaac`](super::Iface::set_slaac).
///
/// There are no knobs yet. Use `SlaacConfig::default()`.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SlaacConfig {}

/// What SLAAC has learned from the routers on the link, for the application.
///
/// The addresses and routes themselves are on the interface, see
/// [`Iface::ip_addrs`](super::Iface::ip_addrs) and [`Stack::routes`](crate::Stack::routes).
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SlaacState {
    /// At least one router advertisement was received.
    pub routers_seen: bool,
    /// The last router advertisement had the "managed address configuration"
    /// flag set: addresses are available through DHCPv6.
    pub managed: bool,
    /// The last router advertisement had the "other configuration" flag set:
    /// other configuration (like DNS servers) is available through DHCPv6.
    pub other_config: bool,
}

/// Router solicitation state machine
#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Start,
    Discovering,
    Maintaining,
    None,
}

/// A prefix of addresses received via router advertisements
#[derive(Debug, Clone, Copy)]
struct Route {
    /// IPv6 cidr to route
    cidr: Ipv6Cidr,
    /// Router, origin of the advertisement
    via_router: Ipv6Addr,
    /// Valid lifetime of the route
    valid_until: Instant,
}

/// Info associated with a prefix
#[derive(Debug, Clone, Copy)]
struct PrefixInfo {
    preferred_until: Instant,
    valid_until: Instant,
}

/// The contents of a prefix information option, as parsed out of a router
/// advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrefixInformation {
    pub prefix_len: u8,
    pub flags: NdiscPrefixInfoFlags,
    pub valid_lifetime: Duration,
    pub preferred_lifetime: Duration,
    pub prefix: Ipv6Addr,
}

impl PrefixInformation {
    /// Validates the prefix information option against check a, b, c in
    /// <https://www.rfc-editor.org/rfc/rfc4862#section-5.5.3>
    ///
    /// Also rejects multicast prefixes, which would form a multicast address.
    /// The RFC leaves that to the address architecture; Linux ignores them too.
    /// And prefix lengths over 128, which RFC 4861 §4.6.2 rules out.
    fn is_valid_prefix_info(&self) -> bool {
        self.prefix_len <= 128
            && self.flags.contains(NdiscPrefixInfoFlags::ADDRCONF)
            && !self.prefix.is_link_local()
            && !self.prefix.is_multicast()
            && self.preferred_lifetime <= self.valid_lifetime
    }
}

impl PrefixInfo {
    fn new(preferred_until: Instant, valid_until: Instant) -> Self {
        Self {
            preferred_until,
            valid_until,
        }
    }

    /// Derive the prefix information from the neighbor discovery option.
    fn from_prefix(prefix: &PrefixInformation, now: Instant) -> Self {
        let preferred_until = now + prefix.preferred_lifetime;
        let valid_until = now + prefix.valid_lifetime;

        Self::new(preferred_until, valid_until)
    }

    /// Get whether the prefix is still valid.
    fn is_valid(&self, now: Instant) -> bool {
        self.valid_until > now
    }
}

impl Route {
    /// Compare this route based on the prefix and the next hop router.
    fn same_route(&self, cidr: &Ipv6Cidr, via_router: &Ipv6Addr) -> bool {
        self.cidr == *cidr && self.via_router == *via_router
    }

    /// Get whether the route is still valid.
    fn is_valid(&self, now: Instant) -> bool {
        self.valid_until > now
    }
}

/// SLAAC runtime state
///
/// Tracks router solicitations and collects information from all received
/// router advertisements.
///
/// State must be synchronized with the IP addresses and routes in the interface.
#[derive(Debug)]
pub(crate) struct Slaac {
    /// Set of prefixes received.
    prefix: Vec<(Ipv6Cidr, PrefixInfo), SLAAC_PREFIX_COUNT>,
    /// Set of routes received.
    routes: Vec<Route, SLAAC_ROUTER_COUNT>,
    /// Router discovery phase.
    phase: Phase,
    /// Signal for address and route updates.
    sync_required: bool,
    /// Time to next router solicitation.
    retry_rs_at: Instant,
    /// Number of solicitations emitted.
    num_solicitations: u8,
    /// What the application can see.
    state: SlaacState,
    #[allow(dead_code)]
    config: SlaacConfig,
}

impl Slaac {
    pub(crate) fn new(config: SlaacConfig) -> Self {
        Self {
            prefix: Vec::new(),
            routes: Vec::new(),
            phase: Phase::Start,
            sync_required: false,
            retry_rs_at: Instant::from_millis(0),
            num_solicitations: MAX_RTR_SOLICITATIONS,
            state: SlaacState::default(),
            config,
        }
    }

    pub(crate) fn state(&self) -> &SlaacState {
        &self.state
    }

    /// Get whether router advertisement information is updated.
    ///
    /// This flags whether new prefixes or routes have been received, or current prefixes and
    /// routes have expired.
    fn has_ra_update(&self) -> bool {
        self.sync_required
    }

    fn add_prefix(&mut self, cidr: &Ipv6Cidr, prefix: &PrefixInformation, now: Instant) {
        if cidr.address().is_link_local() {
            return;
        }
        let prefix_info = PrefixInfo::from_prefix(prefix, now);
        if let Some((_, old_info)) = self.prefix.iter_mut().find(|(c, _)| c == cidr) {
            *old_info = prefix_info;
        } else if self.prefix.push((*cidr, prefix_info)).is_err() {
            warn!("slaac: prefix table full, ignoring prefix {}", cidr);
            return;
        }
        // Unlike the original, a refreshed lifetime also syncs, so the expiry on
        // the installed address and route follows the latest advertisement.
        self.sync_required = true;
    }

    fn expire_prefix(&mut self, cidr: &Ipv6Cidr) {
        if let Some((_, info)) = self.prefix.iter_mut().find(|(c, _)| c == cidr) {
            info.valid_until = Instant::from_millis(0);
            info.preferred_until = Instant::from_millis(0);
            self.sync_required = true;
        }
    }

    fn add_route(&mut self, cidr: &Ipv6Cidr, router: &Ipv6Addr, valid_until: Instant) {
        if let Some(route) = self.routes.iter_mut().find(|r| r.same_route(cidr, router)) {
            route.valid_until = valid_until;
        } else if self
            .routes
            .push(Route {
                cidr: *cidr,
                via_router: *router,
                valid_until,
            })
            .is_err()
        {
            warn!("slaac: router table full, ignoring route via {}", router);
            return;
        }
        self.sync_required = true;
    }

    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Addr) {
        for route in self.routes.iter_mut() {
            if route.same_route(cidr, via_router) {
                route.valid_until = Instant::from_millis(0);
                self.sync_required = true;
            }
        }
    }

    fn process_prefix(&mut self, prefix: PrefixInformation, now: Instant) {
        if !prefix.flags.contains(NdiscPrefixInfoFlags::ADDRCONF) {
            return;
        }

        let cidr = Ipv6Cidr::new(prefix.prefix, prefix.prefix_len);

        if prefix.valid_lifetime > Duration::ZERO {
            self.add_prefix(&cidr, &prefix, now);
        } else {
            self.expire_prefix(&cidr);
        }
    }

    /// Process a router advertisement's information.
    ///
    /// `prefixes` are the prefix information options of the advertisement, all of
    /// them, in order.
    pub(crate) fn process_advertisement(
        &mut self,
        source: &Ipv6Addr,
        flags: NdiscRouterFlags,
        router_lifetime: Duration, // default route lifetime
        prefixes: impl Iterator<Item = PrefixInformation>,
        now: Instant,
    ) {
        for prefix in prefixes {
            if prefix.is_valid_prefix_info() {
                self.process_prefix(prefix, now)
            }
        }

        if router_lifetime > Duration::ZERO {
            self.add_route(&IPV6_DEFAULT, source, now + router_lifetime);
        } else {
            self.expire_route(&IPV6_DEFAULT, source);
        }

        self.state.routers_seen = true;
        self.state.managed = flags.contains(NdiscRouterFlags::MANAGED);
        self.state.other_config = flags.contains(NdiscRouterFlags::OTHER);

        // Advertisement might be unsolicited
        if self.phase == Phase::Discovering {
            self.phase = Phase::Maintaining;
        }
    }

    // Not `any`: every lifetime is looked at, so that the ones that haven't run out
    // count toward the deadline.
    fn prefix_expire_sync_required(&self, clock: &mut Clock) -> bool {
        let mut expired = false;
        for (_, info) in self.prefix.iter() {
            expired |= clock.expired(info.valid_until);
        }
        expired
    }

    fn route_expire_sync_required(&self, clock: &mut Clock) -> bool {
        let mut expired = false;
        for route in self.routes.iter() {
            expired |= clock.expired(route.valid_until);
        }
        expired
    }

    /// Get whether a route and prefix information must be synchronized with the interface.
    pub(crate) fn sync_required(&self, clock: &mut Clock) -> bool {
        // Unlike the original, expiry deadlines count in every phase: an unsolicited
        // advertisement can install state before or after discovery.
        let prefix_expired = self.prefix_expire_sync_required(clock);
        let route_expired = self.route_expire_sync_required(clock);
        self.has_ra_update() || prefix_expired || route_expired
    }

    /// Remove expired routes and prefixes.
    fn update_slaac_state(&mut self, now: Instant) {
        self.prefix.retain(|(_, info)| info.is_valid(now));
        self.routes.retain(|r| r.is_valid(now));
        self.sync_required = false;
    }

    /// Get whether a router solicitation must be emitted.
    fn rs_required(&self, clock: &mut Clock) -> bool {
        clock.expired(self.rs_at())
    }

    /// When the next router solicitation is due. `Instant::MAX` if none is.
    fn rs_at(&self) -> Instant {
        match self.phase {
            Phase::Start | Phase::Discovering if self.num_solicitations > 0 => self.retry_rs_at,
            _ => Instant::MAX,
        }
    }

    /// Solicit again, keeping the prefixes and routes already learned. RFC 4861 §6.3.7.
    pub(crate) fn restart(&mut self) {
        self.phase = Phase::Start;
        self.num_solicitations = MAX_RTR_SOLICITATIONS;
        self.retry_rs_at = Instant::from_millis(0);
    }

    /// Update router solicitation tracking state
    ///
    /// Must be called after sending a router solicitation on the interface.
    fn rs_sent(&mut self, now: Instant) {
        match self.phase {
            Phase::Start | Phase::Discovering if self.retry_rs_at <= now => {
                if self.num_solicitations == 0 {
                    self.phase = Phase::None;
                } else {
                    self.num_solicitations -= 1;
                    self.phase = Phase::Discovering;
                    self.retry_rs_at = now + RTR_SOLICITATION_INTERVAL;
                }
            }
            _ => (),
        }
    }
}

/// Form the address `link_prefix` + EUI-64 of `hardware_addr`, if the prefix is
/// 64 bits long.
fn from_link_prefix(link_prefix: &Ipv6Cidr, hardware_addr: HardwareAddress) -> Option<Ipv6Cidr> {
    if link_prefix.prefix_len() != 64 {
        return None;
    }
    let mut bytes = [0; 16];
    bytes[0..8].copy_from_slice(&link_prefix.address().octets()[0..8]);
    bytes[8..16].copy_from_slice(&hardware_addr.as_eui_64()?);
    Some(Ipv6Cidr::new(Ipv6Addr::from_octets(bytes), 64))
}

impl IfaceState<'_> {
    /// Process a router advertisement that passed the NDISC validity checks.
    pub(crate) fn slaac_process_advertisement(
        &mut self,
        inner: &mut StackInner,
        src_addr: Ipv6Addr,
        icmp_packet: &mut Icmpv6Packet<'_>,
    ) {
        let Some(slaac) = &mut self.slaac else { return };

        let flags = icmp_packet.router_flags();
        let router_lifetime = icmp_packet.router_lifetime();

        // First pass over the options: validate them all, and pick up the
        // source link-layer address option, which teaches us the router's MAC.
        let mut lladdr: Option<RawHardwareAddress> = None;
        let options = icmp_packet.payload_mut();
        let mut offset = 0;
        while offset < options.len() {
            let Ok(opt) = NdiscOption::new_checked(&mut options[offset..]) else {
                trace!("ndisc: malformed router advertisement option");
                return;
            };
            if opt.option_type() == NdiscOptionType::SourceLinkLayerAddr {
                lladdr = Some(opt.link_layer_addr());
            }
            offset += opt.data_len() as usize * 8;
        }

        // Second pass: feed every prefix information option to SLAAC, straight
        // from the packet. The first pass checked that they all parse.
        let mut offset = 0;
        let prefixes = core::iter::from_fn(|| {
            while offset < options.len() {
                let opt = NdiscOption::new_checked(&mut options[offset..]).ok()?;
                offset += opt.data_len() as usize * 8;
                if opt.option_type() == NdiscOptionType::PrefixInformation {
                    return Some(PrefixInformation {
                        prefix_len: opt.prefix_len(),
                        flags: opt.prefix_flags(),
                        valid_lifetime: opt.valid_lifetime(),
                        preferred_lifetime: opt.preferred_lifetime(),
                        prefix: opt.prefix(),
                    });
                }
            }
            None
        });
        slaac.process_advertisement(&src_addr, flags, router_lifetime, prefixes, inner.now);

        if let Some(lladdr) = lladdr
            && let Ok(lladdr) = lladdr.parse(self.medium())
            && lladdr.is_unicast()
        {
            inner.fill_neighbor(self, crate::wire::IpAddr::V6(src_addr), lladdr);
        }
    }

    /// Synchronize the slaac address and router state with the interface state.
    fn sync_slaac_state(&mut self, inner: &mut StackInner) {
        let timestamp = inner.now;
        let hardware_addr = self.hardware_addr;
        let Some(slaac) = &self.slaac else { return };

        // Addresses come and go without touching the link state: the router that
        // advertised the prefix has just been entered into the neighbor cache.
        //
        // Every valid prefix gets its address...
        for (prefix, prefixinfo) in slaac.prefix.iter() {
            if !prefixinfo.is_valid(timestamp) {
                continue;
            }
            let Some(address) = from_link_prefix(prefix, hardware_addr) else {
                continue;
            };
            match self.ip_addrs.iter_mut().find(|a| a.cidr == IpCidr::V6(address)) {
                // One we installed: refresh it rather than leave it behind. The router
                // shortens a prefix's preferred lifetime to retire it, and the address
                // formed from it has to follow, or nothing downstream can tell that it
                // is on its way out.
                Some(existing) if existing.origin == AddrOrigin::Slaac => {
                    existing.preferred_until = Some(prefixinfo.preferred_until);
                }
                // Somebody else's, and it only happens to be the address this prefix
                // forms. Not ours to deprecate: the expiry below leaves it alone too.
                Some(_) => {}
                None => {
                    let new_addr = IfaceAddr {
                        cidr: IpCidr::V6(address),
                        origin: AddrOrigin::Slaac,
                        preferred_until: Some(prefixinfo.preferred_until),
                    };
                    if self.ip_addrs.push(new_addr).is_err() {
                        warn!("slaac: address table full, {} not assigned", address);
                    }
                }
            }
        }
        // ...and the address of every expired prefix goes.
        self.ip_addrs.retain(|a| match a.cidr {
            IpCidr::V6(address) => {
                !(a.origin == AddrOrigin::Slaac
                    && slaac.prefix.iter().any(|(prefix, prefixinfo)| {
                        !prefixinfo.is_valid(timestamp) && from_link_prefix(prefix, hardware_addr) == Some(address)
                    }))
            }
            #[allow(unreachable_patterns)]
            _ => true,
        });

        {
            let handle = self.handle;
            let slaac_routes = &slaac.routes;
            inner.routes.retain(|r| match (&r.cidr, &r.via_router) {
                (IpCidr::V6(cidr), crate::wire::IpAddr::V6(via_router)) => {
                    !(r.origin == RouteOrigin::Slaac
                        && r.iface == handle
                        && slaac_routes
                            .iter()
                            .any(|f| !f.is_valid(timestamp) && f.same_route(cidr, via_router)))
                }
                #[allow(unreachable_patterns)]
                _ => true,
            });

            for route in slaac_routes.iter().filter(|r| r.is_valid(timestamp)) {
                if let Some(existing) = inner.routes.iter_mut().find(|r| {
                    r.origin == RouteOrigin::Slaac
                        && r.iface == handle
                        && match (&r.cidr, &r.via_router) {
                            (IpCidr::V6(cidr), crate::wire::IpAddr::V6(via_router)) => {
                                route.same_route(cidr, via_router)
                            }
                            #[allow(unreachable_patterns)]
                            _ => false,
                        }
                }) {
                    existing.expires_at = Some(route.valid_until);
                } else {
                    let new_route = IfaceRoute {
                        cidr: route.cidr.into(),
                        via_router: route.via_router.into(),
                        iface: handle,
                        origin: RouteOrigin::Slaac,
                        preferred_until: None,
                        expires_at: Some(route.valid_until),
                    };
                    if inner.routes.add(new_route).is_err() {
                        warn!("slaac: route table full, route via {} not installed", route.via_router);
                    }
                }
            }
        }

        self.slaac.as_mut().unwrap().update_slaac_state(timestamp);
        self.config_changed();
    }

    /// Run SLAAC: solicit routers when due, and apply what the advertisements
    /// taught to the interface's addresses and routes.
    pub(crate) fn slaac_poll(&mut self, inner: &mut StackInner, clock: &mut Clock) {
        self.ndisc_rs_egress(inner, clock);
        if self.slaac.as_ref().is_some_and(|s| s.sync_required(clock)) {
            self.sync_slaac_state(inner);
        }
    }

    /// Emit a router solicitation when required by the interface's slaac state machine.
    ///
    /// Solicitations wait for the link to be up and for a link-local address to
    /// send them from. While they wait, their timer doesn't count toward the
    /// deadline: the link coming up restarts them, and adding an address is an
    /// operation on the interface, which is followed by a poll.
    fn ndisc_rs_egress(&mut self, inner: &mut StackInner, clock: &mut Clock) {
        let Some(slaac) = &self.slaac else { return };
        // A solicitation counts as sent even if the driver refuses the frame, so
        // don't spend the budget on a down link.
        if self.last_link_state != LinkState::Up {
            return;
        }
        // RFC 4861 §4.1: the source is the link-local address, or unspecified. Wait
        // for the link-local rather than solicit from `::`, since a reply to `::`
        // must be multicast and the router cannot learn our link-layer address.
        let Some(src_addr) = self.link_local_ipv6_address() else {
            return;
        };
        if !slaac.rs_required(clock) {
            return;
        }
        let dst_addr = IPV6_LINK_LOCAL_ALL_ROUTERS;

        // Router solicit: RS header (8 bytes) plus the source link-layer address
        // option. Without a buffer it counts as sent too: the retry timer sends the
        // next one.
        if let Some(mut buf) = PacketBuf::try_new() {
            let opt_len = crate::stack::lladdr_option_len(self.hardware_addr);
            buf.reserve(PACKET_BUF_DRIVER_HEADROOM + LINK_HEADER_LEN + IPV6_HEADER_LEN);
            buf.set_len(8 + opt_len);
            {
                let mut rs = Icmpv6Packet::new_unchecked(&mut buf);
                rs.set_msg_type(Icmpv6Message::RouterSolicit);
                rs.set_msg_code(0);
                rs.clear_reserved();
                crate::stack::write_lladdr_option(
                    rs.payload_mut(),
                    NdiscOptionType::SourceLinkLayerAddr,
                    self.hardware_addr,
                );
                if !self.checksum_caps().icmpv6.tx {
                    rs.fill_checksum(&src_addr, &dst_addr);
                } else {
                    rs.set_checksum(0);
                }
            }
            // The all-routers destination is multicast, so this never waits on neighbor
            // resolution.
            inner.transmit_ndisc(self, buf, src_addr, dst_addr);
        } else {
            trace!("ndisc: no packet buffer for router solicit");
        }
        let slaac = self.slaac.as_mut().unwrap();
        slaac.rs_sent(clock.now());
        clock.schedule(slaac.rs_at());
    }

    /// Turn SLAAC off: remove the addresses and routes it installed.
    pub(crate) fn slaac_reset(&mut self, inner: &mut StackInner) {
        if self.slaac.take().is_none() {
            return;
        }
        let before = self.ip_addrs.len();
        self.ip_addrs.retain(|a| a.origin != AddrOrigin::Slaac);
        if self.ip_addrs.len() != before {
            inner.purge_iface_link_state(self.handle);
        }
        let handle = self.handle;
        inner
            .routes
            .retain(|r| !(r.origin == RouteOrigin::Slaac && r.iface == handle));
        self.config_changed();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[allow(unused_imports)]
    use std::vec::Vec;
    mod mock {
        use super::super::*;
        pub const SOURCE: Ipv6Addr = Ipv6Addr::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 0);
        pub const PREFIX: PrefixInformation = PrefixInformation {
            prefix_len: 64,
            flags: NdiscPrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(700),
            preferred_lifetime: Duration::from_secs(300),
            prefix: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        };
        pub const VALID: Duration = Duration::from_secs(600);

        pub const ROUTE: Route = Route {
            cidr: Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0),
            via_router: SOURCE,
            valid_until: Instant::from_millis(100000),
        };
    }
    use mock::*;

    /// [`Slaac::sync_required`] in a poll at `now`, and the deadline it counts.
    fn sync_required(slaac: &Slaac, now: Instant) -> (bool, Instant) {
        let mut clock = Clock::new(now);
        let required = slaac.sync_required(&mut clock);
        (required, clock.next())
    }

    fn advertise(slaac: &mut Slaac, router_lifetime: Duration, prefix: Option<PrefixInformation>, now: Instant) {
        slaac.process_advertisement(
            &SOURCE,
            NdiscRouterFlags::empty(),
            router_lifetime,
            prefix.into_iter(),
            now,
        );
    }

    /// `from_link_prefix` forms prefix + EUI-64, for a /64 prefix only.
    #[test]
    fn test_from_link_prefix() {
        let prefix = Ipv6Cidr::new(Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 0), 64);
        #[cfg(feature = "medium-ethernet")]
        {
            let hw = HardwareAddress::Ethernet(crate::wire::EthernetAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
            assert_eq!(
                from_link_prefix(&prefix, hw),
                Some(Ipv6Cidr::new(
                    Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0xa8bb, 0xccff, 0xfedd, 0xeeff),
                    64
                ))
            );
            let long_prefix = Ipv6Cidr::new(Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0, 0, 0, 0), 72);
            assert_eq!(from_link_prefix(&long_prefix, hw), None);
        }
        #[cfg(feature = "medium-ieee802154")]
        {
            let hw = HardwareAddress::Ieee802154(crate::wire::Ieee802154Address::Extended([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            ]));
            assert_eq!(
                from_link_prefix(&prefix, hw),
                Some(Ipv6Cidr::new(
                    Ipv6Addr::new(0x2001, 0xdb8, 3, 0, 0x211, 0x2233, 0x4455, 0x6677),
                    64
                ))
            );
            let short = HardwareAddress::Ieee802154(crate::wire::Ieee802154Address::Short([0x12, 0x34]));
            assert_eq!(from_link_prefix(&prefix, short), None);
        }
    }

    #[test]
    fn test_route() {
        assert!(ROUTE.same_route(&Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0), &SOURCE));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 64), &SOURCE));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0), &Ipv6Addr::UNSPECIFIED));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 0), &Ipv6Addr::UNSPECIFIED));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 64), &Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_route_valid() {
        assert!(ROUTE.is_valid(Instant::ZERO));
        assert!(!ROUTE.is_valid(Instant::from_secs(200)));
    }

    #[test]
    fn test_solicitation() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        let now = Instant::from_millis(1);
        assert!(slaac.rs_required(&mut Clock::new(now)));

        slaac.rs_sent(now);
        assert_eq!(slaac.num_solicitations, 2);
        assert!(!slaac.rs_required(&mut Clock::new(now)));

        let next_poll = slaac.rs_at();
        assert_eq!(next_poll, now + RTR_SOLICITATION_INTERVAL);

        let now = next_poll;
        assert!(slaac.rs_required(&mut Clock::new(now)));

        slaac.num_solicitations = 0;
        assert!(!slaac.rs_required(&mut Clock::new(now)));
        slaac.rs_sent(now);
        assert_eq!(slaac.phase, Phase::None);
        assert_eq!(slaac.rs_at(), Instant::MAX);
    }

    #[test]
    fn test_ra_state() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        assert_eq!(slaac.phase, Phase::Start);
        let now = Instant::from_millis(1);
        assert!(!slaac.has_ra_update());
        assert!(!slaac.state().routers_seen);

        // Unsolicited advertisement
        advertise(&mut slaac, VALID, Some(PREFIX), now);
        assert_eq!(slaac.phase, Phase::Start);
        assert!(slaac.has_ra_update());
        assert!(slaac.state().routers_seen);

        let now = Instant::from_secs(300);
        slaac.rs_sent(now);
        assert_eq!(slaac.phase, Phase::Discovering);

        // Solicited advertisement
        advertise(&mut slaac, VALID, Some(PREFIX), now);
        advertise(&mut slaac, VALID, Some(PREFIX), now);
        assert_eq!(slaac.phase, Phase::Maintaining);
        assert_eq!(slaac.rs_at(), Instant::MAX);
        let (_, poll_at) = sync_required(&slaac, now);
        assert_eq!(poll_at, now + VALID);

        for (prefix, info) in slaac.prefix.iter() {
            assert_eq!(prefix.address(), PREFIX.prefix);
            assert_eq!(prefix.prefix_len(), PREFIX.prefix_len);
            assert_eq!(info.valid_until, now + PREFIX.valid_lifetime);
            assert_eq!(info.preferred_until, now + PREFIX.preferred_lifetime);
            assert!(info.is_valid(now));
        }

        for route in slaac.routes.iter() {
            assert_eq!(route.cidr, Ipv6Cidr::new(Ipv6Addr::UNSPECIFIED, 0));
            assert_eq!(route.via_router, SOURCE);
            assert_eq!(route.valid_until, now + VALID);
            assert!(route.is_valid(now));
        }
        assert_eq!(slaac.prefix.len(), 1);
        assert_eq!(slaac.routes.len(), 1);
        assert!(sync_required(&slaac, now).0);

        slaac.update_slaac_state(now);
        assert!(!sync_required(&slaac, now).0);

        // Skip time until the route expires
        let now = poll_at;
        assert!(sync_required(&slaac, now).0);
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(info.is_valid(now));
        }
        for route in slaac.routes.iter() {
            assert!(!route.is_valid(now));
        }

        slaac.update_slaac_state(now);
        assert!(!sync_required(&slaac, now).0);
        assert_eq!(slaac.routes.len(), 0);

        // Skip time until the prefix expires
        let (_, poll_at) = sync_required(&slaac, now);
        let now = poll_at;
        // Expired, so it needs a sync and there is nothing left to wait for.
        assert_eq!(sync_required(&slaac, now), (true, Instant::MAX));
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(!info.is_valid(now));
        }
        slaac.update_slaac_state(now);
        assert!(!sync_required(&slaac, now).0);
        assert_eq!(slaac.routes.len(), 0);
        assert_eq!(slaac.prefix.len(), 0);

        // No state remaining, nothing to wait on
        assert_eq!(sync_required(&slaac, now), (false, Instant::MAX));
    }

    /// A multicast prefix would form a multicast address. It is ignored.
    #[test]
    fn test_ra_multicast_prefix() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        let now = Instant::from_millis(1);
        let mut prefix = PREFIX;
        prefix.prefix = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0);
        advertise(&mut slaac, VALID, Some(prefix), now);
        assert_eq!(slaac.prefix.len(), 0);
    }

    /// A prefix longer than an address is ignored.
    #[test]
    fn test_ra_prefix_too_long() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        let now = Instant::from_millis(1);
        let mut prefix = PREFIX;
        prefix.prefix_len = 129;
        advertise(&mut slaac, VALID, Some(prefix), now);
        assert_eq!(slaac.prefix.len(), 0);
    }

    #[test]
    fn test_ra_expire() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        let now = Instant::from_millis(1);
        slaac.rs_sent(now);
        advertise(&mut slaac, VALID, Some(PREFIX), now);

        let now = Instant::from_secs(300);

        assert!(sync_required(&slaac, now).0);
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(info.is_valid(now));
        }
        for route in slaac.routes.iter() {
            assert!(route.is_valid(now));
        }
        slaac.update_slaac_state(now);

        let mut expire_prefix = PREFIX;
        expire_prefix.preferred_lifetime = Duration::ZERO;
        expire_prefix.valid_lifetime = Duration::ZERO;

        // Invalidate the prefix, but not the route
        advertise(&mut slaac, VALID, Some(expire_prefix), now);

        assert!(sync_required(&slaac, now).0);
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(!info.is_valid(now));
        }
        for route in slaac.routes.iter() {
            assert!(route.is_valid(now));
        }
        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix.len(), 0);
        assert_eq!(slaac.routes.len(), 1);

        assert!(!sync_required(&slaac, now).0);
        // Invalidate also the route
        advertise(&mut slaac, Duration::ZERO, Some(expire_prefix), now);
        assert!(sync_required(&slaac, now).0);
        for route in slaac.routes.iter() {
            assert!(!route.is_valid(now));
        }

        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix.len(), 0);
        assert_eq!(slaac.routes.len(), 0);
        assert!(!sync_required(&slaac, now).0);
        // No state remaining, nothing to wait on
        assert_eq!(sync_required(&slaac, now), (false, Instant::MAX));
    }
}
