//! IPv6 stateless address autoconfiguration (SLAAC), built into the interface.
//!
//! Turn it on per interface with [`Iface::set_slaac`](super::Iface::set_slaac).
//! The stack then sends router solicitations, and from the router advertisements
//! it receives it forms addresses (EUI-64 from the hardware address) and installs
//! default routes on the interface. Both expire with the lifetimes the router
//! advertised.
//!
//! Needs the `slaac` feature.

use crate::config::{SLAAC_PREFIX_COUNT, SLAAC_ROUTER_COUNT};
use crate::storage::Vec;

use super::{AddrOrigin, IfaceAddr, IfaceState};
use crate::driver::PacketBuf;
use crate::route::{Route as IfaceRoute, RouteOrigin};
use crate::stack::StackInner;
use crate::time::{Duration, Instant};
use crate::wire::{
    HardwareAddress, IPV6_HEADER_LEN, IPV6_LINK_LOCAL_ALL_ROUTERS, Icmpv6Message, Icmpv6Packet, IpCidr, Ipv6Address,
    Ipv6Cidr, LINK_HEADER_LEN, NdiscOption, NdiscOptionType, NdiscPrefixInfoFlags, NdiscRouterFlags,
    RawHardwareAddress, ipv6::AddressExt,
};

const MAX_RTR_SOLICITATIONS: u8 = 3;
const RTR_SOLICITATION_INTERVAL: Duration = Duration::from_secs(4);
const IPV6_DEFAULT: Ipv6Cidr = Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0);

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
    via_router: Ipv6Address,
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
    pub prefix: Ipv6Address,
}

impl PrefixInformation {
    /// Validates the prefix information option against check a, b, c in
    /// <https://www.rfc-editor.org/rfc/rfc4862#section-5.5.3>
    fn is_valid_prefix_info(&self) -> bool {
        self.flags.contains(NdiscPrefixInfoFlags::ADDRCONF)
            && !self.prefix.is_link_local()
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
    fn same_route(&self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) -> bool {
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

    fn add_route(&mut self, cidr: &Ipv6Cidr, router: &Ipv6Address, valid_until: Instant) {
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

    fn expire_route(&mut self, cidr: &Ipv6Cidr, via_router: &Ipv6Address) {
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
        source: &Ipv6Address,
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

    fn prefix_expire_sync_required(&self, now: Instant) -> bool {
        self.prefix.iter().any(|(_, info)| !info.is_valid(now))
    }

    fn route_expire_sync_required(&self, now: Instant) -> bool {
        self.routes.iter().any(|r| !r.is_valid(now))
    }

    /// Get whether a route and prefix information must be synchronized with the interface.
    pub(crate) fn sync_required(&self, now: Instant) -> bool {
        self.has_ra_update() || self.prefix_expire_sync_required(now) || self.route_expire_sync_required(now)
    }

    /// Remove expired routes and prefixes.
    fn update_slaac_state(&mut self, now: Instant) {
        self.prefix.retain(|(_, info)| info.is_valid(now));
        self.routes.retain(|r| r.is_valid(now));
        self.sync_required = false;
    }

    /// Get whether a router solicitation must be emitted.
    fn rs_required(&self, now: Instant) -> bool {
        matches!(self.phase, Phase::Start | Phase::Discovering if self.retry_rs_at <= now && self.num_solicitations > 0)
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

    /// Get the next time the SLAAC state must be polled for updates.
    ///
    /// `Instant::MAX` if there is nothing to wait on.
    pub(crate) fn poll_at(&self, now: Instant) -> Instant {
        let rs_at = match self.phase {
            Phase::Discovering | Phase::Start if self.num_solicitations > 0 => self.retry_rs_at,
            _ => Instant::MAX,
        };
        // Unlike the original, expiry deadlines count in every phase: an unsolicited
        // advertisement can install state before or after discovery.
        let prefix_at = self.prefix.iter().filter_map(|(_, prefix_info)| {
            if prefix_info.is_valid(now) {
                Some(prefix_info.valid_until)
            } else {
                None
            }
        });
        let routes_at = self
            .routes
            .iter()
            .filter_map(|r| if r.is_valid(now) { Some(r.valid_until) } else { None });
        prefix_at.chain(routes_at).fold(rs_at, Instant::min)
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
    Some(Ipv6Cidr::new(Ipv6Address::from_octets(bytes), 64))
}

impl IfaceState<'_> {
    /// Process a router advertisement that passed the NDISC validity checks.
    pub(crate) fn slaac_process_advertisement(
        &mut self,
        inner: &mut StackInner,
        src_addr: Ipv6Address,
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
            inner.fill_neighbor(self, crate::wire::IpAddress::Ipv6(src_addr), lladdr);
        }
    }

    /// Synchronize the slaac address and router state with the interface state.
    pub(crate) fn sync_slaac_state(&mut self, inner: &mut StackInner) {
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
            match self.ip_addrs.iter_mut().find(|a| a.cidr == IpCidr::Ipv6(address)) {
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
                        cidr: IpCidr::Ipv6(address),
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
            IpCidr::Ipv6(address) => {
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
                (IpCidr::Ipv6(cidr), crate::wire::IpAddress::Ipv6(via_router)) => {
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
                            (IpCidr::Ipv6(cidr), crate::wire::IpAddress::Ipv6(via_router)) => {
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

    /// Emit a router solicitation when required by the interface's slaac state machine.
    pub(crate) fn ndisc_rs_egress(&mut self, inner: &mut StackInner) {
        let Some(slaac) = &self.slaac else { return };
        if !slaac.rs_required(inner.now) {
            return;
        }
        // RFC 4861 §4.1: the source is the link-local address, or unspecified. Wait
        // for the link-local rather than solicit from `::`, since a reply to `::`
        // must be multicast and the router cannot learn our link-layer address.
        let Some(src_addr) = self.link_local_ipv6_address() else {
            return;
        };
        let dst_addr = IPV6_LINK_LOCAL_ALL_ROUTERS;

        // Router solicit: RS header (8 bytes) plus the source link-layer address
        // option.
        let Some(mut buf) = PacketBuf::try_new() else {
            // The retry timer sends the next one.
            trace!("ndisc: no packet buffer for router solicit");
            return;
        };
        let opt_len = crate::stack::lladdr_option_len(self.hardware_addr);
        buf.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN);
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
        self.slaac.as_mut().unwrap().rs_sent(inner.now);
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
        pub const SOURCE: Ipv6Address = Ipv6Address::new(0xfe80, 0xdb8, 0, 0, 0, 0, 0, 0);
        pub const PREFIX: PrefixInformation = PrefixInformation {
            prefix_len: 64,
            flags: NdiscPrefixInfoFlags::ADDRCONF,
            valid_lifetime: Duration::from_secs(700),
            preferred_lifetime: Duration::from_secs(300),
            prefix: Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        };
        pub const VALID: Duration = Duration::from_secs(600);

        pub const ROUTE: Route = Route {
            cidr: Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0),
            via_router: SOURCE,
            valid_until: Instant::from_millis_const(100000),
        };
    }
    use mock::*;

    fn advertise(slaac: &mut Slaac, router_lifetime: Duration, prefix: Option<PrefixInformation>, now: Instant) {
        slaac.process_advertisement(
            &SOURCE,
            NdiscRouterFlags::empty(),
            router_lifetime,
            prefix.into_iter(),
            now,
        );
    }

    #[test]
    fn test_route() {
        assert!(ROUTE.same_route(&Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0), &SOURCE));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 64), &SOURCE));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0), &Ipv6Address::UNSPECIFIED));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 0), &Ipv6Address::UNSPECIFIED));
        assert!(!ROUTE.same_route(&Ipv6Cidr::new(SOURCE, 64), &Ipv6Address::UNSPECIFIED));
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
        assert!(slaac.rs_required(now));

        slaac.rs_sent(now);
        assert_eq!(slaac.num_solicitations, 2);
        assert!(!slaac.rs_required(now));

        let next_poll = slaac.poll_at(now);
        assert_eq!(next_poll, now + RTR_SOLICITATION_INTERVAL);

        let now = next_poll;
        assert!(slaac.rs_required(now));

        slaac.num_solicitations = 0;
        assert!(!slaac.rs_required(now));
        slaac.rs_sent(now);
        assert_eq!(slaac.phase, Phase::None);
        assert_eq!(slaac.poll_at(now), Instant::MAX);
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
        let poll_at = slaac.poll_at(now);
        assert_eq!(poll_at, now + VALID);

        for (prefix, info) in slaac.prefix.iter() {
            assert_eq!(prefix.address(), PREFIX.prefix);
            assert_eq!(prefix.prefix_len(), PREFIX.prefix_len);
            assert_eq!(info.valid_until, now + PREFIX.valid_lifetime);
            assert_eq!(info.preferred_until, now + PREFIX.preferred_lifetime);
            assert!(info.is_valid(now));
        }

        for route in slaac.routes.iter() {
            assert_eq!(route.cidr, Ipv6Cidr::new(Ipv6Address::UNSPECIFIED, 0));
            assert_eq!(route.via_router, SOURCE);
            assert_eq!(route.valid_until, now + VALID);
            assert!(route.is_valid(now));
        }
        assert_eq!(slaac.prefix.len(), 1);
        assert_eq!(slaac.routes.len(), 1);
        assert!(slaac.sync_required(now));

        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));

        // Skip time until the route expires
        let now = poll_at;
        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(info.is_valid(now));
        }
        for route in slaac.routes.iter() {
            assert!(!route.is_valid(now));
        }

        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));
        assert_eq!(slaac.routes.len(), 0);

        // Skip time until the prefix expires
        let poll_at = slaac.poll_at(now);
        let now = poll_at;
        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(!info.is_valid(now));
        }
        // Should already return MAX
        assert_eq!(slaac.poll_at(now), Instant::MAX);
        slaac.update_slaac_state(now);
        assert!(!slaac.sync_required(now));
        assert_eq!(slaac.routes.len(), 0);
        assert_eq!(slaac.prefix.len(), 0);

        // No state remaining, nothing to wait on
        assert_eq!(slaac.poll_at(now), Instant::MAX);
    }

    #[test]
    fn test_ra_expire() {
        let mut slaac = Slaac::new(SlaacConfig::default());
        let now = Instant::from_millis(1);
        slaac.rs_sent(now);
        advertise(&mut slaac, VALID, Some(PREFIX), now);

        let now = Instant::from_secs(300);

        assert!(slaac.sync_required(now));
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

        assert!(slaac.sync_required(now));
        for (_prefix, info) in slaac.prefix.iter() {
            assert!(!info.is_valid(now));
        }
        for route in slaac.routes.iter() {
            assert!(route.is_valid(now));
        }
        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix.len(), 0);
        assert_eq!(slaac.routes.len(), 1);

        assert!(!slaac.sync_required(now));
        // Invalidate also the route
        advertise(&mut slaac, Duration::ZERO, Some(expire_prefix), now);
        assert!(slaac.sync_required(now));
        for route in slaac.routes.iter() {
            assert!(!route.is_valid(now));
        }
        assert_eq!(slaac.poll_at(now), Instant::MAX);

        slaac.update_slaac_state(now);
        assert_eq!(slaac.prefix.len(), 0);
        assert_eq!(slaac.routes.len(), 0);
        assert!(!slaac.sync_required(now));
        // No state remaining, nothing to wait on
        assert_eq!(slaac.poll_at(now), Instant::MAX);
    }
}
