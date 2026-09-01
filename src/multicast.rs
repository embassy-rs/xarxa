// IP multicast group membership, with IGMP (IPv4) and MLD (IPv6). The public
// surface is `Iface::join_multicast_group` and friends, plus `MulticastError`,
// which `iface` re-exports.

use crate::config::MULTICAST_GROUP_COUNT;
use crate::storage::{Full, Vec};
use core::result::Result;

use crate::driver::PacketBuf;
use crate::iface::{Iface, IfaceState};
use crate::stack::StackInner;
use crate::time::{Duration, Instant};
use crate::wire::*;

/// Error type for [`Iface::join_multicast_group`] and [`Iface::leave_multicast_group`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MulticastError {
    /// Cannot join/leave the given multicast group.
    Unaddressable,
    /// The group table is full. Only possible without the `alloc` feature, where
    /// the limit is [`MULTICAST_GROUP_COUNT`].
    TooManyGroups,
}

#[cfg(feature = "ipv4")]
pub(crate) enum IgmpReportState {
    Inactive,
    ToGeneralQuery {
        version: IgmpVersion,
        timeout: Instant,
        interval: Duration,
        next_index: usize,
    },
    ToSpecificQuery {
        version: IgmpVersion,
        timeout: Instant,
        group: Ipv4Address,
    },
}

#[cfg(feature = "ipv6")]
pub(crate) enum MldReportState {
    Inactive,
    ToGeneralQuery { timeout: Instant },
    ToSpecificQuery { group: Ipv6Address, timeout: Instant },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupState {
    /// Joining group, we have to send the join packet.
    Joining,
    /// We've already sent the join packet, we have nothing to do.
    Joined,
    /// We want to leave the group, we have to send a leave packet.
    Leaving,
}

pub(crate) struct State {
    groups: Vec<(IpAddress, GroupState), MULTICAST_GROUP_COUNT>,
    /// When to report for (all or) the next multicast group membership via IGMP
    #[cfg(feature = "ipv4")]
    igmp_report_state: IgmpReportState,
    #[cfg(feature = "ipv6")]
    mld_report_state: MldReportState,
}

impl State {
    pub(crate) fn new() -> Self {
        Self {
            groups: Vec::new(),
            #[cfg(feature = "ipv4")]
            igmp_report_state: IgmpReportState::Inactive,
            #[cfg(feature = "ipv6")]
            mld_report_state: MldReportState::Inactive,
        }
    }

    pub(crate) fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        // Return false if we don't have the multicast group,
        // or we're leaving it.
        match self.get(&addr.into()) {
            None => false,
            Some(GroupState::Joining) => true,
            Some(GroupState::Joined) => true,
            Some(GroupState::Leaving) => false,
        }
    }

    /// The earliest time at which a pending membership report is due.
    pub(crate) fn poll_at(&self) -> Instant {
        #[allow(unused_mut)]
        let mut deadline = Instant::MAX;
        #[cfg(feature = "ipv4")]
        match self.igmp_report_state {
            IgmpReportState::Inactive => {}
            IgmpReportState::ToGeneralQuery { timeout, .. } | IgmpReportState::ToSpecificQuery { timeout, .. } => {
                deadline = deadline.min(timeout)
            }
        }
        #[cfg(feature = "ipv6")]
        match self.mld_report_state {
            MldReportState::Inactive => {}
            MldReportState::ToGeneralQuery { timeout } | MldReportState::ToSpecificQuery { timeout, .. } => {
                deadline = deadline.min(timeout)
            }
        }
        deadline
    }

    fn get(&self, addr: &IpAddress) -> Option<GroupState> {
        self.groups.iter().find(|(a, _)| a == addr).map(|(_, state)| *state)
    }

    fn get_mut(&mut self, addr: &IpAddress) -> Option<&mut GroupState> {
        self.groups.iter_mut().find(|(a, _)| a == addr).map(|(_, state)| state)
    }

    fn insert(&mut self, addr: IpAddress, state: GroupState) -> Result<(), Full> {
        match self.get_mut(&addr) {
            Some(old) => {
                *old = state;
                Ok(())
            }
            None => self.groups.push((addr, state)).map_err(|_| Full),
        }
    }

    fn remove(&mut self, addr: &IpAddress) {
        if let Some(index) = self.groups.iter().position(|(a, _)| a == addr) {
            self.groups.swap_remove(index);
        }
    }

    /// The joined addresses.
    fn keys(&self) -> impl Iterator<Item = &IpAddress> + Clone + '_ {
        self.groups.iter().map(|(addr, _)| addr)
    }

    /// The addresses of the groups the interface listens on: the joined
    /// groups, not counting the ones being left.
    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn active_groups(&self) -> impl Iterator<Item = &IpAddress> + '_ {
        self.groups
            .iter()
            .filter(|(_, state)| !matches!(state, GroupState::Leaving))
            .map(|(addr, _)| addr)
    }
}

impl core::fmt::Display for MulticastError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            MulticastError::Unaddressable => write!(f, "Unaddressable"),
            MulticastError::TooManyGroups => write!(f, "Too many groups"),
        }
    }
}

impl core::error::Error for MulticastError {}

impl Iface<'_, '_> {
    /// Join a multicast group.
    ///
    /// The stack accepts packets sent to the group right away, and reports the
    /// membership to the routers on the link from the next [`Stack::poll`](crate::Stack::poll).
    ///
    /// Errors:
    /// - `Unaddressable` if the address is not a multicast address.
    pub fn join_multicast_group<T: Into<IpAddress>>(&mut self, addr: T) -> Result<(), MulticastError> {
        let res = self.state_mut().join_multicast_group(addr);
        #[cfg(feature = "medium-ethernet")]
        self.state_mut().sync_multicast_filter();
        res
    }

    /// Leave a multicast group.
    ///
    /// The stack stops accepting packets sent to the group right away, and
    /// reports the leave to the routers on the link from the next
    /// [`Stack::poll`](crate::Stack::poll). Leaving a group that was not joined
    /// does nothing.
    ///
    /// Errors:
    /// - `Unaddressable` if the address is not a multicast address.
    pub fn leave_multicast_group<T: Into<IpAddress>>(&mut self, addr: T) -> Result<(), MulticastError> {
        let res = self.state_mut().leave_multicast_group(addr);
        #[cfg(feature = "medium-ethernet")]
        self.state_mut().sync_multicast_filter();
        res
    }

    /// Check whether the interface listens to the given multicast address.
    ///
    /// Besides the joined groups, this is true for the groups every host is a
    /// member of: the IPv4 all systems group, the IPv6 all nodes group, and the
    /// IPv6 solicited node group of each address assigned to the interface.
    pub fn has_multicast_group<T: Into<IpAddress>>(&self, addr: T) -> bool {
        self.state().has_multicast_group(addr)
    }
}

impl IfaceState<'_> {
    /// Add an address to a list of subscribed multicast IP addresses.
    pub(crate) fn join_multicast_group<T: Into<IpAddress>>(&mut self, addr: T) -> Result<(), MulticastError> {
        let addr = addr.into();
        if !addr.is_multicast() {
            return Err(MulticastError::Unaddressable);
        }

        if let Some(state) = self.multicast.get_mut(&addr) {
            *state = match state {
                GroupState::Joining => GroupState::Joining,
                GroupState::Joined => GroupState::Joined,
                GroupState::Leaving => GroupState::Joined,
            };
        } else {
            self.multicast
                .insert(addr, GroupState::Joining)
                .map_err(|_| MulticastError::TooManyGroups)?;
        }
        Ok(())
    }

    /// Remove an address from the subscribed multicast IP addresses.
    pub(crate) fn leave_multicast_group<T: Into<IpAddress>>(&mut self, addr: T) -> Result<(), MulticastError> {
        let addr = addr.into();
        if !addr.is_multicast() {
            return Err(MulticastError::Unaddressable);
        }

        if let Some(state) = self.multicast.get_mut(&addr) {
            let delete;
            (*state, delete) = match state {
                GroupState::Joining => (GroupState::Joined, true),
                GroupState::Joined => (GroupState::Leaving, false),
                GroupState::Leaving => (GroupState::Leaving, false),
            };
            if delete {
                self.multicast.remove(&addr);
            }
        }
        Ok(())
    }

    #[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
    pub(crate) fn update_solicited_node_groups(&mut self) {
        // Remove old solicited-node multicast addresses
        // Walk the group table by index: leaving a group may remove the entry
        // at the current index (and move the last one into its place), in
        // which case the index is not advanced.
        let mut i = 0;
        while i < self.multicast.groups.len() {
            let (addr, _) = self.multicast.groups[i];
            let stale =
                matches!(addr, IpAddress::Ipv6(a) if a.is_solicited_node_multicast() && !self.has_solicited_node(a));
            let len = self.multicast.groups.len();
            if stale {
                let _ = self.leave_multicast_group(addr);
            }
            if self.multicast.groups.len() == len {
                i += 1;
            }
        }

        // Joining only touches the group table, so the address table can be
        // walked by index.
        for i in 0..self.ip_addrs.len() {
            #[allow(irrefutable_let_patterns)]
            if let IpCidr::Ipv6(cidr) = self.ip_addrs[i].cidr {
                let _ = self.join_multicast_group(cidr.address().solicited_node());
            }
        }
    }

    /// Do multicast egress.
    ///
    /// - Send join/leave packets according to the multicast group state.
    /// - Depending on `igmp_report_state` and the therein contained
    ///   timeouts, send IGMP membership reports.
    pub(crate) fn multicast_egress(&mut self, inner: &mut StackInner) {
        // Process multicast joins.
        while let Some(&(addr, _)) = self
            .multicast
            .groups
            .iter()
            .find(|&&(_, state)| state == GroupState::Joining)
        {
            match addr {
                #[cfg(feature = "ipv4")]
                IpAddress::Ipv4(addr) => {
                    if let Some(pkt) = self.igmp_report_packet(IgmpVersion::Version2, addr) {
                        self.dispatch_ip(inner, pkt);
                    }
                }
                #[cfg(feature = "ipv6")]
                IpAddress::Ipv6(addr) => {
                    if let Some(pkt) =
                        self.mldv2_report_packet(core::iter::once((MldRecordType::ChangeToInclude, addr)))
                    {
                        self.dispatch_ip(inner, pkt);
                    }
                }
            }

            // NOTE: this is always replacing an existing entry, so it can't fail.
            let _ = self.multicast.insert(addr, GroupState::Joined);
        }

        // Process multicast leaves.
        while let Some(&(addr, _)) = self
            .multicast
            .groups
            .iter()
            .find(|&&(_, state)| state == GroupState::Leaving)
        {
            match addr {
                #[cfg(feature = "ipv4")]
                IpAddress::Ipv4(addr) => {
                    if let Some(pkt) = self.igmp_leave_packet(addr) {
                        self.dispatch_ip(inner, pkt);
                    }
                }
                #[cfg(feature = "ipv6")]
                IpAddress::Ipv6(addr) => {
                    if let Some(pkt) =
                        self.mldv2_report_packet(core::iter::once((MldRecordType::ChangeToExclude, addr)))
                    {
                        self.dispatch_ip(inner, pkt);
                    }
                }
            }

            self.multicast.remove(&addr);
        }

        #[cfg(feature = "ipv4")]
        match self.multicast.igmp_report_state {
            IgmpReportState::ToSpecificQuery {
                version,
                timeout,
                group,
            } if inner.now >= timeout => {
                if let Some(pkt) = self.igmp_report_packet(version, group) {
                    // Send initial membership report
                    self.dispatch_ip(inner, pkt);
                }
                self.multicast.igmp_report_state = IgmpReportState::Inactive;
            }
            IgmpReportState::ToGeneralQuery {
                version,
                timeout,
                interval,
                next_index,
            } if inner.now >= timeout => {
                let addr = self
                    .multicast
                    .keys()
                    .filter_map(|addr| match addr {
                        IpAddress::Ipv4(addr) => Some(*addr),
                        #[allow(unreachable_patterns)]
                        _ => None,
                    })
                    .nth(next_index);

                match addr {
                    Some(addr) => {
                        if let Some(pkt) = self.igmp_report_packet(version, addr) {
                            // Send initial membership report
                            self.dispatch_ip(inner, pkt);

                            let next_timeout = (timeout + interval).max(inner.now);
                            self.multicast.igmp_report_state = IgmpReportState::ToGeneralQuery {
                                version,
                                timeout: next_timeout,
                                interval,
                                next_index: next_index + 1,
                            };
                        } else {
                            // No address to report from: nothing else to send.
                            self.multicast.igmp_report_state = IgmpReportState::Inactive;
                        }
                    }
                    None => {
                        self.multicast.igmp_report_state = IgmpReportState::Inactive;
                    }
                }
            }
            _ => {}
        }
        #[cfg(feature = "ipv6")]
        match self.multicast.mld_report_state {
            MldReportState::ToGeneralQuery { timeout } if inner.now >= timeout => {
                let records = self.multicast.keys().filter_map(|addr| match addr {
                    IpAddress::Ipv6(addr) => Some((MldRecordType::ModeIsExclude, *addr)),
                    #[allow(unreachable_patterns)]
                    _ => None,
                });
                if let Some(pkt) = self.mldv2_report_packet(records) {
                    self.dispatch_ip(inner, pkt);
                }
                self.multicast.mld_report_state = MldReportState::Inactive;
            }
            MldReportState::ToSpecificQuery { group, timeout } if inner.now >= timeout => {
                let record = (MldRecordType::ModeIsExclude, group);
                if let Some(pkt) = self.mldv2_report_packet(core::iter::once(record)) {
                    self.dispatch_ip(inner, pkt);
                }
                self.multicast.mld_report_state = MldReportState::Inactive;
            }
            _ => {}
        }
    }

    /// Transmit a fully-built IP packet (IP header included) on this interface.
    ///
    /// The destination is multicast, which is always routable and doesn't require
    /// neighbor discovery: the packet goes out of this interface, with the
    /// destination itself as the next hop.
    fn dispatch_ip(&mut self, inner: &mut StackInner, mut buf: PacketBuf) {
        let (dst_addr, ethertype) = match IpVersion::of_packet(&buf) {
            #[cfg(feature = "ipv4")]
            Ok(IpVersion::Ipv4) => (
                IpAddress::Ipv4(Ipv4Packet::new_unchecked(&mut buf).dst_addr()),
                EthernetProtocol::Ipv4,
            ),
            #[cfg(feature = "ipv6")]
            Ok(IpVersion::Ipv6) => (
                IpAddress::Ipv6(Ipv6Packet::new_unchecked(&mut buf).dst_addr()),
                EthernetProtocol::Ipv6,
            ),
            Err(_) => return,
        };
        inner.transmit_ip(self, dst_addr, dst_addr, buf, ethertype);
    }

    /// Host duties of the **IGMPv2** protocol.
    ///
    /// Sets up `igmp_report_state` for responding to IGMP general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; this is not currently done.
    #[cfg(feature = "ipv4")]
    pub(crate) fn process_igmp(&mut self, inner: &mut StackInner, dst_addr: Ipv4Address, mut buf: PacketBuf) {
        let igmp_packet = check!(IgmpPacket::new_checked(&mut buf));
        if !igmp_packet.verify_checksum() {
            trace!("igmp: checksum incorrect");
            return;
        }

        // Check if the address is 0.0.0.0 or multicast
        let group_addr = igmp_packet.group_addr();
        if !group_addr.is_unspecified() && !group_addr.is_multicast() {
            trace!("igmp: malformed group address");
            return;
        }

        // FIXME: report membership after a delay
        match igmp_packet.msg_type() {
            IgmpMessage::MembershipQuery => {
                let max_resp_time = igmp_packet.max_resp_time();
                // See RFC 3376: 7.1. Query Version Distinctions
                let version = if igmp_packet.max_resp_code() == 0 {
                    IgmpVersion::Version1
                } else {
                    IgmpVersion::Version2
                };

                // General query
                if group_addr.is_unspecified() && dst_addr == IPV4_MULTICAST_ALL_SYSTEMS {
                    let ipv4_multicast_group_count = self
                        .multicast
                        .keys()
                        .filter(|a| matches!(a, IpAddress::Ipv4(_)))
                        .count();

                    // Are we member in any groups?
                    if ipv4_multicast_group_count != 0 {
                        let interval = match version {
                            IgmpVersion::Version1 => Duration::from_millis(100),
                            IgmpVersion::Version2 => {
                                // No dependence on a random generator
                                // (see [#24](https://github.com/m-labs/smoltcp/issues/24))
                                // but at least spread reports evenly across max_resp_time.
                                let intervals = ipv4_multicast_group_count as u32 + 1;
                                max_resp_time / intervals
                            }
                        };
                        self.multicast.igmp_report_state = IgmpReportState::ToGeneralQuery {
                            version,
                            timeout: inner.now + interval,
                            interval,
                            next_index: 0,
                        };
                    }
                } else {
                    // Group-specific query
                    if self.has_multicast_group(group_addr) && dst_addr == group_addr {
                        // Don't respond immediately
                        let timeout = max_resp_time / 4;
                        self.multicast.igmp_report_state = IgmpReportState::ToSpecificQuery {
                            version,
                            timeout: inner.now + timeout,
                            group: group_addr,
                        };
                    }
                }
            }
            // Ignore membership reports
            IgmpMessage::MembershipReportV1 | IgmpMessage::MembershipReportV2 => (),
            // Ignore hosts leaving groups
            IgmpMessage::LeaveGroup => (),
            _ => trace!("igmp: unknown message type"),
        }
    }

    #[cfg(feature = "ipv4")]
    fn igmp_report_packet(&self, version: IgmpVersion, group_addr: Ipv4Address) -> Option<PacketBuf> {
        let iface_addr = self.ipv4_addr()?;
        let mut pkt = PacketBuf::try_new()?;
        pkt.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
        pkt.set_len(IGMP_BUFFER_LEN);
        {
            let mut igmp_packet = IgmpPacket::new_unchecked(&mut pkt);
            match version {
                IgmpVersion::Version1 => igmp_packet.set_msg_type(IgmpMessage::MembershipReportV1),
                IgmpVersion::Version2 => igmp_packet.set_msg_type(IgmpMessage::MembershipReportV2),
            };
            igmp_packet.set_max_resp_code(0);
            igmp_packet.set_group_address(group_addr);
            igmp_packet.fill_checksum();
        }
        // Send to the group being reported
        // [#183](https://github.com/m-labs/smoltcp/issues/183).
        crate::stack::push_ipv4_header(
            &mut pkt,
            iface_addr,
            group_addr,
            IpProtocol::Igmp,
            1,
            &self.checksum_caps(),
        );
        Some(pkt)
    }

    #[cfg(feature = "ipv4")]
    fn igmp_leave_packet(&self, group_addr: Ipv4Address) -> Option<PacketBuf> {
        let iface_addr = self.ipv4_addr()?;
        let mut pkt = PacketBuf::try_new()?;
        pkt.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN);
        pkt.set_len(IGMP_BUFFER_LEN);
        {
            let mut igmp_packet = IgmpPacket::new_unchecked(&mut pkt);
            igmp_packet.set_msg_type(IgmpMessage::LeaveGroup);
            igmp_packet.set_max_resp_code(0);
            igmp_packet.set_group_address(group_addr);
            igmp_packet.fill_checksum();
        }
        crate::stack::push_ipv4_header(
            &mut pkt,
            iface_addr,
            IPV4_MULTICAST_ALL_ROUTERS,
            IpProtocol::Igmp,
            1,
            &self.checksum_caps(),
        );
        Some(pkt)
    }

    /// Host duties of the **MLDv2** protocol.
    ///
    /// Sets up `mld_report_state` for responding to MLD general/specific membership queries.
    /// Membership must not be reported immediately in order to avoid flooding the network
    /// after a query is broadcasted by a router; Currently the delay is fixed and not randomized.
    #[cfg(feature = "ipv6")]
    pub(crate) fn process_mldv2(
        &mut self,
        inner: &mut StackInner,
        dst_addr: Ipv6Address,
        icmp_packet: &Icmpv6Packet<'_>,
    ) {
        if icmp_packet.msg_code() != 0 {
            return;
        }

        let mcast_addr = icmp_packet.mcast_addr();
        let max_resp_code = icmp_packet.max_resp_code();

        // Do not respond immediately to the query, but wait a random time
        let delay = if max_resp_code > 0 {
            (inner.rand.rand_u16() % max_resp_code).into()
        } else {
            0
        };
        let delay = Duration::from_millis(delay);
        // General query
        if mcast_addr.is_unspecified() && (dst_addr == IPV6_LINK_LOCAL_ALL_NODES || self.has_ip_addr(dst_addr)) {
            let ipv6_multicast_group_count = self
                .multicast
                .keys()
                .filter(|a| matches!(a, IpAddress::Ipv6(_)))
                .count();
            if ipv6_multicast_group_count != 0 {
                self.multicast.mld_report_state = MldReportState::ToGeneralQuery {
                    timeout: inner.now + delay,
                };
            }
        }
        if self.has_multicast_group(mcast_addr) && dst_addr == mcast_addr {
            self.multicast.mld_report_state = MldReportState::ToSpecificQuery {
                group: mcast_addr,
                timeout: inner.now + delay,
            };
        }
    }

    #[cfg(feature = "ipv6")]
    /// Build an MLDv2 report with one address record per item of `records`.
    ///
    /// Records past what fits in one packet are left out.
    fn mldv2_report_packet(
        &self,
        records: impl Iterator<Item = (MldRecordType, Ipv6Address)> + Clone,
    ) -> Option<PacketBuf> {
        // Per [RFC 3810 § 5.2.13], source addresses must be link-local, falling
        // back to the unspecified address if we haven't acquired one.
        // [RFC 3810 § 5.2.13]: https://tools.ietf.org/html/rfc3810#section-5.2.13
        let src_addr = self.link_local_ipv6_address().unwrap_or(Ipv6Address::UNSPECIFIED);

        // Per [RFC 3810 § 5.2.14], all MLDv2 reports are sent to ff02::16.
        // [RFC 3810 § 5.2.14]: https://tools.ietf.org/html/rfc3810#section-5.2.14
        let dst_addr = IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS;

        // MLD report: the report header (8 bytes) plus one record per group.
        let mut pkt = PacketBuf::try_new()?;
        pkt.reserve(LINK_HEADER_LEN + IPV6_HEADER_LEN + MLDV2_ROUTER_ALERT_LEN);
        let max_records = (pkt.tailroom() - 8) / MLD_ADDRESS_RECORD_LEN;
        let record_count = records.clone().count();
        if record_count > max_records {
            warn!(
                "mld: {} groups don't fit in one report, reporting {}",
                record_count, max_records
            );
        }
        let record_count = record_count.min(max_records);
        let records = records.take(record_count);
        pkt.set_len(8 + record_count * MLD_ADDRESS_RECORD_LEN);
        {
            let mut mld = Icmpv6Packet::new_unchecked(&mut pkt);
            mld.set_msg_type(Icmpv6Message::MldReport);
            mld.set_msg_code(0);
            mld.clear_reserved();
            mld.set_nr_mcast_addr_rcrds(record_count as u16);
            let mut payload = mld.payload_mut();
            for (record_type, mcast_addr) in records {
                let mut record = MldAddressRecord::new_unchecked(&mut payload[..MLD_ADDRESS_RECORD_LEN]);
                record.set_record_type(record_type);
                record.set_aux_data_len(0);
                record.set_num_srcs(0);
                record.set_mcast_addr(mcast_addr);
                payload = &mut payload[MLD_ADDRESS_RECORD_LEN..];
            }
            if !self.checksum_caps().icmpv6.tx {
                mld.fill_checksum(&src_addr, &dst_addr);
            } else {
                mld.set_checksum(0);
            }
        }
        push_mldv2_router_alert(&mut pkt);

        // All MLDv2 messages must be sent with an IPv6 Hop limit of 1.
        crate::stack::push_ipv6_header(&mut pkt, src_addr, dst_addr, IpProtocol::HopByHop, 1);
        Some(pkt)
    }
}

/// The length of the hop-by-hop header carrying the MLDv2 router alert option.
#[cfg(feature = "ipv6")]
const MLDV2_ROUTER_ALERT_LEN: usize = 8;

/// Prepend the hop-by-hop header containing a MLDv2 router alert option to a
/// fully-built MLD message.
///
/// One 8-byte extension header: next header and length, the router alert
/// option (RFC 2711), and a PadN option of length 0 to fill the 8 bytes.
#[cfg(feature = "ipv6")]
fn push_mldv2_router_alert(buf: &mut PacketBuf) {
    buf.push_front(MLDV2_ROUTER_ALERT_LEN);
    let hbh = &mut buf[..MLDV2_ROUTER_ALERT_LEN];
    hbh[0] = IpProtocol::Icmpv6.into();
    hbh[1] = 0;
    hbh[2] = Ipv6OptionType::RouterAlert.into();
    hbh[3] = Ipv6RouterAlert::DATA_LEN;
    hbh[4..6].copy_from_slice(&u16::from(Ipv6RouterAlert::MulticastListenerDiscovery).to_be_bytes());
    hbh[6] = Ipv6OptionType::PadN.into();
    hbh[7] = 0;
}

#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "ipv6"
))]
mod test {
    use std::vec::Vec;

    use super::*;
    use crate::driver::{ChecksumCapabilities, ChecksumOffload};
    use crate::iface::IfaceHandle;
    use crate::iface::Medium;
    use crate::stack::Stack;
    use crate::test_device::{Queue, Sent, TestDevice};

    const OUR_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const REMOTE_HW: EthernetAddress = EthernetAddress([0x52, 0x54, 0x00, 0x00, 0x00, 0x00]);
    const OUR_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const REMOTE_V4: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const OUR_LL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const REMOTE_LL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x100);
    const IFACE: IfaceHandle = IfaceHandle::new(0);

    /// A stack with one interface of the given medium, owning [`OUR_V4`]/24 and
    /// [`OUR_LL`]/64 (plus, on Ethernet, the automatic link-local address, whose
    /// solicited-node group is the same as [`OUR_LL`]'s).
    fn test_stack(medium: Medium) -> (Stack<'static>, Queue, Sent) {
        test_stack_with_checksum(medium, ChecksumCapabilities::default())
    }

    /// [`test_stack`], with a device that claims to handle the given checksums itself.
    fn test_stack_with_checksum(medium: Medium, checksum: ChecksumCapabilities) -> (Stack<'static>, Queue, Sent) {
        let driver = TestDevice::new(medium).with_checksum(checksum);
        let (rx, tx) = (driver.rx.clone(), driver.tx.clone());
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(
            &mut stack,
            match medium {
                Medium::Ethernet => HardwareAddress::Ethernet(OUR_HW),
                Medium::Ip => HardwareAddress::Ip,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => unreachable!(),
            },
        );
        assert_eq!(handle, IFACE);
        stack
            .iface(handle)
            .set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_LL.into(), 64)])
            .unwrap();
        (stack, rx, tx)
    }

    /// The IP packets transmitted since the last call, link-layer header stripped.
    fn recv_all(medium: Medium, tx: &Sent) -> Vec<Vec<u8>> {
        tx.borrow_mut()
            .drain(..)
            .map(|frame| match medium {
                Medium::Ethernet => {
                    let mut bytes = frame;
                    let eth = EthernetFrame::new_checked(&mut bytes[..]).unwrap();
                    assert_eq!(eth.src_addr(), OUR_HW);
                    assert!(eth.dst_addr().is_multicast());
                    bytes[ETHERNET_HEADER_LEN..].to_vec()
                }
                Medium::Ip => frame,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => unreachable!(),
            })
            .collect()
    }

    /// Inject an IP packet, framed for the medium, and poll the stack to process it.
    fn inject(
        stack: &mut Stack,
        rx: &Queue,
        medium: Medium,
        ethertype: EthernetProtocol,
        packet: Vec<u8>,
        now: Instant,
    ) -> Instant {
        let frame = match medium {
            Medium::Ethernet => {
                let mut frame = vec![0; ETHERNET_HEADER_LEN];
                {
                    let mut eth = EthernetFrame::new_unchecked(&mut frame[..]);
                    eth.set_dst_addr(EthernetAddress([0x33, 0x33, 0x00, 0x00, 0x00, 0x00]));
                    eth.set_src_addr(REMOTE_HW);
                    eth.set_ethertype(ethertype);
                }
                frame.extend_from_slice(&packet);
                frame
            }
            Medium::Ip => packet,
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => unreachable!(),
        };
        rx.borrow_mut().push_back(frame);
        stack.poll(now)
    }

    /// A parsed IGMP packet: source, destination, hop limit, message type, group.
    type IgmpReport = (Ipv4Address, Ipv4Address, u8, IgmpMessage, Ipv4Address);

    fn recv_igmp(medium: Medium, tx: &Sent) -> Vec<IgmpReport> {
        recv_all(medium, tx)
            .iter_mut()
            .filter_map(|packet| {
                let mut ipv4_packet = Ipv4Packet::new_checked(&mut packet[..]).ok()?;
                assert!(ipv4_packet.verify_checksum());
                if ipv4_packet.next_header() != IpProtocol::Igmp {
                    return None;
                }
                let (src_addr, dst_addr, hop_limit) =
                    (ipv4_packet.src_addr(), ipv4_packet.dst_addr(), ipv4_packet.hop_limit());
                let igmp_packet = IgmpPacket::new_checked(ipv4_packet.payload_mut()).ok()?;
                assert!(igmp_packet.verify_checksum());
                Some((
                    src_addr,
                    dst_addr,
                    hop_limit,
                    igmp_packet.msg_type(),
                    igmp_packet.group_addr(),
                ))
            })
            .collect()
    }

    /// A whole IPv4 packet carrying an IGMP message.
    fn igmp_packet(
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        msg_type: IgmpMessage,
        max_resp_time: Duration,
        group_addr: Ipv4Address,
    ) -> Vec<u8> {
        let mut bytes = vec![0; IPV4_HEADER_LEN + IGMP_BUFFER_LEN];
        {
            let mut igmp = IgmpPacket::new_unchecked(&mut bytes[IPV4_HEADER_LEN..]);
            igmp.set_msg_type(msg_type);
            igmp.set_max_resp_time(max_resp_time);
            igmp.set_group_address(group_addr);
            igmp.fill_checksum();
        }
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + IGMP_BUFFER_LEN) as u16);
            ip.set_next_header(IpProtocol::Igmp);
            ip.set_hop_limit(1);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
            ip.fill_checksum();
        }
        bytes
    }

    /// A parsed MLDv2 report: source, destination, hop limit, and the address records.
    type MldReport = (Ipv6Address, Ipv6Address, u8, Vec<(MldRecordType, Ipv6Address)>);

    fn recv_mld(medium: Medium, tx: &Sent) -> Vec<MldReport> {
        recv_all(medium, tx)
            .iter_mut()
            .filter_map(|packet| {
                let ipv6_packet = Ipv6Packet::new_checked(&mut packet[..]).ok()?;
                if ipv6_packet.next_header() != IpProtocol::HopByHop {
                    return None;
                }
                let (src_addr, dst_addr, hop_limit) =
                    (ipv6_packet.src_addr(), ipv6_packet.dst_addr(), ipv6_packet.hop_limit());

                // The first 2 octets of this payload hold the next-header indicator and the
                // Hop-by-Hop header length (in 8-octet words, minus 1). The remaining 6 octets
                // hold the Hop-by-Hop Router Alert and PadN options.
                let ip_payload = &mut packet[IPV6_HEADER_LEN..];
                assert_eq!(&ip_payload[..8], &[0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00]);

                let mut icmpv6_packet = Icmpv6Packet::new_checked(&mut ip_payload[8..]).unwrap();
                assert!(icmpv6_packet.verify_checksum(&src_addr, &dst_addr));
                assert_eq!(icmpv6_packet.msg_type(), Icmpv6Message::MldReport);
                assert_eq!(icmpv6_packet.msg_code(), 0);
                let nr_mcast_addr_rcrds = icmpv6_packet.nr_mcast_addr_rcrds() as usize;

                let mut records = Vec::new();
                let mut payload = icmpv6_packet.payload_mut();
                while !payload.is_empty() {
                    let record = MldAddressRecord::new_checked(payload).unwrap();
                    assert_eq!(record.num_srcs(), 0);
                    assert_eq!(record.aux_data_len(), 0);
                    records.push((record.record_type(), record.mcast_addr()));
                    payload = &mut payload[MLD_ADDRESS_RECORD_LEN..];
                }
                assert_eq!(records.len(), nr_mcast_addr_rcrds);
                Some((src_addr, dst_addr, hop_limit, records))
            })
            .collect()
    }

    /// A whole IPv6 packet carrying an MLDv2 query from `src_addr` to `dst_addr`,
    /// with hop limit 1.
    fn mld_query(src_addr: Ipv6Address, dst_addr: Ipv6Address, mcast_addr: Ipv6Address, max_resp_code: u16) -> Vec<u8> {
        let mut bytes = vec![0; IPV6_HEADER_LEN + 28];
        {
            let mut query = Icmpv6Packet::new_unchecked(&mut bytes[IPV6_HEADER_LEN..]);
            query.set_msg_type(Icmpv6Message::MldQuery);
            query.set_msg_code(0);
            query.clear_reserved();
            query.set_max_resp_code(max_resp_code);
            query.set_mcast_addr(mcast_addr);
            query.clear_s_flag();
            query.set_qrv(1);
            query.set_qqic(60);
            query.set_num_srcs(0);
            query.fill_checksum(&src_addr, &dst_addr);
        }
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len(28);
            ip.set_next_header(IpProtocol::Icmpv6);
            ip.set_hop_limit(1);
            ip.set_src_addr(src_addr);
            ip.set_dst_addr(dst_addr);
        }
        bytes
    }

    #[test]
    fn test_handle_igmp() {
        for medium in [Medium::Ip, Medium::Ethernet] {
            let groups = [Ipv4Address::new(224, 0, 0, 22), Ipv4Address::new(224, 0, 0, 56)];

            let (mut stack, rx, tx) = test_stack(medium);
            stack.poll(Instant::ZERO);
            tx.borrow_mut().clear();

            // Join multicast groups
            let timestamp = Instant::ZERO;
            for group in &groups {
                stack.iface(IFACE).join_multicast_group(*group).unwrap();
                assert!(stack.iface(IFACE).has_multicast_group(*group));
            }
            assert!(stack.iface(IFACE).has_multicast_group(IPV4_MULTICAST_ALL_SYSTEMS));
            assert_eq!(stack.poll(timestamp), Instant::MAX);

            let reports = recv_igmp(medium, &tx);
            assert_eq!(reports.len(), 2);
            for (i, group_addr) in groups.iter().enumerate() {
                assert_eq!(
                    reports[i],
                    (OUR_V4, *group_addr, 1, IgmpMessage::MembershipReportV2, *group_addr)
                );
            }

            // General query: the memberships are reported one at a time, spread
            // evenly over the maximum response time.
            let max_resp_time = Duration::from_secs(10);
            let interval = max_resp_time / 3;
            let query = igmp_packet(
                REMOTE_V4,
                IPV4_MULTICAST_ALL_SYSTEMS,
                IgmpMessage::MembershipQuery,
                max_resp_time,
                Ipv4Address::UNSPECIFIED,
            );
            let deadline = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, timestamp);
            assert_eq!(deadline, timestamp + interval);
            assert!(recv_igmp(medium, &tx).is_empty());

            let deadline = stack.poll(deadline);
            assert_eq!(deadline, timestamp + interval * 2);
            assert_eq!(
                recv_igmp(medium, &tx),
                [(OUR_V4, groups[0], 1, IgmpMessage::MembershipReportV2, groups[0])]
            );
            let deadline = stack.poll(deadline);
            assert_eq!(deadline, timestamp + interval * 3);
            assert_eq!(
                recv_igmp(medium, &tx),
                [(OUR_V4, groups[1], 1, IgmpMessage::MembershipReportV2, groups[1])]
            );
            assert_eq!(stack.poll(deadline), Instant::MAX);
            assert!(recv_igmp(medium, &tx).is_empty());

            // Group-specific query: only the queried group is reported, after a
            // quarter of the maximum response time.
            let query = igmp_packet(
                REMOTE_V4,
                groups[1],
                IgmpMessage::MembershipQuery,
                max_resp_time,
                groups[1],
            );
            let deadline = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, timestamp);
            assert_eq!(deadline, timestamp + max_resp_time / 4);
            assert!(recv_igmp(medium, &tx).is_empty());
            assert_eq!(stack.poll(deadline), Instant::MAX);
            assert_eq!(
                recv_igmp(medium, &tx),
                [(OUR_V4, groups[1], 1, IgmpMessage::MembershipReportV2, groups[1])]
            );

            // A query for a group we're not a member of is ignored.
            let other = Ipv4Address::new(224, 0, 0, 99);
            let query = igmp_packet(REMOTE_V4, other, IgmpMessage::MembershipQuery, max_resp_time, other);
            assert_eq!(
                inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, timestamp),
                Instant::MAX
            );

            // Leave multicast groups
            let timestamp = Instant::ZERO;
            for group in &groups {
                stack.iface(IFACE).leave_multicast_group(*group).unwrap();
                assert!(!stack.iface(IFACE).has_multicast_group(*group));
            }
            stack.poll(timestamp);

            let leaves = recv_igmp(medium, &tx);
            assert_eq!(leaves.len(), 2);
            for (i, group_addr) in groups.iter().cloned().enumerate() {
                assert_eq!(
                    leaves[i],
                    (
                        OUR_V4,
                        IPV4_MULTICAST_ALL_ROUTERS,
                        1,
                        IgmpMessage::LeaveGroup,
                        group_addr
                    )
                );
            }
        }
    }

    #[test]
    fn test_join_ipv6_multicast_group() {
        for medium in [Medium::Ip, Medium::Ethernet] {
            let (mut stack, _rx, tx) = test_stack(medium);

            let groups = [
                Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb),
                Ipv6Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x0017),
            ];

            let timestamp = Instant::from_millis(0);

            // Drain the unsolicited node multicast report from the device
            stack.poll(timestamp);
            let _ = recv_mld(medium, &tx);

            for &group in &groups {
                stack.iface(IFACE).join_multicast_group(group).unwrap();
                assert!(stack.iface(IFACE).has_multicast_group(group));
            }
            assert!(stack.iface(IFACE).has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));
            stack.poll(timestamp);
            assert!(stack.iface(IFACE).has_multicast_group(IPV6_LINK_LOCAL_ALL_NODES));

            let reports = recv_mld(medium, &tx);
            assert_eq!(reports.len(), 2);

            for (&group_addr, report) in groups.iter().zip(reports) {
                assert_eq!(
                    report,
                    (
                        OUR_LL,
                        IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
                        1,
                        vec![(MldRecordType::ChangeToInclude, group_addr)]
                    )
                );

                stack.iface(IFACE).leave_multicast_group(group_addr).unwrap();
                assert!(!stack.iface(IFACE).has_multicast_group(group_addr));
                stack.poll(timestamp);
                assert!(!stack.iface(IFACE).has_multicast_group(group_addr));
                assert_eq!(
                    recv_mld(medium, &tx),
                    [(
                        OUR_LL,
                        IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
                        1,
                        vec![(MldRecordType::ChangeToExclude, group_addr)]
                    )]
                );
            }
        }
    }

    #[test]
    fn test_handle_valid_multicast_query() {
        let medium = Medium::Ethernet;
        let (mut stack, rx, tx) = test_stack(medium);

        let mut timestamp = Instant::ZERO;

        let query_ip_addr = Ipv6Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);

        stack.iface(IFACE).join_multicast_group(query_ip_addr).unwrap();

        stack.poll(timestamp);
        // flush multicast reports from the join_multicast_group calls
        recv_mld(medium, &tx);

        let queries = [
            // General query, expect both multicast addresses back
            (
                Ipv6Address::UNSPECIFIED,
                IPV6_LINK_LOCAL_ALL_NODES,
                vec![OUR_LL.solicited_node(), query_ip_addr],
            ),
            // Address specific query, expect only the queried address back
            (query_ip_addr, query_ip_addr, vec![query_ip_addr]),
        ];

        for (mcast_query, address, results) in queries.iter() {
            let query = mld_query(REMOTE_LL, *address, *mcast_query, 1000);
            // The report is delayed by a random time within the maximum response time.
            let deadline = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, query, timestamp);
            assert!(deadline >= timestamp && deadline < timestamp + Duration::from_millis(1000));
            assert!(recv_mld(medium, &tx).is_empty());

            timestamp += Duration::from_millis(1000);
            assert_eq!(stack.poll(timestamp), Instant::MAX);

            let expected_records = results
                .iter()
                .map(|addr| (MldRecordType::ModeIsExclude, *addr))
                .collect::<Vec<_>>();
            assert_eq!(
                recv_mld(medium, &tx),
                [(OUR_LL, IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS, 1, expected_records)]
            );
        }

        // A query that didn't come from a link-local address, or with a hop limit
        // other than 1, is ignored.
        let query = mld_query(
            Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2),
            IPV6_LINK_LOCAL_ALL_NODES,
            Ipv6Address::UNSPECIFIED,
            1000,
        );
        assert_eq!(
            inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, query, timestamp),
            Instant::MAX
        );
        let mut query = mld_query(REMOTE_LL, IPV6_LINK_LOCAL_ALL_NODES, Ipv6Address::UNSPECIFIED, 1000);
        Ipv6Packet::new_unchecked(&mut query[..]).set_hop_limit(64);
        assert_eq!(
            inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, query, timestamp),
            Instant::MAX
        );
    }

    /// The solicited-node group of every address is joined automatically on
    /// Ethernet interfaces, and left when the address goes away.
    #[test]
    fn test_solicited_node_groups() {
        let medium = Medium::Ethernet;
        let (mut stack, _rx, tx) = test_stack(medium);
        let solicited_node = OUR_LL.solicited_node();
        assert!(stack.iface(IFACE).has_multicast_group(solicited_node));

        stack.poll(Instant::ZERO);
        assert_eq!(
            recv_mld(medium, &tx),
            [(
                OUR_LL,
                IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
                1,
                vec![(MldRecordType::ChangeToInclude, solicited_node)]
            )]
        );

        let new_addr = Ipv6Address::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2);
        stack
            .iface(IFACE)
            .add_ip_addr(IpCidr::new(new_addr.into(), 64))
            .unwrap();
        stack.poll(Instant::ZERO);
        assert_eq!(
            recv_mld(medium, &tx),
            [(
                OUR_LL,
                IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
                1,
                vec![(MldRecordType::ChangeToInclude, new_addr.solicited_node())]
            )]
        );

        stack.iface(IFACE).remove_ip_addr(new_addr);
        assert!(!stack.iface(IFACE).has_multicast_group(new_addr.solicited_node()));
        stack.poll(Instant::ZERO);
        assert_eq!(
            recv_mld(medium, &tx),
            [(
                OUR_LL,
                IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
                1,
                vec![(MldRecordType::ChangeToExclude, new_addr.solicited_node())]
            )]
        );

        // Not on IP interfaces: there is no link to report on.
        let (mut stack, _rx, tx) = test_stack(Medium::Ip);
        stack.poll(Instant::ZERO);
        assert!(recv_mld(Medium::Ip, &tx).is_empty());
    }

    /// Joined groups are accepted by ingress, other multicast destinations are not.
    #[test]
    #[cfg(feature = "udp")]
    fn test_multicast_ingress() {
        let medium = Medium::Ip;
        let (mut stack, rx, _tx) = test_stack(medium);
        let group = Ipv4Address::new(224, 0, 0, 251);
        let handle = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(handle)
            .bind(5353, IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        let datagram = {
            let mut bytes = vec![0; UDP_HEADER_LEN + 2];
            let mut udp = UdpPacket::new_unchecked(&mut bytes[..]);
            udp.set_src_port(5353);
            udp.set_dst_port(5353);
            udp.set_len((UDP_HEADER_LEN + 2) as u16);
            udp.payload_mut().copy_from_slice(b"hi");
            udp.fill_checksum(&REMOTE_V4.into(), &group.into());
            bytes
        };
        let packet = {
            let mut bytes = vec![0; IPV4_HEADER_LEN + datagram.len()];
            {
                let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
                ip.set_version(4);
                ip.set_header_len(IPV4_HEADER_LEN as u8);
                ip.set_total_len((IPV4_HEADER_LEN + datagram.len()) as u16);
                ip.set_next_header(IpProtocol::Udp);
                ip.set_hop_limit(64);
                ip.set_src_addr(REMOTE_V4);
                ip.set_dst_addr(group);
                ip.fill_checksum();
            }
            bytes[IPV4_HEADER_LEN..].copy_from_slice(&datagram);
            bytes
        };

        // Not joined: dropped.
        inject(
            &mut stack,
            &rx,
            medium,
            EthernetProtocol::Ipv4,
            packet.clone(),
            Instant::ZERO,
        );
        assert!(stack.udp_socket(handle).recv().is_err());

        // Joined: delivered.
        stack.iface(IFACE).join_multicast_group(group).unwrap();
        inject(
            &mut stack,
            &rx,
            medium,
            EthernetProtocol::Ipv4,
            packet.clone(),
            Instant::ZERO,
        );
        let recv = stack.udp_socket(handle).recv().unwrap();
        assert_eq!(&*recv, b"hi");
        assert_eq!(recv.meta().endpoint, IpEndpoint::new(REMOTE_V4.into(), 5353));
        drop(recv);

        // Left: dropped again.
        stack.iface(IFACE).leave_multicast_group(group).unwrap();
        inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, packet, Instant::ZERO);
        assert!(stack.udp_socket(handle).recv().is_err());
    }

    /// A device that computes the IPv4 and ICMPv6 checksums itself gets those
    /// fields zeroed. The IGMP checksum is not offloadable, so it is computed
    /// either way.
    #[test]
    fn test_checksum_offload() {
        let medium = Medium::Ip;
        let mut caps = ChecksumCapabilities::default();
        caps.ipv4 = ChecksumOffload::BOTH;
        caps.icmpv6 = ChecksumOffload::BOTH;
        let (mut stack, _rx, tx) = test_stack_with_checksum(medium, caps);
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();

        stack
            .iface(IFACE)
            .join_multicast_group(Ipv4Address::new(224, 0, 0, 22))
            .unwrap();
        stack
            .iface(IFACE)
            .join_multicast_group(Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0, 0x00fb))
            .unwrap();
        stack.poll(Instant::ZERO);

        let packets = recv_all(medium, &tx);
        assert_eq!(packets.len(), 2);

        let mut igmp = packets[0].clone();
        let mut ip = Ipv4Packet::new_checked(&mut igmp[..]).unwrap();
        assert_eq!(ip.checksum(), 0);
        assert!(IgmpPacket::new_checked(ip.payload_mut()).unwrap().verify_checksum());

        let mut mld = packets[1].clone();
        let ip = Ipv6Packet::new_checked(&mut mld[..]).unwrap();
        assert_eq!(ip.next_header(), IpProtocol::HopByHop);
        let icmp = Icmpv6Packet::new_checked(&mut mld[IPV6_HEADER_LEN + MLDV2_ROUTER_ALERT_LEN..]).unwrap();
        assert_eq!(icmp.checksum(), 0);
    }
}
