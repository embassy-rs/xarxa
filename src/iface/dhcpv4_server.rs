//! DHCPv4 server.
//!
//! The server is part of an interface. Turn it on with
//! [`Iface::set_dhcpv4_server`] and it answers DHCP requests arriving on that
//! interface, handing out addresses from a configured pool. Inspect the leases
//! with [`Iface::dhcpv4_server_leases`] and remove one with
//! [`Iface::remove_dhcpv4_server_lease`].
//!
//! The interface must have an IPv4 address: it is the server's own address and
//! its subnet provides the subnet mask sent to clients. The pool must be inside
//! that subnet.
//!
//! Only Ethernet interfaces are supported. Requests relayed by a DHCP relay
//! agent are ignored, and offered addresses are not probed with ICMP before
//! being handed out (a client that detects a conflict declines the address,
//! which takes it out of the pool for a while).
//!
//! [`Iface::set_dhcpv4_server`]: super::Iface::set_dhcpv4_server
//! [`Iface::dhcpv4_server_leases`]: super::Iface::dhcpv4_server_leases
//! [`Iface::remove_dhcpv4_server_lease`]: super::Iface::remove_dhcpv4_server_lease

use byteorder::{ByteOrder, NetworkEndian};
use heapless::Vec;

use super::IfaceState;
use crate::config::{DHCP_MAX_DNS_SERVER_COUNT, DHCP_SERVER_CLIENT_ID_SIZE, DHCP_SERVER_LEASE_COUNT};
use crate::driver::{ChecksumCapabilities, PacketBuf};
use crate::stack::{StackInner, push_ipv4_header};
use crate::time::{Duration, Instant};
use crate::wire::{
    DHCP_CLIENT_PORT, DHCP_HEADER_LEN, DHCP_MAGIC_NUMBER, DHCP_SERVER_PORT, DhcpFlags, DhcpMessageType, DhcpOption,
    DhcpPacket, EthernetAddress, EthernetProtocol, IPV4_HEADER_LEN, IpAddress, IpCidr, IpProtocol, Ipv4Address,
    Ipv4AddressExt, Ipv4Cidr, LINK_HEADER_LEN, UDP_HEADER_LEN, UdpPacket, dhcpv4_field as field,
};

/// How long an offered address is held back for the client it was offered to.
const OFFER_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a declined address is kept out of the pool (RFC 2131 §4.3.3).
const DECLINE_TIMEOUT: Duration = Duration::from_secs(600);

/// The shortest lease granted when a client asks for one (RFC 2132 §9.2).
const MIN_LEASE_DURATION: Duration = Duration::from_secs(60);

/// BOOTP messages are at least this long (RFC 951); replies are padded to it,
/// since some clients drop shorter ones.
const MIN_MESSAGE_SIZE: usize = 300;

/// Configuration of the DHCP server, passed to [`Iface::set_dhcpv4_server`].
///
/// Start from [`DhcpServerConfig::new`] and change the fields you need.
///
/// [`Iface::set_dhcpv4_server`]: super::Iface::set_dhcpv4_server
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DhcpServerConfig {
    /// First address of the pool leases are taken from.
    pub pool_start: Ipv4Address,
    /// Last address of the pool, inclusive.
    pub pool_end: Ipv4Address,
    /// How long a lease lasts. Clients asking for a shorter lease get it.
    pub lease_duration: Duration,
    /// The default gateway sent to clients, if any.
    pub gateway: Option<Ipv4Address>,
    /// The DNS servers sent to clients. Empty sends none.
    pub dns_servers: Vec<Ipv4Address, DHCP_MAX_DNS_SERVER_COUNT>,
    /// Extra options added to every OFFER and ACK.
    pub outgoing_options: &'static [DhcpOption<'static>],
}

impl DhcpServerConfig {
    /// A configuration leasing addresses from `pool_start` to `pool_end`
    /// (inclusive) for one hour, with no gateway and no DNS servers.
    pub fn new(pool_start: Ipv4Address, pool_end: Ipv4Address) -> Self {
        Self {
            pool_start,
            pool_end,
            lease_duration: Duration::from_secs(3600),
            gateway: None,
            dns_servers: Vec::new(),
            outgoing_options: &[],
        }
    }
}

/// The state of one [`DhcpServerLease`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DhcpServerLeaseState {
    /// The address was offered and the client has not requested it yet.
    Offered,
    /// The client holds the address.
    Bound,
    /// The client released the address, or chose another server. Kept as a
    /// record so a returning client gets the same address.
    Released,
    /// The client reported the address as in use by someone else. The address
    /// is kept out of the pool until the hold expires.
    Declined,
}

/// One entry of the DHCP server's lease table.
///
/// Read them with [`Iface::dhcpv4_server_leases`].
///
/// [`Iface::dhcpv4_server_leases`]: super::Iface::dhcpv4_server_leases
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DhcpServerLease {
    address: Ipv4Address,
    hardware_addr: EthernetAddress,
    client_id: [u8; DHCP_SERVER_CLIENT_ID_SIZE],
    client_id_len: u8,
    state: DhcpServerLeaseState,
    expires_at: Instant,
}

impl DhcpServerLease {
    fn new(id: &ClientId<'_>, hardware_addr: EthernetAddress) -> Self {
        let mut lease = Self {
            address: Ipv4Address::UNSPECIFIED,
            hardware_addr,
            client_id: [0; DHCP_SERVER_CLIENT_ID_SIZE],
            client_id_len: 0,
            state: DhcpServerLeaseState::Released,
            expires_at: Instant::from_millis(0),
        };
        if let ClientId::Id(bytes) = id {
            lease.client_id[..bytes.len()].copy_from_slice(bytes);
            lease.client_id_len = bytes.len() as u8;
        }
        lease
    }

    /// The leased address.
    pub fn address(&self) -> Ipv4Address {
        self.address
    }

    /// The client's hardware address, from its latest message.
    pub fn hardware_addr(&self) -> EthernetAddress {
        self.hardware_addr
    }

    /// The client identifier the client sent, or `None` if it sent none and is
    /// identified by its hardware address.
    pub fn client_id(&self) -> Option<&[u8]> {
        match self.client_id_len {
            0 => None,
            len => Some(&self.client_id[..len as usize]),
        }
    }

    /// The state of the lease.
    pub fn state(&self) -> DhcpServerLeaseState {
        self.state
    }

    /// When the lease stops holding its address.
    ///
    /// For an offered lease this is when the unanswered offer lapses, for a
    /// bound one the end of the lease, and for a declined one the end of the
    /// hold that keeps the address out of the pool. A released lease is already
    /// past it. Past this time the entry is only a record: the address is free,
    /// and the entry makes a returning client get it again.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Whether the lease still holds its address.
    fn is_active(&self, now: Instant) -> bool {
        match self.state {
            DhcpServerLeaseState::Released => false,
            DhcpServerLeaseState::Offered | DhcpServerLeaseState::Bound | DhcpServerLeaseState::Declined => {
                self.expires_at > now
            }
        }
    }

    fn matches_client(&self, id: &ClientId<'_>) -> bool {
        match id {
            ClientId::Id(bytes) => self.client_id() == Some(*bytes),
            ClientId::Hw(hw) => self.client_id_len == 0 && self.hardware_addr == *hw,
        }
    }
}

/// What identifies a client: the client identifier option if it sent one, else
/// its hardware address (RFC 2131 §4.2).
enum ClientId<'a> {
    Id(&'a [u8]),
    Hw(EthernetAddress),
}

/// What to answer a DHCPREQUEST with.
enum Answer {
    Ack,
    Nak(&'static str),
    Silent,
}

/// A reply about to be built: the fields that vary between OFFER, ACK and NAK.
struct Reply {
    message_type: DhcpMessageType,
    ciaddr: Ipv4Address,
    yiaddr: Ipv4Address,
    lease_duration: Option<Duration>,
    message: Option<&'static str>,
}

/// The DHCP server state of one interface.
#[derive(Debug)]
pub(crate) struct Server {
    config: DhcpServerConfig,
    leases: Vec<DhcpServerLease, DHCP_SERVER_LEASE_COUNT>,
}

impl Server {
    pub(crate) fn new(config: DhcpServerConfig) -> Self {
        Self {
            config,
            leases: Vec::new(),
        }
    }

    pub(crate) fn leases(&self) -> &[DhcpServerLease] {
        &self.leases
    }

    pub(crate) fn remove_lease(&mut self, address: Ipv4Address) -> bool {
        let len = self.leases.len();
        self.leases.retain(|lease| lease.address != address);
        self.leases.len() != len
    }

    fn in_pool(&self, addr: Ipv4Address) -> bool {
        (self.config.pool_start.to_bits()..=self.config.pool_end.to_bits()).contains(&addr.to_bits())
    }

    /// The lease of this client, if any. Declined entries don't count: they
    /// block an address, they don't belong to anyone.
    fn find_by_client(&self, id: &ClientId<'_>) -> Option<usize> {
        self.leases
            .iter()
            .position(|lease| lease.state != DhcpServerLeaseState::Declined && lease.matches_client(id))
    }

    /// Whether `addr` can be given to the client `id`: no active lease holds it,
    /// other than the client's own.
    fn available_for(&self, addr: Ipv4Address, id: &ClientId<'_>, now: Instant) -> bool {
        !self.leases.iter().any(|lease| {
            lease.address == addr
                && lease.is_active(now)
                && (lease.state == DhcpServerLeaseState::Declined || !lease.matches_client(id))
        })
    }

    /// The lease table slot for this client: its existing lease, a fresh one, or
    /// one reclaimed from the longest-expired record. `None` if every slot holds
    /// an active lease.
    fn entry_for(&mut self, id: &ClientId<'_>, chaddr: EthernetAddress, now: Instant) -> Option<usize> {
        if let Some(i) = self.find_by_client(id) {
            self.leases[i].hardware_addr = chaddr;
            return Some(i);
        }
        match self.leases.push(DhcpServerLease::new(id, chaddr)) {
            Ok(()) => Some(self.leases.len() - 1),
            Err(lease) => {
                let i = self
                    .leases
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| !l.is_active(now))
                    .min_by_key(|(_, l)| l.expires_at)
                    .map(|(i, _)| i)?;
                self.leases[i] = lease;
                Some(i)
            }
        }
    }

    /// Choose an address for a discovering client (RFC 2131 §4.3.1): its current
    /// or previous lease first, then the address it asks for, then the first
    /// free address of the pool.
    fn pick_addr(
        &self,
        id: &ClientId<'_>,
        requested: Option<Ipv4Address>,
        now: Instant,
        server_cidr: &Ipv4Cidr,
    ) -> Option<Ipv4Address> {
        let usable = |addr: Ipv4Address| {
            self.in_pool(addr) && addr_valid(addr, server_cidr) && self.available_for(addr, id, now)
        };

        if let Some(i) = self.find_by_client(id)
            && usable(self.leases[i].address)
        {
            return Some(self.leases[i].address);
        }
        if let Some(addr) = requested
            && usable(addr)
        {
            return Some(addr);
        }
        // Bounded: there are at most DHCP_SERVER_LEASE_COUNT active leases, so a
        // pool inside the subnet yields a free address within that many steps
        // (plus the handful of reserved addresses), or is exhausted.
        for bits in self.config.pool_start.to_bits()..=self.config.pool_end.to_bits() {
            let addr = Ipv4Address::from_bits(bits);
            if addr_valid(addr, server_cidr) && self.available_for(addr, id, now) {
                return Some(addr);
            }
        }
        None
    }

    /// The lease duration to grant, honoring a shorter request (RFC 2131 §4.3.1).
    fn lease_duration(&self, requested: Option<Duration>) -> Duration {
        match requested {
            Some(d) => d.max(MIN_LEASE_DURATION).min(self.config.lease_duration),
            None => self.config.lease_duration,
        }
    }

    /// Handle one client message. Returns the reply to transmit, with its IP and
    /// Ethernet destination, or `None` when the message gets no reply.
    fn handle(
        &mut self,
        now: Instant,
        server_cidr: Ipv4Cidr,
        checksum_caps: &ChecksumCapabilities,
        message_type: DhcpMessageType,
        packet: &DhcpPacket<'_>,
    ) -> Option<(PacketBuf, Ipv4Address, EthernetAddress)> {
        let chaddr = packet.client_hardware_address();
        let id = match packet.option(field::OPT_CLIENT_ID) {
            Some(data) if !data.is_empty() && data.len() <= DHCP_SERVER_CLIENT_ID_SIZE => ClientId::Id(data),
            Some(data) => {
                trace!("DHCP server: client id of {} bytes too long, using chaddr", data.len());
                ClientId::Hw(chaddr)
            }
            None => ClientId::Hw(chaddr),
        };

        match message_type {
            DhcpMessageType::Discover => self.handle_discover(now, server_cidr, checksum_caps, packet, &id, chaddr),
            DhcpMessageType::Request => self.handle_request(now, server_cidr, checksum_caps, packet, &id, chaddr),
            DhcpMessageType::Decline => {
                let Some(addr) = packet.option(field::OPT_REQUESTED_IP).and_then(parse_ipv4) else {
                    return None;
                };
                if let Some(i) = self.find_by_client(&id)
                    && self.leases[i].address == addr
                {
                    // RFC 2131 §4.3.3: the address is in use by someone else.
                    warn!("DHCP server: {} declined {}, possible address conflict", chaddr, addr);
                    self.leases[i].state = DhcpServerLeaseState::Declined;
                    self.leases[i].expires_at = now + DECLINE_TIMEOUT;
                }
                None
            }
            DhcpMessageType::Release => {
                let addr = packet.client_ip();
                if let Some(i) = self.find_by_client(&id)
                    && self.leases[i].address == addr
                    && self.leases[i].is_active(now)
                {
                    debug!("DHCP server: {} released {}", chaddr, addr);
                    self.leases[i].state = DhcpServerLeaseState::Released;
                    self.leases[i].expires_at = now;
                }
                None
            }
            DhcpMessageType::Inform => {
                // RFC 2131 §4.3.5: configuration parameters only, no lease time,
                // no yiaddr, sent to ciaddr.
                let ciaddr = packet.client_ip();
                if ciaddr == Ipv4Address::UNSPECIFIED {
                    return None;
                }
                debug!("DHCP server: answering INFORM from {}", ciaddr);
                self.build_reply(
                    server_cidr,
                    checksum_caps,
                    packet,
                    Reply {
                        message_type: DhcpMessageType::Ack,
                        ciaddr,
                        yiaddr: Ipv4Address::UNSPECIFIED,
                        lease_duration: None,
                        message: None,
                    },
                )
            }
            _ => {
                trace!("DHCP server: ignoring {:?}", message_type);
                None
            }
        }
    }

    fn handle_discover(
        &mut self,
        now: Instant,
        server_cidr: Ipv4Cidr,
        checksum_caps: &ChecksumCapabilities,
        packet: &DhcpPacket<'_>,
        id: &ClientId<'_>,
        chaddr: EthernetAddress,
    ) -> Option<(PacketBuf, Ipv4Address, EthernetAddress)> {
        let requested = packet.option(field::OPT_REQUESTED_IP).and_then(parse_ipv4);
        let requested_lease = packet
            .option(field::OPT_IP_LEASE_TIME)
            .and_then(parse_u32)
            .map(|secs| Duration::from_secs(secs as u64));

        let Some(addr) = self.pick_addr(id, requested, now, &server_cidr) else {
            debug!("DHCP server: no free address for {}", chaddr);
            return None;
        };

        // RFC 2131 §4.3.1: a client with a running lease that asks for no
        // specific one is offered the time it has left.
        let duration = match self.find_by_client(id) {
            Some(i)
                if requested_lease.is_none()
                    && self.leases[i].state == DhcpServerLeaseState::Bound
                    && self.leases[i].address == addr
                    && self.leases[i].expires_at > now =>
            {
                self.leases[i].expires_at - now
            }
            _ => self.lease_duration(requested_lease),
        };

        let Some(i) = self.entry_for(id, chaddr, now) else {
            warn!("DHCP server: lease table full, ignoring DISCOVER from {}", chaddr);
            return None;
        };
        let lease = &mut self.leases[i];
        // Offering a client its own running lease must not shorten it.
        if !(lease.state == DhcpServerLeaseState::Bound && lease.address == addr && lease.expires_at > now) {
            lease.state = DhcpServerLeaseState::Offered;
            lease.address = addr;
            lease.expires_at = now + OFFER_TIMEOUT;
        }

        debug!("DHCP server: offering {} to {}", addr, chaddr);
        self.build_reply(
            server_cidr,
            checksum_caps,
            packet,
            Reply {
                message_type: DhcpMessageType::Offer,
                ciaddr: Ipv4Address::UNSPECIFIED,
                yiaddr: addr,
                lease_duration: Some(duration),
                message: None,
            },
        )
    }

    fn handle_request(
        &mut self,
        now: Instant,
        server_cidr: Ipv4Cidr,
        checksum_caps: &ChecksumCapabilities,
        packet: &DhcpPacket<'_>,
        id: &ClientId<'_>,
        chaddr: EthernetAddress,
    ) -> Option<(PacketBuf, Ipv4Address, EthernetAddress)> {
        let requested = packet.option(field::OPT_REQUESTED_IP).and_then(parse_ipv4);
        let server_id = packet.option(field::OPT_SERVER_IDENTIFIER).and_then(parse_ipv4);
        let ciaddr = packet.client_ip();

        if server_id.is_some_and(|s| s != server_cidr.address()) {
            // The client selected another server (RFC 2131 §3.1 step 4): what it
            // held with us is dead, only the record stays.
            if let Some(i) = self.find_by_client(id) {
                debug!("DHCP server: {} chose another server", chaddr);
                self.leases[i].state = DhcpServerLeaseState::Released;
                self.leases[i].expires_at = now;
            }
            return None;
        }
        let selecting = server_id.is_some();

        // The address the client claims, per its state (RFC 2131 §4.3.2):
        // SELECTING and INIT-REBOOT put it in the requested-ip option,
        // RENEWING and REBINDING in ciaddr.
        let addr = if let Some(addr) = requested {
            addr
        } else if !selecting && ciaddr != Ipv4Address::UNSPECIFIED {
            ciaddr
        } else {
            trace!("DHCP server: malformed REQUEST from {}", chaddr);
            return None;
        };
        let init_reboot = !selecting && requested.is_some();

        let answer = if !server_cidr.contains_addr(&addr) || !addr_valid(addr, &server_cidr) {
            // RFC 2131 §4.3.2: the client is on the wrong network.
            Answer::Nak("requested address not on this network")
        } else {
            match self.find_by_client(id) {
                Some(i) if self.leases[i].address == addr && self.available_for(addr, id, now) => Answer::Ack,
                Some(_) => Answer::Nak("requested address does not match the lease"),
                // RFC 2131 §4.3.2: a server with no record of an INIT-REBOOT
                // client must stay silent, another server may know it.
                None if init_reboot => Answer::Silent,
                // No record but the address is free and ours to give: this is
                // how leases survive a server reboot.
                None if self.in_pool(addr) && self.available_for(addr, id, now) => Answer::Ack,
                // The chosen server must answer one way or the other.
                None if selecting => Answer::Nak("requested address is not available"),
                // A renewal of an address outside the pool is not ours to judge.
                None if !self.in_pool(addr) => Answer::Silent,
                None => Answer::Nak("requested address is in use"),
            }
        };

        match answer {
            Answer::Ack => {
                let duration = self.lease_duration(
                    packet
                        .option(field::OPT_IP_LEASE_TIME)
                        .and_then(parse_u32)
                        .map(|secs| Duration::from_secs(secs as u64)),
                );
                // Drop stale records of previous holders of the address.
                self.leases.retain(|l| l.address != addr || l.matches_client(id));
                let Some(i) = self.entry_for(id, chaddr, now) else {
                    warn!("DHCP server: lease table full, cannot commit {}", addr);
                    return self.nak(server_cidr, checksum_caps, packet, "no free leases");
                };
                let lease = &mut self.leases[i];
                lease.address = addr;
                lease.state = DhcpServerLeaseState::Bound;
                lease.expires_at = now + duration;
                debug!("DHCP server: leased {} to {}", addr, chaddr);
                self.build_reply(
                    server_cidr,
                    checksum_caps,
                    packet,
                    Reply {
                        message_type: DhcpMessageType::Ack,
                        ciaddr,
                        yiaddr: addr,
                        lease_duration: Some(duration),
                        message: None,
                    },
                )
            }
            Answer::Nak(reason) => {
                debug!("DHCP server: NAK to {} for {}: {}", chaddr, addr, reason);
                self.nak(server_cidr, checksum_caps, packet, reason)
            }
            Answer::Silent => None,
        }
    }

    fn nak(
        &self,
        server_cidr: Ipv4Cidr,
        checksum_caps: &ChecksumCapabilities,
        packet: &DhcpPacket<'_>,
        reason: &'static str,
    ) -> Option<(PacketBuf, Ipv4Address, EthernetAddress)> {
        self.build_reply(
            server_cidr,
            checksum_caps,
            packet,
            Reply {
                message_type: DhcpMessageType::Nak,
                ciaddr: Ipv4Address::UNSPECIFIED,
                yiaddr: Ipv4Address::UNSPECIFIED,
                lease_duration: None,
                message: Some(reason),
            },
        )
    }

    /// Build one reply, UDP header included, and pick its destination
    /// (RFC 2131 §4.1). `None` if the pool is empty: the client retransmits.
    ///
    /// Panics if the message doesn't fit in a packet, which only an absurd
    /// `outgoing_options` can cause.
    fn build_reply(
        &self,
        server_cidr: Ipv4Cidr,
        checksum_caps: &ChecksumCapabilities,
        request: &DhcpPacket<'_>,
        reply: Reply,
    ) -> Option<(PacketBuf, Ipv4Address, EthernetAddress)> {
        let chaddr = request.client_hardware_address();
        let flags = request.flags();

        // RFC 2131 §4.1: to the relay if there is one (unsupported here), else
        // to ciaddr, else broadcast if asked to, else straight to the client's
        // hardware address. NAKs always go to broadcast: the client may not
        // have an address it can be reached on.
        let (dst_addr, dst_hw) = if reply.message_type == DhcpMessageType::Nak {
            (Ipv4Address::BROADCAST, EthernetAddress::BROADCAST)
        } else if reply.ciaddr != Ipv4Address::UNSPECIFIED {
            (reply.ciaddr, chaddr)
        } else if flags.contains(DhcpFlags::BROADCAST) {
            (Ipv4Address::BROADCAST, EthernetAddress::BROADCAST)
        } else {
            (reply.yiaddr, chaddr)
        };

        let mut buf = PacketBuf::try_new()?;
        buf.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);
        buf.set_len(buf.tailroom());

        let mut packet = DhcpPacket::new_unchecked(&mut buf[..]);
        packet.fill_client_header(reply.message_type, chaddr);
        packet.set_transaction_id(request.transaction_id());
        packet.set_flags(flags);
        packet.set_client_ip(reply.ciaddr);
        packet.set_your_ip(reply.yiaddr);
        packet.set_server_ip(Ipv4Address::UNSPECIFIED);
        packet.set_relay_agent_ip(Ipv4Address::UNSPECIFIED);

        let mut options = packet.options_mut();
        let result = (|| {
            options.emit(DhcpOption {
                kind: field::OPT_DHCP_MESSAGE_TYPE,
                data: &[reply.message_type.into()],
            })?;
            options.emit(DhcpOption {
                kind: field::OPT_SERVER_IDENTIFIER,
                data: &server_cidr.address().octets(),
            })?;
            if let Some(duration) = reply.lease_duration {
                let secs = duration.secs().min(u32::MAX as u64) as u32;
                options.emit(DhcpOption {
                    kind: field::OPT_IP_LEASE_TIME,
                    data: &secs.to_be_bytes(),
                })?;
            }
            if reply.message_type != DhcpMessageType::Nak {
                // RFC 2132 §3.3: the subnet mask must come before the router.
                options.emit(DhcpOption {
                    kind: field::OPT_SUBNET_MASK,
                    data: &server_cidr.netmask().octets(),
                })?;
                if let Some(gateway) = self.config.gateway {
                    options.emit(DhcpOption {
                        kind: field::OPT_ROUTER,
                        data: &gateway.octets(),
                    })?;
                }
                if !self.config.dns_servers.is_empty() {
                    let mut data = [0; 4 * DHCP_MAX_DNS_SERVER_COUNT];
                    for (i, server) in self.config.dns_servers.iter().enumerate() {
                        data[i * 4..i * 4 + 4].copy_from_slice(&server.octets());
                    }
                    options.emit(DhcpOption {
                        kind: field::OPT_DOMAIN_NAME_SERVER,
                        data: &data[..4 * self.config.dns_servers.len()],
                    })?;
                }
                for option in self.config.outgoing_options {
                    options.emit(*option)?;
                }
            }
            if let Some(message) = reply.message {
                options.emit(DhcpOption {
                    kind: field::OPT_MESSAGE,
                    data: message.as_bytes(),
                })?;
            }
            options.end()
        })();

        unwrap!(result, "DHCP reply does not fit in a packet");
        let mut len = DHCP_HEADER_LEN + options.written();
        if len < MIN_MESSAGE_SIZE {
            buf[len..MIN_MESSAGE_SIZE].fill(0);
            len = MIN_MESSAGE_SIZE;
        }
        buf.set_len(len);

        buf.push_front(UDP_HEADER_LEN);
        let mut udp = UdpPacket::new_unchecked(&mut buf[..]);
        udp.set_src_port(DHCP_SERVER_PORT);
        udp.set_dst_port(DHCP_CLIENT_PORT);
        udp.set_len((UDP_HEADER_LEN + len) as u16);
        if !checksum_caps.udp.tx {
            udp.fill_checksum(&IpAddress::Ipv4(server_cidr.address()), &IpAddress::Ipv4(dst_addr));
        } else {
            // A zero checksum means "no checksum" on UDP-over-IPv4, and is what a
            // device that computes it itself expects to find in the field.
            udp.set_checksum(0);
        }

        Some((buf, dst_addr, dst_hw))
    }
}

/// Whether `addr` can be leased at all: a unicast address of the served subnet
/// that is not the server's own, the network address, or the broadcast address.
fn addr_valid(addr: Ipv4Address, server_cidr: &Ipv4Cidr) -> bool {
    addr.x_is_unicast()
        && server_cidr.contains_addr(&addr)
        && addr != server_cidr.address()
        && addr != server_cidr.network().address()
        && server_cidr.broadcast() != Some(addr)
}

impl IfaceState<'_> {
    /// The subnet the server serves: the interface's first IPv4 address.
    fn dhcpv4_server_cidr(&self) -> Option<Ipv4Cidr> {
        self.cidrs().find_map(|cidr| match cidr {
            IpCidr::Ipv4(cidr) => Some(*cidr),
            #[allow(unreachable_patterns)]
            _ => None,
        })
    }

    /// Process a DHCP packet received on this interface from `src_ip`, and send
    /// the reply, if it gets one. `payload` is the UDP payload; the ports have
    /// already been checked by the caller.
    pub(crate) fn dhcpv4_server_process(&mut self, inner: &mut StackInner, src_ip: Ipv4Address, payload: &mut [u8]) {
        let checksum_caps = self.checksum_caps();
        let server_cidr = self.dhcpv4_server_cidr();
        let Some(server) = &mut self.dhcpv4_server else { return };
        let Some(server_cidr) = server_cidr else {
            trace!("DHCP server: no IPv4 address on the interface, ignoring");
            return;
        };

        let packet = match DhcpPacket::new_checked(payload) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("DHCP server: invalid pkt from {}: {:?}", src_ip, e);
                return;
            }
        };

        if packet.magic_number() != DHCP_MAGIC_NUMBER
            || packet.hardware_type() != crate::wire::ArpHardware::Ethernet
            || packet.hardware_len() != EthernetAddress::SIZE as u8
            || packet.opcode() != crate::wire::DhcpOpCode::Request
        {
            debug!("DHCP server: invalid pkt from {}", src_ip);
            return;
        }
        let Ok(message_type) = packet.message_type() else {
            debug!("DHCP server: pkt from {} has no message type", src_ip);
            return;
        };
        if packet.relay_agent_ip() != Ipv4Address::UNSPECIFIED {
            trace!("DHCP server: relayed requests are not supported");
            return;
        }

        debug!("DHCP server: recv {:?} from {}", message_type, src_ip);
        let reply = server.handle(inner.now, server_cidr, &checksum_caps, message_type, &packet);

        if let Some((mut buf, dst_addr, dst_hw)) = reply {
            push_ipv4_header(
                &mut buf,
                server_cidr.address(),
                dst_addr,
                IpProtocol::Udp,
                64,
                &checksum_caps,
            );
            inner.transmit_ethernet(self, dst_hw, buf, EthernetProtocol::Ipv4);
        }
    }
}

fn parse_ipv4(data: &[u8]) -> Option<Ipv4Address> {
    let octets: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(Ipv4Address::from_octets(octets))
}

fn parse_u32(data: &[u8]) -> Option<u32> {
    (data.len() == 4).then(|| NetworkEndian::read_u32(data))
}

#[cfg(test)]
mod test {
    use std::vec::Vec;

    use super::*;
    use crate::driver::ChecksumOffload;
    use crate::iface::{IfaceHandle, Medium};
    use crate::stack::Stack;
    use crate::test_device::{Queue, Sent, TestDevice};
    use crate::wire::{DhcpOpCode, ETHERNET_HEADER_LEN, EthernetFrame, HardwareAddress, IpProtocol, Ipv4Packet};

    const SERVER_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const CLIENT_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x42]);
    const CLIENT2_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x43]);
    const CLIENT3_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x44]);
    const SERVER_IP: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const DNS_IP: Ipv4Address = Ipv4Address::new(1, 1, 1, 1);
    const POOL_START: Ipv4Address = Ipv4Address::new(192, 168, 1, 10);
    const POOL_END: Ipv4Address = Ipv4Address::new(192, 168, 1, 11);
    const OTHER_SERVER_IP: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);
    const XID: u32 = 0xabcd1234;
    const IFACE: IfaceHandle = IfaceHandle::new(0);
    const LEASE_SECS: u64 = 300;

    fn at(secs: i64) -> Instant {
        Instant::from_secs(secs)
    }

    /// A pool of two addresses, ourselves as gateway, one DNS server.
    fn test_config() -> DhcpServerConfig {
        let mut config = DhcpServerConfig::new(POOL_START, POOL_END);
        config.lease_duration = Duration::from_secs(LEASE_SECS);
        config.gateway = Some(SERVER_IP);
        config.dns_servers.push(DNS_IP).unwrap();
        config
    }

    /// A stack with one Ethernet interface at 192.168.1.1/24, DHCP server on.
    fn test_stack() -> (Stack<'static>, Queue, Sent) {
        test_stack_with_checksum(ChecksumCapabilities::default())
    }

    fn test_stack_with_checksum(checksum: ChecksumCapabilities) -> (Stack<'static>, Queue, Sent) {
        let driver = TestDevice::new(Medium::Ethernet).with_checksum(checksum);
        let (rx, tx) = (driver.rx.clone(), driver.tx.clone());
        let mut stack = Stack::new(1);
        let handle = driver.install(&mut stack, HardwareAddress::Ethernet(SERVER_HW));
        assert_eq!(handle, IFACE);
        stack
            .iface(handle)
            .add_ip_addr(IpCidr::new(SERVER_IP.into(), 24))
            .unwrap();
        // Drain the multicast reports the addresses trigger, so the tests only
        // see the frames DHCP provokes.
        stack.poll(at(0));
        tx.borrow_mut().clear();
        stack.iface(handle).set_dhcpv4_server(Some(test_config()));
        (stack, rx, tx)
    }

    /// A client message under construction.
    struct Msg {
        message_type: DhcpMessageType,
        chaddr: EthernetAddress,
        ciaddr: Ipv4Address,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        flags: DhcpFlags,
        options: Vec<(u8, Vec<u8>)>,
    }

    impl Msg {
        /// A broadcast message from an unconfigured client, the DISCOVER shape.
        fn new(message_type: DhcpMessageType, chaddr: EthernetAddress) -> Self {
            Self {
                message_type,
                chaddr,
                ciaddr: Ipv4Address::UNSPECIFIED,
                src_ip: Ipv4Address::UNSPECIFIED,
                dst_ip: Ipv4Address::BROADCAST,
                flags: DhcpFlags::empty(),
                options: Vec::new(),
            }
        }

        fn opt(mut self, kind: u8, data: &[u8]) -> Self {
            self.options.push((kind, data.to_vec()));
            self
        }

        fn requested_ip(self, addr: Ipv4Address) -> Self {
            self.opt(field::OPT_REQUESTED_IP, &addr.octets())
        }

        fn server_id(self, addr: Ipv4Address) -> Self {
            self.opt(field::OPT_SERVER_IDENTIFIER, &addr.octets())
        }

        /// From a configured client straight to the server, the RENEW shape.
        fn unicast_from(mut self, addr: Ipv4Address) -> Self {
            self.ciaddr = addr;
            self.src_ip = addr;
            self.dst_ip = SERVER_IP;
            self
        }
    }

    /// Build the whole Ethernet frame of a client message.
    fn frame(msg: &Msg) -> Vec<u8> {
        let mut dhcp = vec![0; 400];
        let dhcp_len = {
            let mut packet = DhcpPacket::new_unchecked(&mut dhcp);
            packet.fill_client_header(msg.message_type, msg.chaddr);
            packet.set_transaction_id(XID);
            packet.set_flags(msg.flags);
            packet.set_client_ip(msg.ciaddr);
            packet.set_your_ip(Ipv4Address::UNSPECIFIED);
            packet.set_server_ip(Ipv4Address::UNSPECIFIED);
            packet.set_relay_agent_ip(Ipv4Address::UNSPECIFIED);
            let mut writer = packet.options_mut();
            writer
                .emit(DhcpOption {
                    kind: field::OPT_DHCP_MESSAGE_TYPE,
                    data: &[msg.message_type.into()],
                })
                .unwrap();
            for (kind, data) in &msg.options {
                writer.emit(DhcpOption { kind: *kind, data }).unwrap();
            }
            writer.end().unwrap();
            DHCP_HEADER_LEN + writer.written()
        };
        dhcp.truncate(dhcp_len);

        let dst_hw = if msg.dst_ip == Ipv4Address::BROADCAST {
            EthernetAddress::BROADCAST
        } else {
            SERVER_HW
        };
        let mut frame = vec![0; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + dhcp_len];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame);
            eth.set_dst_addr(dst_hw);
            eth.set_src_addr(msg.chaddr);
            eth.set_ethertype(EthernetProtocol::Ipv4);
        }
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut frame[ETHERNET_HEADER_LEN..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + UDP_HEADER_LEN + dhcp_len) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_hop_limit(64);
            ip.set_src_addr(msg.src_ip);
            ip.set_dst_addr(msg.dst_ip);
            ip.fill_checksum();
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]);
            udp.set_src_port(DHCP_CLIENT_PORT);
            udp.set_dst_port(DHCP_SERVER_PORT);
            udp.set_len((UDP_HEADER_LEN + dhcp_len) as u16);
            udp.payload_mut().copy_from_slice(&dhcp);
            udp.fill_checksum(&IpAddress::Ipv4(msg.src_ip), &IpAddress::Ipv4(msg.dst_ip));
        }
        frame
    }

    /// Feed one client message and run the stack.
    fn send(stack: &mut Stack<'_>, rx: &Queue, msg: Msg, t: i64) {
        rx.borrow_mut().push_back(frame(&msg));
        stack.poll(at(t));
    }

    /// What a transmitted reply is: the addressing and the DHCP payload.
    struct SentDhcp {
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        dst_hw: EthernetAddress,
        dhcp: Vec<u8>,
    }

    fn parse_sent(frame: &[u8]) -> SentDhcp {
        let mut frame = frame.to_vec();
        let eth = EthernetFrame::new_checked(&mut frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(eth.src_addr(), SERVER_HW);
        let dst_hw = eth.dst_addr();
        let ip = Ipv4Packet::new_checked(&mut frame[ETHERNET_HEADER_LEN..]).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let (src_ip, dst_ip) = (ip.src_addr(), ip.dst_addr());
        let udp = UdpPacket::new_checked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]).unwrap();
        assert!(udp.verify_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip)));
        assert_eq!(udp.src_port(), DHCP_SERVER_PORT);
        assert_eq!(udp.dst_port(), DHCP_CLIENT_PORT);
        // Replies are padded to the BOOTP minimum message size.
        assert!(udp.payload().len() >= MIN_MESSAGE_SIZE);
        SentDhcp {
            src_ip,
            dst_ip,
            dst_hw,
            dhcp: udp.payload().to_vec(),
        }
    }

    /// The last transmitted frame, parsed.
    fn last_sent(tx: &Sent) -> SentDhcp {
        parse_sent(tx.borrow().last().unwrap())
    }

    fn message_type(sent: &mut SentDhcp) -> DhcpMessageType {
        DhcpPacket::new_checked(&mut sent.dhcp).unwrap().message_type().unwrap()
    }

    /// The lease table, cloned out of the short-lived interface view.
    fn leases(stack: &mut Stack<'_>) -> Vec<DhcpServerLease> {
        stack.iface(IFACE).dhcpv4_server_leases().to_vec()
    }

    /// Drive a client to a bound lease on `POOL_START`: DISCOVER at `t`, REQUEST
    /// at `t + 1`.
    fn bind_first_client(stack: &mut Stack<'_>, rx: &Queue, t: i64) {
        send(stack, rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), t);
        send(
            stack,
            rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW)
                .server_id(SERVER_IP)
                .requested_ip(POOL_START),
            t + 1,
        );
    }

    #[test]
    fn test_discover_request_ack() {
        let (mut stack, rx, tx) = test_stack();

        // DISCOVER: an OFFER comes back, unicast straight to the client's MAC
        // and offered address (no broadcast flag, no ciaddr).
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
        assert_eq!(tx.borrow().len(), 1);
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Offer);
        assert_eq!(sent.src_ip, SERVER_IP);
        assert_eq!(sent.dst_ip, POOL_START);
        assert_eq!(sent.dst_hw, CLIENT_HW);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.opcode(), DhcpOpCode::Reply);
            assert_eq!(packet.transaction_id(), XID);
            assert_eq!(packet.your_ip(), POOL_START);
            assert_eq!(packet.client_ip(), Ipv4Address::UNSPECIFIED);
            assert_eq!(packet.relay_agent_ip(), Ipv4Address::UNSPECIFIED);
            assert_eq!(packet.client_hardware_address(), CLIENT_HW);
            assert_eq!(
                packet.option(field::OPT_SERVER_IDENTIFIER),
                Some(&SERVER_IP.octets()[..])
            );
            assert_eq!(
                packet.option(field::OPT_IP_LEASE_TIME),
                Some(&(LEASE_SECS as u32).to_be_bytes()[..])
            );
            assert_eq!(packet.option(field::OPT_SUBNET_MASK), Some(&[255, 255, 255, 0][..]));
            assert_eq!(packet.option(field::OPT_ROUTER), Some(&SERVER_IP.octets()[..]));
            assert_eq!(packet.option(field::OPT_DOMAIN_NAME_SERVER), Some(&DNS_IP.octets()[..]));
            // RFC 2132 §3.3: the subnet mask must come before the router.
            let kinds: Vec<u8> = packet.options().map(|o| o.kind).collect();
            assert_eq!(
                kinds,
                &[
                    field::OPT_DHCP_MESSAGE_TYPE,
                    field::OPT_SERVER_IDENTIFIER,
                    field::OPT_IP_LEASE_TIME,
                    field::OPT_SUBNET_MASK,
                    field::OPT_ROUTER,
                    field::OPT_DOMAIN_NAME_SERVER,
                ]
            );
        }
        {
            let leases = leases(&mut stack);
            assert_eq!(leases.len(), 1);
            assert_eq!(leases[0].address(), POOL_START);
            assert_eq!(leases[0].hardware_addr(), CLIENT_HW);
            assert_eq!(leases[0].client_id(), None);
            assert_eq!(leases[0].state(), DhcpServerLeaseState::Offered);
            assert_eq!(leases[0].expires_at(), at(0) + OFFER_TIMEOUT);
        }

        // REQUEST of the offer: an ACK, and the lease is bound.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW)
                .server_id(SERVER_IP)
                .requested_ip(POOL_START),
            1,
        );
        assert_eq!(tx.borrow().len(), 2);
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Ack);
        assert_eq!(sent.dst_ip, POOL_START);
        assert_eq!(sent.dst_hw, CLIENT_HW);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.your_ip(), POOL_START);
            assert_eq!(
                packet.option(field::OPT_IP_LEASE_TIME),
                Some(&(LEASE_SECS as u32).to_be_bytes()[..])
            );
        }
        {
            let leases = leases(&mut stack);
            assert_eq!(leases.len(), 1);
            assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);
            assert_eq!(leases[0].expires_at(), at(1) + Duration::from_secs(LEASE_SECS));
        }
    }

    #[test]
    fn test_broadcast_flag() {
        let (mut stack, rx, tx) = test_stack();
        let mut msg = Msg::new(DhcpMessageType::Discover, CLIENT_HW);
        msg.flags = DhcpFlags::BROADCAST;
        send(&mut stack, &rx, msg, 0);
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Offer);
        assert_eq!(sent.dst_ip, Ipv4Address::BROADCAST);
        assert_eq!(sent.dst_hw, EthernetAddress::BROADCAST);
        // The flags are echoed back (RFC 2131 table 3).
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.flags(), DhcpFlags::BROADCAST);
    }

    #[test]
    fn test_two_clients_get_distinct_addresses() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT2_HW), 2);
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Offer);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_END);
    }

    #[test]
    fn test_requested_ip_honored() {
        let (mut stack, rx, tx) = test_stack();
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT_HW).requested_ip(POOL_END),
            0,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_END);
    }

    #[test]
    fn test_request_for_other_server_releases_the_offer() {
        let (mut stack, rx, tx) = test_stack();
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
        assert_eq!(tx.borrow().len(), 1);

        // The client picks another server: no reply, and the offer is released.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW)
                .server_id(OTHER_SERVER_IP)
                .requested_ip(POOL_START),
            1,
        );
        assert_eq!(tx.borrow().len(), 1);
        assert_eq!(leases(&mut stack)[0].state(), DhcpServerLeaseState::Released);

        // The released address is available to the next client at once.
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT2_HW), 2);
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
    }

    #[test]
    fn test_request_of_taken_address_naks() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        // Another client asks us for the same address: NAK, broadcast, with the
        // server identifier and no lease time or parameters (RFC 2131 table 3).
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT2_HW)
                .server_id(SERVER_IP)
                .requested_ip(POOL_START),
            2,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Nak);
        assert_eq!(sent.dst_ip, Ipv4Address::BROADCAST);
        assert_eq!(sent.dst_hw, EthernetAddress::BROADCAST);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.your_ip(), Ipv4Address::UNSPECIFIED);
        assert_eq!(
            packet.option(field::OPT_SERVER_IDENTIFIER),
            Some(&SERVER_IP.octets()[..])
        );
        assert_eq!(packet.option(field::OPT_IP_LEASE_TIME), None);
        assert_eq!(packet.option(field::OPT_SUBNET_MASK), None);
        assert!(packet.option(field::OPT_MESSAGE).is_some());

        // The holder keeps its lease.
        let leases = leases(&mut stack);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);
    }

    #[test]
    fn test_renew() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        // A renewal: unicast, ciaddr filled, no requested-ip, no server-id.
        // The ACK goes back to ciaddr and the lease is extended.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW).unicast_from(POOL_START),
            100,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Ack);
        assert_eq!(sent.dst_ip, POOL_START);
        assert_eq!(sent.dst_hw, CLIENT_HW);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.client_ip(), POOL_START);
            assert_eq!(packet.your_ip(), POOL_START);
        }
        let leases = leases(&mut stack);
        assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);
        assert_eq!(leases[0].expires_at(), at(100) + Duration::from_secs(LEASE_SECS));
    }

    #[test]
    fn test_renew_after_server_restart() {
        // A server that lost its lease table adopts a renewal of a free pool
        // address, so clients keep their addresses across a reboot.
        let (mut stack, rx, tx) = test_stack();
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW).unicast_from(POOL_START),
            0,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Ack);
        let leases = leases(&mut stack);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].address(), POOL_START);
        assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);

        // A renewal of an address outside the pool is not ours: silence.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT2_HW).unicast_from(Ipv4Address::new(192, 168, 1, 200)),
            1,
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_init_reboot() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        // INIT-REBOOT of the right address: ACK.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW).requested_ip(POOL_START),
            2,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Ack);

        // INIT-REBOOT of the wrong address: NAK.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW).requested_ip(POOL_END),
            3,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Nak);

        // INIT-REBOOT of an address on the wrong network: NAK (RFC 2131 §4.3.2).
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW).requested_ip(Ipv4Address::new(10, 0, 0, 5)),
            4,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Nak);

        // INIT-REBOOT from a client we have no record of: silence, another
        // server may know it (RFC 2131 §4.3.2).
        let before = tx.borrow().len();
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT2_HW).requested_ip(POOL_END),
            5,
        );
        assert_eq!(tx.borrow().len(), before);
    }

    #[test]
    fn test_release() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        let mut msg = Msg::new(DhcpMessageType::Release, CLIENT_HW).server_id(SERVER_IP);
        msg.ciaddr = POOL_START;
        msg.src_ip = POOL_START;
        msg.dst_ip = SERVER_IP;
        send(&mut stack, &rx, msg, 2);
        assert_eq!(tx.borrow().len(), 2); // no reply to RELEASE
        assert_eq!(leases(&mut stack)[0].state(), DhcpServerLeaseState::Released);

        // The address is available again, and the record makes a returning
        // client get it back.
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 3);
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
    }

    #[test]
    fn test_decline() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        // The client reports the address as in use: it is held out of the pool.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Decline, CLIENT_HW)
                .server_id(SERVER_IP)
                .requested_ip(POOL_START),
            2,
        );
        assert_eq!(tx.borrow().len(), 2); // no reply to DECLINE
        {
            let leases = leases(&mut stack);
            assert_eq!(leases[0].state(), DhcpServerLeaseState::Declined);
            assert_eq!(leases[0].expires_at(), at(2) + DECLINE_TIMEOUT);
        }

        // The declining client discovers again and gets a different address.
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 3);
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_END);

        // While the hold lasts, the declined address is not handed out even
        // with the pool otherwise empty.
        let before = tx.borrow().len();
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT2_HW), 4);
        assert_eq!(tx.borrow().len(), before);

        // After it, it is.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT2_HW),
            2 + DECLINE_TIMEOUT.secs() as i64 + 1,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
    }

    #[test]
    fn test_pool_exhaustion_and_expiry() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT2_HW)
                .server_id(SERVER_IP)
                .requested_ip(POOL_END),
            2,
        );
        assert_eq!(tx.borrow().len(), 3);

        // Both addresses taken: a third client gets nothing.
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT3_HW), 3);
        assert_eq!(tx.borrow().len(), 3);

        // Once the leases run out, it gets the first expired one.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT3_HW),
            LEASE_SECS as i64 + 2,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Offer);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
    }

    #[test]
    fn test_expired_client_keeps_its_address() {
        let (mut stack, rx, tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        // Long after the lease expired, the record still hands the returning
        // client the same address.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT_HW),
            LEASE_SECS as i64 + 100,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
    }

    #[test]
    fn test_remove_lease() {
        let (mut stack, rx, _tx) = test_stack();
        bind_first_client(&mut stack, &rx, 0);

        assert!(stack.iface(IFACE).remove_dhcpv4_server_lease(POOL_START));
        assert!(stack.iface(IFACE).dhcpv4_server_leases().is_empty());
        assert!(!stack.iface(IFACE).remove_dhcpv4_server_lease(POOL_START));

        // The address is free for someone else now.
        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT2_HW), 2);
        let leases = leases(&mut stack);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].address(), POOL_START);
        assert_eq!(leases[0].hardware_addr(), CLIENT2_HW);
    }

    #[test]
    fn test_inform() {
        let (mut stack, rx, tx) = test_stack();

        // A statically-configured host asks for the other parameters: an ACK
        // with them, no lease time, no yiaddr, and no lease recorded.
        let client_ip = Ipv4Address::new(192, 168, 1, 77);
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Inform, CLIENT_HW).unicast_from(client_ip),
            0,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Ack);
        assert_eq!(sent.dst_ip, client_ip);
        assert_eq!(sent.dst_hw, CLIENT_HW);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.your_ip(), Ipv4Address::UNSPECIFIED);
        assert_eq!(packet.client_ip(), client_ip);
        assert_eq!(packet.option(field::OPT_IP_LEASE_TIME), None);
        assert_eq!(packet.option(field::OPT_SUBNET_MASK), Some(&[255, 255, 255, 0][..]));
        assert_eq!(packet.option(field::OPT_ROUTER), Some(&SERVER_IP.octets()[..]));
        assert!(stack.iface(IFACE).dhcpv4_server_leases().is_empty());
    }

    #[test]
    fn test_client_id_keying() {
        let (mut stack, rx, tx) = test_stack();
        let id = [1, 0x02, 0, 0, 0, 0, 0x42];

        // Bind with a client identifier.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT_HW).opt(field::OPT_CLIENT_ID, &id),
            0,
        );
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Request, CLIENT_HW)
                .opt(field::OPT_CLIENT_ID, &id)
                .server_id(SERVER_IP)
                .requested_ip(POOL_START),
            1,
        );
        {
            let leases = leases(&mut stack);
            assert_eq!(leases[0].client_id(), Some(&id[..]));
            assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);
        }

        // The same identifier from another hardware address is the same client
        // (RFC 2131 §4.2) and keeps its address.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT2_HW).opt(field::OPT_CLIENT_ID, &id),
            2,
        );
        let mut sent = last_sent(&tx);
        assert_eq!(sent.dst_hw, CLIENT2_HW);
        assert_eq!(DhcpPacket::new_checked(&mut sent.dhcp).unwrap().your_ip(), POOL_START);
        {
            let leases = leases(&mut stack);
            assert_eq!(leases.len(), 1);
            assert_eq!(leases[0].hardware_addr(), CLIENT2_HW);
        }

        // An identifier too long to store falls back to hardware address keying.
        let long_id = [0xab; DHCP_SERVER_CLIENT_ID_SIZE + 1];
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT3_HW).opt(field::OPT_CLIENT_ID, &long_id),
            3,
        );
        let leases = leases(&mut stack);
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[1].hardware_addr(), CLIENT3_HW);
        assert_eq!(leases[1].client_id(), None);
    }

    #[test]
    fn test_requested_lease_duration() {
        let (mut stack, rx, tx) = test_stack();

        // A shorter lease than the configured one is granted.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT_HW).opt(field::OPT_IP_LEASE_TIME, &100u32.to_be_bytes()),
            0,
        );
        let mut sent = last_sent(&tx);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.option(field::OPT_IP_LEASE_TIME), Some(&100u32.to_be_bytes()[..]));

        // A longer one is capped at the configured duration.
        send(
            &mut stack,
            &rx,
            Msg::new(DhcpMessageType::Discover, CLIENT_HW).opt(field::OPT_IP_LEASE_TIME, &100000u32.to_be_bytes()),
            1,
        );
        let mut sent = last_sent(&tx);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(
            packet.option(field::OPT_IP_LEASE_TIME),
            Some(&(LEASE_SECS as u32).to_be_bytes()[..])
        );
    }

    #[test]
    fn test_extra_options() {
        let (mut stack, rx, tx) = test_stack();
        let mut config = test_config();
        config.outgoing_options = &[DhcpOption {
            kind: field::OPT_NTP_SERVERS,
            data: &[192, 168, 1, 2],
        }];
        stack.iface(IFACE).set_dhcpv4_server(Some(config));

        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
        let mut sent = last_sent(&tx);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.option(field::OPT_NTP_SERVERS), Some(&[192, 168, 1, 2][..]));
    }

    #[test]
    fn test_relayed_request_ignored() {
        let (mut stack, rx, tx) = test_stack();
        let mut msg = frame(&Msg::new(DhcpMessageType::Discover, CLIENT_HW));
        // Patch giaddr in: a relayed request is ignored.
        {
            let ip_and_udp = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
            let mut packet = DhcpPacket::new_unchecked(&mut msg[ip_and_udp..]);
            packet.set_relay_agent_ip(Ipv4Address::new(10, 0, 0, 1));
        }
        rx.borrow_mut().push_back(msg);
        stack.poll(at(0));
        assert_eq!(tx.borrow().len(), 0);
    }

    #[test]
    fn test_no_ipv4_address_is_silent() {
        let driver = TestDevice::new(Medium::Ethernet);
        let (rx, tx) = (driver.rx.clone(), driver.tx.clone());
        let mut stack = Stack::new(1);
        let handle = driver.install(&mut stack, HardwareAddress::Ethernet(SERVER_HW));
        stack.iface(handle).set_dhcpv4_server(Some(test_config()));
        stack.poll(at(0));
        tx.borrow_mut().clear();

        rx.borrow_mut()
            .push_back(frame(&Msg::new(DhcpMessageType::Discover, CLIENT_HW)));
        stack.poll(at(1));
        assert_eq!(tx.borrow().len(), 0);
    }

    /// A device that computes the IPv4 and UDP checksums itself gets both fields
    /// zeroed in the replies.
    #[test]
    fn test_checksum_offload() {
        let mut caps = ChecksumCapabilities::default();
        caps.ipv4 = ChecksumOffload::BOTH;
        caps.udp = ChecksumOffload::BOTH;
        let (mut stack, rx, tx) = test_stack_with_checksum(caps);

        send(&mut stack, &rx, Msg::new(DhcpMessageType::Discover, CLIENT_HW), 0);
        let mut frame = tx.borrow()[0].clone();
        let ip = Ipv4Packet::new_checked(&mut frame[ETHERNET_HEADER_LEN..]).unwrap();
        assert_eq!(ip.checksum(), 0);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]).unwrap();
        assert_eq!(udp.src_port(), DHCP_SERVER_PORT);
        assert_eq!(udp.checksum(), 0);
    }

    /// The stack's own DHCP client acquires a lease from the stack's own DHCP
    /// server, two stacks wired back to back.
    #[test]
    #[cfg(feature = "dhcpv4")]
    fn test_client_against_server() {
        use crate::iface::dhcpv4::DhcpConfig;

        let server_device = TestDevice::new(Medium::Ethernet);
        let mut server_stack = Stack::new(1);
        let server_iface = server_device.install(&mut server_stack, HardwareAddress::Ethernet(SERVER_HW));
        server_stack
            .iface(server_iface)
            .add_ip_addr(IpCidr::new(SERVER_IP.into(), 24))
            .unwrap();
        server_stack.iface(server_iface).set_dhcpv4_server(Some(test_config()));

        let client_device = TestDevice::new(Medium::Ethernet);
        let mut client_stack = Stack::new(2);
        let client_iface = client_device.install(&mut client_stack, HardwareAddress::Ethernet(CLIENT_HW));
        client_stack.iface(client_iface).set_dhcpv4(Some(DhcpConfig::default()));

        for t in 0..10 {
            client_stack.poll(at(t));
            for frame in client_device.tx.borrow_mut().drain(..) {
                server_device.rx.borrow_mut().push_back(frame);
            }
            server_stack.poll(at(t));
            for frame in server_device.tx.borrow_mut().drain(..) {
                client_device.rx.borrow_mut().push_back(frame);
            }
        }

        let lease = client_stack.iface(client_iface).dhcpv4_lease().cloned().unwrap();
        assert_eq!(lease.address, Ipv4Cidr::new(POOL_START, 24));
        assert_eq!(lease.router, Some(SERVER_IP));
        assert_eq!(&lease.dns_servers[..], &[DNS_IP]);
        assert_eq!(lease.server.address, SERVER_IP);
        assert_eq!(lease.server.identifier, SERVER_IP);

        let leases = server_stack.iface(server_iface).dhcpv4_server_leases().to_vec();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].address(), POOL_START);
        assert_eq!(leases[0].hardware_addr(), CLIENT_HW);
        assert_eq!(leases[0].state(), DhcpServerLeaseState::Bound);
        // The client sent a client identifier built from its hardware address.
        assert_eq!(leases[0].client_id(), Some(&[1, 0x02, 0, 0, 0, 0, 0x42][..]));
    }
}
