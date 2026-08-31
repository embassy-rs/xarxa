//! DHCPv4 client.
//!
//! The client is part of an interface. Turn it on with [`Iface::set_dhcpv4`] and it
//! runs from [`Stack::poll`]: it finds a server, gets a lease, and renews it. The
//! leased address and default route are installed on the interface by the stack
//! itself. Read the lease with [`Iface::dhcpv4_lease`], and watch
//! [`Iface::config_generation`] to notice changes.
//!
//! Only Ethernet interfaces are supported.
//!
//! [`Iface::set_dhcpv4`]: super::Iface::set_dhcpv4
//! [`Iface::dhcpv4_lease`]: super::Iface::dhcpv4_lease
//! [`Iface::config_generation`]: super::Iface::config_generation
//! [`Stack::poll`]: crate::Stack::poll

use byteorder::{ByteOrder, NetworkEndian};
use heapless::Vec;

use super::{AddrOrigin, IfaceAddr, IfaceState};
use crate::config::DHCP_MAX_DNS_SERVER_COUNT;
#[cfg(feature = "dhcpv4-options")]
use crate::config::DHCP_OPTIONS_BUF_SIZE;
use crate::driver::ChecksumCapabilities;
use crate::driver::PacketBuf;
use crate::route::{Route, RouteOrigin};
use crate::stack::StackInner;
use crate::time::{Duration, Instant};
use crate::wire::{
    DHCP_CLIENT_PORT, DHCP_HEADER_LEN, DHCP_MAGIC_NUMBER, DHCP_SERVER_PORT, DhcpFlags, DhcpMessageType, DhcpOption,
    DhcpPacket, EthernetAddress, IPV4_HEADER_LEN, IpAddress, IpCidr, Ipv4Address, Ipv4AddressExt, Ipv4Cidr,
    LINK_HEADER_LEN, UDP_HEADER_LEN, UdpPacket, dhcpv4_field as field,
};

const DEFAULT_LEASE_DURATION: Duration = Duration::from_secs(120);

/// How long to wait for an offer before sending another DISCOVER.
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for an ACK before sending another REQUEST. Doubles every 2 tries.
const INITIAL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How many REQUESTs to send before going back to discovery.
const REQUEST_RETRIES: u16 = 5;
/// The shortest time to wait between renew or rebind attempts.
const MIN_RENEW_TIMEOUT: Duration = Duration::from_secs(60);

const DEFAULT_PARAMETER_REQUEST_LIST: &[u8] =
    &[field::OPT_SUBNET_MASK, field::OPT_ROUTER, field::OPT_DOMAIN_NAME_SERVER];

/// A lease obtained from a DHCP server.
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DhcpLease {
    /// How to reach the server that gave the lease.
    pub server: DhcpServerInfo,
    /// The leased address and its subnet.
    pub address: Ipv4Cidr,
    /// The default gateway, if the server gave one.
    pub router: Option<Ipv4Address>,
    /// The DNS servers, if the server gave any.
    pub dns_servers: Vec<Ipv4Address, DHCP_MAX_DNS_SERVER_COUNT>,
    /// All options received from the DHCP server.
    ///
    /// You may have to ask the server to send the option you're interested in with [`DhcpConfig::parameter_request_list`].
    #[cfg(feature = "dhcpv4-options")]
    pub options: DhcpLeaseOptions,
}

/// How to reach a DHCP server.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DhcpServerInfo {
    /// The address to send packets to.
    pub address: Ipv4Address,
    /// The server identifier to put in packets. Usually the same as `address`,
    /// but can differ, for example behind a DHCP relay.
    pub identifier: Ipv4Address,
}

/// The received options of a lease. See [`DhcpLease::options`].
///
/// Options that don't fit in the buffer are dropped. The buffer size is
/// [`DHCP_OPTIONS_BUF_SIZE`].
#[cfg(feature = "dhcpv4-options")]
#[derive(Clone)]
pub struct DhcpLeaseOptions {
    // Options stored back to back, each as kind, length, data.
    buf: [u8; DHCP_OPTIONS_BUF_SIZE],
    len: u16,
}

#[cfg(feature = "dhcpv4-options")]
impl DhcpLeaseOptions {
    fn new() -> Self {
        Self {
            buf: [0; DHCP_OPTIONS_BUF_SIZE],
            len: 0,
        }
    }

    // Add one option. Errors if it doesn't fit.
    fn push(&mut self, option: DhcpOption<'_>) -> Result<(), ()> {
        let len = self.len as usize;
        let total = 2 + option.data.len();
        if option.data.len() > u8::MAX as usize || self.buf.len() - len < total {
            return Err(());
        }
        self.buf[len] = option.kind;
        self.buf[len + 1] = option.data.len() as u8;
        self.buf[len + 2..len + total].copy_from_slice(option.data);
        self.len = (len + total) as u16;
        Ok(())
    }

    /// The data of the first option of the given kind, if present.
    pub fn get(&self, kind: u8) -> Option<&[u8]> {
        self.iter().find(|opt| opt.kind == kind).map(|opt| opt.data)
    }

    /// Iterate over all options.
    pub fn iter(&self) -> impl Iterator<Item = DhcpOption<'_>> + '_ {
        let mut buf = &self.buf[..self.len as usize];
        core::iter::from_fn(move || {
            if buf.is_empty() {
                return None;
            }
            let len = buf[1] as usize;
            let opt = DhcpOption {
                kind: buf[0],
                data: &buf[2..2 + len],
            };
            buf = &buf[2 + len..];
            Some(opt)
        })
    }
}

#[cfg(feature = "dhcpv4-options")]
impl PartialEq for DhcpLeaseOptions {
    fn eq(&self, other: &Self) -> bool {
        self.buf[..self.len as usize] == other.buf[..other.len as usize]
    }
}

#[cfg(feature = "dhcpv4-options")]
impl Eq for DhcpLeaseOptions {}

#[cfg(feature = "dhcpv4-options")]
impl core::fmt::Debug for DhcpLeaseOptions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

#[cfg(all(feature = "dhcpv4-options", feature = "defmt"))]
impl defmt::Format for DhcpLeaseOptions {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "[");
        let mut first = true;
        for opt in self.iter() {
            if !first {
                defmt::write!(f, ", ");
            }
            first = false;
            defmt::write!(f, "{}", opt);
        }
        defmt::write!(f, "]");
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct DiscoverState {
    /// When to send next request
    retry_at: Instant,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RequestState {
    /// When to send next request
    retry_at: Instant,
    /// How many retries have been done
    retry: u16,
    /// Server we're trying to request from
    server: DhcpServerInfo,
    /// IP address that we're trying to request.
    requested_ip: Ipv4Address,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct RenewState {
    /// Active lease.
    lease: DhcpLease,

    /// Renew timer. When reached, we will start attempting
    /// to renew this lease with the DHCP server.
    ///
    /// Must be less or equal than `rebind_at`.
    renew_at: Instant,

    /// Rebind timer. When reached, we will start broadcasting to renew
    /// this lease with any DHCP server.
    ///
    /// Must be greater than or equal to `renew_at`, and less than or
    /// equal to `expires_at`.
    rebind_at: Instant,

    /// Whether the T2 time has elapsed
    rebinding: bool,

    /// Expiration timer. When reached, this lease is no longer valid, so it must be
    /// thrown away and the interface deconfigured.
    expires_at: Instant,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum ClientState {
    /// Discovering the DHCP server
    Discovering(DiscoverState),
    /// Requesting an address
    Requesting(RequestState),
    /// Having an address, refresh it periodically.
    Renewing(RenewState),
}

/// Configuration of the DHCP client, passed to [`Iface::set_dhcpv4`].
///
/// Start from [`DhcpConfig::default`] and change the fields you need.
///
/// [`Iface::set_dhcpv4`]: super::Iface::set_dhcpv4
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub struct DhcpConfig {
    /// Extra options added to every outgoing packet.
    pub outgoing_options: &'static [DhcpOption<'static>],
    /// The parameter request list option sent to the server.
    ///
    /// `None` asks for the subnet mask, router and DNS servers. Changing this does
    /// not change which options the client itself reads from the lease.
    pub parameter_request_list: Option<&'static [u8]>,
    /// A cap on the lease duration the server gives.
    ///
    /// Useful to react faster to IP configuration changes, and to test renewals.
    pub max_lease_duration: Option<Duration>,
    /// Ignore NAKs from the server.
    ///
    /// This is not RFC compliant. It is a workaround for servers that send spurious
    /// NAKs, for example when several servers share a network.
    pub ignore_naks: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            outgoing_options: &[],
            parameter_request_list: None,
            max_lease_duration: None,
            ignore_naks: false,
        }
    }
}

/// The DHCP client state of one interface.
#[derive(Debug)]
pub(crate) struct Client {
    /// State of the DHCP client.
    state: ClientState,
    /// xid of the last sent message.
    transaction_id: u32,
    pub(crate) config: DhcpConfig,
}

impl Client {
    pub(crate) fn new(config: DhcpConfig) -> Self {
        Client {
            state: ClientState::Discovering(DiscoverState {
                retry_at: Instant::from_millis(0),
            }),
            transaction_id: 1,
            config,
        }
    }

    /// The current lease, if any.
    pub(crate) fn lease(&self) -> Option<&DhcpLease> {
        match &self.state {
            ClientState::Renewing(state) => Some(&state.lease),
            _ => None,
        }
    }

    /// When the client next wants to run.
    pub(crate) fn poll_at(&self) -> Instant {
        match &self.state {
            ClientState::Discovering(state) => state.retry_at,
            ClientState::Requesting(state) => state.retry_at,
            ClientState::Renewing(state) => if state.rebinding {
                state.rebind_at
            } else {
                state.renew_at.min(state.rebind_at)
            }
            .min(state.expires_at),
        }
    }

    fn parse_ack(
        now: Instant,
        packet: &DhcpPacket<'_>,
        max_lease_duration: Option<Duration>,
        server: DhcpServerInfo,
    ) -> Option<(DhcpLease, Instant, Instant, Instant)> {
        let subnet_mask = match packet.option(field::OPT_SUBNET_MASK).and_then(parse_ipv4) {
            Some(subnet_mask) => subnet_mask,
            None => {
                debug!("DHCP ignoring ACK because missing subnet_mask");
                return None;
            }
        };

        let prefix_len = match subnet_mask.prefix_len() {
            Some(prefix_len) => prefix_len,
            None => {
                debug!("DHCP ignoring ACK because subnet_mask is not a valid mask");
                return None;
            }
        };

        if !packet.your_ip().x_is_unicast() {
            debug!("DHCP ignoring ACK because your_ip is not unicast");
            return None;
        }

        let mut lease_duration = packet
            .option(field::OPT_IP_LEASE_TIME)
            .and_then(parse_u32)
            .map(|d| Duration::from_secs(d as _))
            .unwrap_or(DEFAULT_LEASE_DURATION);
        if let Some(max_lease_duration) = max_lease_duration {
            lease_duration = lease_duration.min(max_lease_duration);
        }

        // Cleanup the DNS servers list, keeping only unicasts/
        // TP-Link TD-W8970 sends 0.0.0.0 as second DNS server if there's only one configured :(
        let mut dns_servers = Vec::new();
        if let Some(data) = packet.option(field::OPT_DOMAIN_NAME_SERVER) {
            data.chunks_exact(4)
                .filter_map(parse_ipv4)
                .filter(|s| s.x_is_unicast())
                .take(DHCP_MAX_DNS_SERVER_COUNT)
                .for_each(|a| {
                    // Cannot fail: `take` bounds the count by the vector's capacity.
                    dns_servers.push(a).ok();
                });
        }

        #[cfg(feature = "dhcpv4-options")]
        let options = {
            let mut options = DhcpLeaseOptions::new();
            for opt in packet.options() {
                if options.push(opt).is_err() {
                    debug!("DHCP lease options buffer full, dropping option {}", opt.kind);
                }
            }
            options
        };

        let lease = DhcpLease {
            server,
            address: Ipv4Cidr::new(packet.your_ip(), prefix_len),
            router: packet.option(field::OPT_ROUTER).and_then(parse_ipv4),
            dns_servers,
            #[cfg(feature = "dhcpv4-options")]
            options,
        };

        // Set renew and rebind times as per RFC 2131:
        // Times T1 and T2 are configurable by the server through
        // options. T1 defaults to (0.5 * duration_of_lease). T2
        // defaults to (0.875 * duration_of_lease).
        // When receiving T1 and T2, they must be in the order:
        // T1 < T2 < lease_duration
        let (renew_duration, rebind_duration) = match (
            packet
                .option(field::OPT_RENEWAL_TIME_VALUE)
                .and_then(parse_u32)
                .map(|d| Duration::from_secs(d as u64)),
            packet
                .option(field::OPT_REBINDING_TIME_VALUE)
                .and_then(parse_u32)
                .map(|d| Duration::from_secs(d as u64)),
        ) {
            (Some(renew_duration), Some(rebind_duration))
                if renew_duration < rebind_duration && rebind_duration < lease_duration =>
            {
                (renew_duration, rebind_duration)
            }
            // RFC 2131 does not say what to do if only one value is
            // provided, so:

            // If only T1 is provided, set T2 to be 0.75 through the gap
            // between T1 and the duration of the lease. If T1 is set to
            // the default (0.5 * duration_of_lease), then T2 will also
            // be set to the default (0.875 * duration_of_lease).
            (Some(renew_duration), None) if renew_duration < lease_duration => (
                renew_duration,
                renew_duration + (lease_duration - renew_duration) * 3 / 4,
            ),

            // If only T2 is provided, then T1 will be set to be
            // whichever is smaller of the default (0.5 *
            // duration_of_lease) or T2.
            (None, Some(rebind_duration)) if rebind_duration < lease_duration => {
                ((lease_duration / 2).min(rebind_duration), rebind_duration)
            }

            // Use the defaults if the following order is not met:
            // T1 < T2 < lease_duration
            (_, _) => {
                debug!("using default T1 and T2 values since the provided values are invalid");
                (lease_duration / 2, lease_duration * 7 / 8)
            }
        };
        let renew_at = now + renew_duration;
        let rebind_at = now + rebind_duration;
        let expires_at = now + lease_duration;

        Some((lease, renew_at, rebind_at, expires_at))
    }

    #[cfg(not(test))]
    fn random_transaction_id(inner: &mut StackInner) -> u32 {
        inner.rand.rand_u32()
    }

    #[cfg(test)]
    fn random_transaction_id(_inner: &mut StackInner) -> u32 {
        0x12345678
    }

    /// Build one client message, UDP header included, ready for
    /// `transmit_ipv4_on`. `None` if the pool is empty: the retry timer sends
    /// the next one.
    ///
    /// Panics if the message doesn't fit in a packet. The options the client
    /// emits are tiny, so only an absurd `outgoing_options` can cause that.
    #[allow(clippy::too_many_arguments)]
    fn build(
        config: &DhcpConfig,
        #[cfg(feature = "hostname")] hostname: Option<&str>,
        message_type: DhcpMessageType,
        transaction_id: u32,
        ethernet_addr: EthernetAddress,
        client_ip: Ipv4Address,
        requested_ip: Option<Ipv4Address>,
        server_identifier: Option<Ipv4Address>,
        ip_mtu: usize,
        src_addr: Ipv4Address,
        dst_addr: Ipv4Address,
        checksum_caps: &ChecksumCapabilities,
    ) -> Option<PacketBuf> {
        // Worst case biggest IPv4 header length.
        // 0x0f * 4 = 60 bytes.
        const MAX_IPV4_HEADER_LEN: usize = 60;
        let max_size = (ip_mtu - MAX_IPV4_HEADER_LEN - UDP_HEADER_LEN) as u16;

        let mut buf = PacketBuf::try_new()?;
        buf.reserve(LINK_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);
        let max_payload = buf.tailroom().min(ip_mtu - IPV4_HEADER_LEN - UDP_HEADER_LEN);
        buf.set_len(max_payload);

        let mut packet = DhcpPacket::new_unchecked(&mut buf[..]);
        packet.fill_client_header(message_type, ethernet_addr);
        packet.set_transaction_id(transaction_id);
        packet.set_flags(DhcpFlags::empty());
        packet.set_client_ip(client_ip);
        packet.set_your_ip(Ipv4Address::UNSPECIFIED);
        packet.set_server_ip(Ipv4Address::UNSPECIFIED);
        packet.set_relay_agent_ip(Ipv4Address::UNSPECIFIED);

        let mut options = packet.options_mut();
        let client_id = {
            let mut id = [0u8; 7];
            id[0] = 1; // hardware type: Ethernet
            id[1..].copy_from_slice(ethernet_addr.as_bytes());
            id
        };
        let result = (|| {
            options.emit(DhcpOption {
                kind: field::OPT_DHCP_MESSAGE_TYPE,
                data: &[message_type.into()],
            })?;
            options.emit(DhcpOption {
                kind: field::OPT_CLIENT_ID,
                data: &client_id,
            })?;
            #[cfg(feature = "hostname")]
            if let Some(hostname) = hostname {
                options.emit(DhcpOption::hostname(hostname.as_bytes()))?;
            }
            if let Some(requested_ip) = requested_ip {
                options.emit(DhcpOption {
                    kind: field::OPT_REQUESTED_IP,
                    data: &requested_ip.octets(),
                })?;
            }
            if let Some(server_identifier) = server_identifier {
                options.emit(DhcpOption {
                    kind: field::OPT_SERVER_IDENTIFIER,
                    data: &server_identifier.octets(),
                })?;
            }
            options.emit(DhcpOption {
                kind: field::OPT_MAX_DHCP_MESSAGE_SIZE,
                data: &max_size.to_be_bytes(),
            })?;
            options.emit(DhcpOption {
                kind: field::OPT_PARAMETER_REQUEST_LIST,
                data: config.parameter_request_list.unwrap_or(DEFAULT_PARAMETER_REQUEST_LIST),
            })?;
            for option in config.outgoing_options {
                options.emit(*option)?;
            }
            options.end()
        })();

        unwrap!(result, "DHCP message does not fit in a packet");
        let len = DHCP_HEADER_LEN + options.written();
        buf.set_len(len);

        buf.push_front(UDP_HEADER_LEN);
        let mut udp = UdpPacket::new_unchecked(&mut buf[..]);
        udp.set_src_port(DHCP_CLIENT_PORT);
        udp.set_dst_port(DHCP_SERVER_PORT);
        udp.set_len((UDP_HEADER_LEN + len) as u16);
        if !checksum_caps.udp.tx {
            udp.fill_checksum(&IpAddress::Ipv4(src_addr), &IpAddress::Ipv4(dst_addr));
        } else {
            // A zero checksum means "no checksum" on UDP-over-IPv4, and is what a
            // device that computes it itself expects to find in the field.
            udp.set_checksum(0);
        }

        Some(buf)
    }
}

impl IfaceState<'_> {
    /// Process a DHCP packet received on this interface from `src_ip`. `payload` is
    /// the UDP payload, the ports have already been checked by the caller.
    pub(crate) fn dhcpv4_process(&mut self, inner: &mut StackInner, src_ip: Ipv4Address, payload: &mut [u8]) {
        let ethernet_addr = self.hardware_addr;
        let Some(client) = &mut self.dhcpv4 else { return };
        let ethernet_addr = ethernet_addr.ethernet_or_panic();

        let packet = match DhcpPacket::new_checked(payload) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("DHCP invalid pkt from {}: {:?}", src_ip, e);
                return;
            }
        };

        if packet.magic_number() != DHCP_MAGIC_NUMBER
            || packet.hardware_type() != crate::wire::ArpHardware::Ethernet
            || packet.hardware_len() != EthernetAddress::SIZE as u8
            || packet.opcode() != crate::wire::DhcpOpCode::Reply
        {
            debug!("DHCP invalid pkt from {}", src_ip);
            return;
        }

        let message_type = match packet.message_type() {
            Ok(message_type) => message_type,
            Err(_) => {
                debug!("DHCP pkt from {} has no message type", src_ip);
                return;
            }
        };

        if packet.client_hardware_address() != ethernet_addr {
            return;
        }
        if packet.transaction_id() != client.transaction_id {
            return;
        }
        let server_identifier = match packet.option(field::OPT_SERVER_IDENTIFIER).and_then(parse_ipv4) {
            Some(server_identifier) => server_identifier,
            None => {
                debug!("DHCP ignoring {:?} because missing server_identifier", message_type);
                return;
            }
        };

        debug!("DHCP recv {:?} from {}", message_type, src_ip);

        let now = inner.now;
        let max_lease_duration = client.config.max_lease_duration;
        let ignore_naks = client.config.ignore_naks;
        match (&mut client.state, message_type) {
            (ClientState::Discovering(_), DhcpMessageType::Offer) => {
                if !packet.your_ip().x_is_unicast() {
                    debug!("DHCP ignoring OFFER because your_ip is not unicast");
                    return;
                }

                client.state = ClientState::Requesting(RequestState {
                    retry_at: now,
                    retry: 0,
                    server: DhcpServerInfo {
                        address: src_ip,
                        identifier: server_identifier,
                    },
                    requested_ip: packet.your_ip(), // use the offered ip
                });
            }
            (ClientState::Requesting(state), DhcpMessageType::Ack) => {
                let Some((lease, renew_at, rebind_at, expires_at)) =
                    Client::parse_ack(now, &packet, max_lease_duration, state.server)
                else {
                    return;
                };
                client.state = ClientState::Renewing(RenewState {
                    lease: lease.clone(),
                    renew_at,
                    rebind_at,
                    expires_at,
                    rebinding: false,
                });
                self.dhcpv4_apply(inner, Some(&lease), None);
            }
            (ClientState::Renewing(state), DhcpMessageType::Ack) => {
                let Some((lease, renew_at, rebind_at, expires_at)) =
                    Client::parse_ack(now, &packet, max_lease_duration, state.lease.server)
                else {
                    return;
                };
                state.renew_at = renew_at;
                state.rebind_at = rebind_at;
                state.rebinding = false;
                state.expires_at = expires_at;
                if state.lease != lease {
                    let old = core::mem::replace(&mut state.lease, lease.clone());
                    self.dhcpv4_apply(inner, Some(&lease), Some(&old));
                }
            }
            (ClientState::Requesting(_) | ClientState::Renewing(_), DhcpMessageType::Nak) => {
                if !ignore_naks {
                    self.dhcpv4_reset(inner);
                }
            }
            _ => {
                debug!("DHCP ignoring {:?}: unexpected in current state", message_type);
            }
        }
    }

    /// Run the client's timers: send whatever is due, expire the lease when its
    /// time comes.
    pub(crate) fn dhcpv4_dispatch(&mut self, inner: &mut StackInner) {
        let ethernet_addr = self.hardware_addr;
        let ip_mtu = self.ip_mtu();
        let checksum_caps = self.checksum_caps();
        let Some(client) = &mut self.dhcpv4 else { return };
        let ethernet_addr = ethernet_addr.ethernet_or_panic();
        let now = inner.now;

        match &mut client.state {
            ClientState::Discovering(state) => {
                if now < state.retry_at {
                    return;
                }

                debug!("DHCP send DISCOVER to {}", Ipv4Address::BROADCAST);
                client.transaction_id = Client::random_transaction_id(inner);
                state.retry_at = now + DISCOVER_TIMEOUT;
                let buf = Client::build(
                    &client.config,
                    #[cfg(feature = "hostname")]
                    inner.hostname(),
                    DhcpMessageType::Discover,
                    client.transaction_id,
                    ethernet_addr,
                    Ipv4Address::UNSPECIFIED,
                    None,
                    None,
                    ip_mtu,
                    Ipv4Address::UNSPECIFIED,
                    Ipv4Address::BROADCAST,
                    &checksum_caps,
                );
                if let Some(buf) = buf {
                    inner.transmit_ipv4_on(self, Ipv4Address::UNSPECIFIED, Ipv4Address::BROADCAST, buf);
                }
            }
            ClientState::Requesting(state) => {
                if now < state.retry_at {
                    return;
                }

                if state.retry >= REQUEST_RETRIES {
                    debug!("DHCP request retries exceeded, restarting discovery");
                    self.dhcpv4_reset(inner);
                    return;
                }

                debug!("DHCP send request to {}", Ipv4Address::BROADCAST);
                // Exponential backoff: Double every 2 retries.
                state.retry_at = now + INITIAL_REQUEST_TIMEOUT * (1u32 << (state.retry as u32 / 2));
                state.retry += 1;
                let buf = Client::build(
                    &client.config,
                    #[cfg(feature = "hostname")]
                    inner.hostname(),
                    DhcpMessageType::Request,
                    client.transaction_id,
                    ethernet_addr,
                    Ipv4Address::UNSPECIFIED,
                    Some(state.requested_ip),
                    Some(state.server.identifier),
                    ip_mtu,
                    Ipv4Address::UNSPECIFIED,
                    Ipv4Address::BROADCAST,
                    &checksum_caps,
                );
                if let Some(buf) = buf {
                    inner.transmit_ipv4_on(self, Ipv4Address::UNSPECIFIED, Ipv4Address::BROADCAST, buf);
                }
            }
            ClientState::Renewing(state) => {
                if state.expires_at <= now {
                    debug!("DHCP lease expired");
                    self.dhcpv4_reset(inner);
                    return;
                }

                if now < state.renew_at || state.rebinding && now < state.rebind_at {
                    return;
                }

                state.rebinding |= now >= state.rebind_at;

                let src_addr = state.lease.address.address();
                // Renewing is unicast to the original server, rebinding is broadcast
                let dst_addr = if state.rebinding {
                    Ipv4Address::BROADCAST
                } else {
                    state.lease.server.address
                };

                // In both RENEWING and REBINDING states, if the client receives no
                // response to its DHCPREQUEST message, the client SHOULD wait one-half
                // of the remaining time until T2 (in RENEWING state) and one-half of
                // the remaining lease time (in REBINDING state), down to a minimum of
                // 60 seconds, before retransmitting the DHCPREQUEST message.
                if state.rebinding {
                    state.rebind_at = now + MIN_RENEW_TIMEOUT.max((state.expires_at - now) / 2);
                } else {
                    state.renew_at = now
                        + MIN_RENEW_TIMEOUT
                            .max((state.rebind_at - now) / 2)
                            .min(state.rebind_at - now);
                }

                debug!("DHCP send renew to {}", dst_addr);
                client.transaction_id = Client::random_transaction_id(inner);
                let buf = Client::build(
                    &client.config,
                    #[cfg(feature = "hostname")]
                    inner.hostname(),
                    DhcpMessageType::Request,
                    client.transaction_id,
                    ethernet_addr,
                    src_addr,
                    None,
                    None,
                    ip_mtu,
                    src_addr,
                    dst_addr,
                    &checksum_caps,
                );
                if let Some(buf) = buf {
                    inner.transmit_ipv4_on(self, src_addr, dst_addr, buf);
                }
            }
        }
    }

    /// Drop the lease, if any, and restart discovery. Does nothing if the client
    /// is off.
    pub(crate) fn dhcpv4_reset(&mut self, inner: &mut StackInner) {
        let Some(client) = &mut self.dhcpv4 else { return };
        trace!("DHCP reset");
        let old = core::mem::replace(
            &mut client.state,
            ClientState::Discovering(DiscoverState {
                retry_at: Instant::from_millis(0),
            }),
        );
        if let ClientState::Renewing(state) = old {
            self.dhcpv4_apply(inner, None, Some(&state.lease));
        }
    }

    /// Install `new` on the interface in place of `old`: the address, and a default
    /// route via the router.
    ///
    /// Addresses and routes that are not part of the old lease are left alone.
    fn dhcpv4_apply(&mut self, inner: &mut StackInner, new: Option<&DhcpLease>, old: Option<&DhcpLease>) {
        let old_addr = old.map(|l| IpCidr::Ipv4(l.address));
        let new_addr = new.map(|l| IpCidr::Ipv4(l.address));
        if old_addr != new_addr {
            self.ip_addrs.retain(|a| a.origin != AddrOrigin::Dhcpv4);
            if let Some(cidr) = new_addr {
                let addr = IfaceAddr {
                    cidr,
                    origin: AddrOrigin::Dhcpv4,
                    preferred_until: None,
                };
                if self.ip_addrs.push(addr).is_err() {
                    warn!("dhcp: address table full, {} not assigned", cidr);
                }
            }
            inner.purge_iface_link_state(self.handle);
        }

        let old_router = old.and_then(|l| l.router);
        let new_router = new.and_then(|l| l.router);
        if old_router != new_router {
            let handle = self.handle;
            inner
                .routes
                .retain(|route| !(route.origin == RouteOrigin::Dhcpv4 && route.iface == handle));
            if let Some(new_router) = new_router {
                let route = Route {
                    origin: RouteOrigin::Dhcpv4,
                    ..Route::new_ipv4_gateway(new_router, handle)
                };
                if inner.routes.add(route).is_err() {
                    warn!("dhcp: route table full, default route not installed");
                }
            }
        }

        self.config_changed();
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
    use crate::driver::LinkState;
    use crate::iface::{IfaceHandle, Medium};
    use crate::stack::Stack;
    use crate::test_device::{Link, Queue, Sent, TestDevice};
    use crate::wire::{
        ArpPacket, DhcpOpCode, ETHERNET_HEADER_LEN, EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress,
        IpProtocol, Ipv4Packet,
    };

    const OUR_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    const SERVER_HW: EthernetAddress = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    const SERVER_IP: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const OFFERED_IP: Ipv4Address = Ipv4Address::new(192, 168, 1, 50);
    const DNS_IP: Ipv4Address = Ipv4Address::new(1, 1, 1, 1);
    const XID: u32 = 0x12345678;
    const IFACE: IfaceHandle = IfaceHandle::new(0);

    /// A stack with one Ethernet interface, no addresses, DHCP on.
    fn test_stack() -> (Stack<'static>, Queue, Sent) {
        let (stack, rx, tx, _link) = test_stack_with_checksum(ChecksumCapabilities::default());
        (stack, rx, tx)
    }

    /// [`test_stack`], also handing out control of the link state the device reports.
    fn test_stack_with_link() -> (Stack<'static>, Queue, Sent, Link) {
        test_stack_with_checksum(ChecksumCapabilities::default())
    }

    /// [`test_stack`], with a device that claims to handle the given checksums itself.
    fn test_stack_with_checksum(checksum: ChecksumCapabilities) -> (Stack<'static>, Queue, Sent, Link) {
        let driver = TestDevice::new(Medium::Ethernet).with_checksum(checksum);
        let (rx, tx, link) = (driver.rx.clone(), driver.tx.clone(), driver.link.clone());
        let mut stack = Stack::new(1);
        let handle = driver.install(&mut stack, HardwareAddress::Ethernet(OUR_HW));
        assert_eq!(handle, IFACE);
        // Drain the solicited-node multicast report the link-local address triggers,
        // so the tests only see the frames DHCP provokes.
        stack.poll(at(0));
        tx.borrow_mut().clear();
        stack.iface(handle).set_dhcpv4(Some(DhcpConfig::default()));
        (stack, rx, tx, link)
    }

    fn at(secs: i64) -> Instant {
        Instant::from_secs(secs)
    }

    /// A server reply as a whole Ethernet frame, unicast to our MAC and to `dst_ip`.
    fn reply(message_type: DhcpMessageType, xid: u32, dst_ip: Ipv4Address, options: &[DhcpOption<'_>]) -> Vec<u8> {
        let mut dhcp = vec![0; 576];
        let dhcp_len = {
            let mut packet = DhcpPacket::new_unchecked(&mut dhcp);
            packet.fill_client_header(message_type, OUR_HW);
            packet.set_opcode(DhcpOpCode::Reply);
            packet.set_transaction_id(xid);
            packet.set_flags(DhcpFlags::empty());
            packet.set_client_ip(Ipv4Address::UNSPECIFIED);
            packet.set_your_ip(if message_type == DhcpMessageType::Nak {
                Ipv4Address::UNSPECIFIED
            } else {
                OFFERED_IP
            });
            packet.set_server_ip(SERVER_IP);
            packet.set_relay_agent_ip(Ipv4Address::UNSPECIFIED);
            let mut writer = packet.options_mut();
            writer
                .emit(DhcpOption {
                    kind: field::OPT_DHCP_MESSAGE_TYPE,
                    data: &[message_type.into()],
                })
                .unwrap();
            writer
                .emit(DhcpOption {
                    kind: field::OPT_SERVER_IDENTIFIER,
                    data: &SERVER_IP.octets(),
                })
                .unwrap();
            for option in options {
                writer.emit(*option).unwrap();
            }
            writer.end().unwrap();
            DHCP_HEADER_LEN + writer.written()
        };
        dhcp.truncate(dhcp_len);

        let mut frame = vec![0; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + dhcp_len];
        {
            let mut eth = EthernetFrame::new_unchecked(&mut frame);
            eth.set_dst_addr(OUR_HW);
            eth.set_src_addr(SERVER_HW);
            eth.set_ethertype(EthernetProtocol::Ipv4);
        }
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut frame[ETHERNET_HEADER_LEN..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + UDP_HEADER_LEN + dhcp_len) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_hop_limit(64);
            ip.set_src_addr(SERVER_IP);
            ip.set_dst_addr(dst_ip);
            ip.fill_checksum();
        }
        {
            let mut udp = UdpPacket::new_unchecked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]);
            udp.set_src_port(DHCP_SERVER_PORT);
            udp.set_dst_port(DHCP_CLIENT_PORT);
            udp.set_len((UDP_HEADER_LEN + dhcp_len) as u16);
            udp.payload_mut().copy_from_slice(&dhcp);
            udp.fill_checksum(&IpAddress::Ipv4(SERVER_IP), &IpAddress::Ipv4(dst_ip));
        }
        frame
    }

    fn ack_options() -> Vec<DhcpOption<'static>> {
        vec![
            DhcpOption {
                kind: field::OPT_SUBNET_MASK,
                data: &[255, 255, 255, 0],
            },
            DhcpOption {
                kind: field::OPT_ROUTER,
                data: &[192, 168, 1, 1],
            },
            // A bogus 0.0.0.0 DNS server is dropped.
            DhcpOption {
                kind: field::OPT_DOMAIN_NAME_SERVER,
                data: &[1, 1, 1, 1, 0, 0, 0, 0],
            },
            DhcpOption {
                kind: field::OPT_IP_LEASE_TIME,
                data: &[0, 0, 0x02, 0x58], // 600 s
            },
        ]
    }

    /// What a transmitted frame is: the IP addresses, the UDP ports, and the DHCP payload.
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
        assert_eq!(eth.src_addr(), OUR_HW);
        let dst_hw = eth.dst_addr();
        let ip = Ipv4Packet::new_checked(&mut frame[ETHERNET_HEADER_LEN..]).unwrap();
        assert!(ip.verify_checksum());
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let (src_ip, dst_ip) = (ip.src_addr(), ip.dst_addr());
        let udp = UdpPacket::new_checked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]).unwrap();
        assert!(udp.verify_checksum(&IpAddress::Ipv4(src_ip), &IpAddress::Ipv4(dst_ip)));
        assert_eq!(udp.src_port(), DHCP_CLIENT_PORT);
        assert_eq!(udp.dst_port(), DHCP_SERVER_PORT);
        SentDhcp {
            src_ip,
            dst_ip,
            dst_hw,
            dhcp: udp.payload().to_vec(),
        }
    }

    fn message_type(sent: &mut SentDhcp) -> DhcpMessageType {
        DhcpPacket::new_checked(&mut sent.dhcp).unwrap().message_type().unwrap()
    }

    /// Drive the client to BOUND: DISCOVER, OFFER, REQUEST, ACK. Returns the stack
    /// with the lease applied at `at(2)`.
    fn bound_stack() -> (Stack<'static>, Queue, Sent) {
        let (stack, rx, tx, _link) = bound_stack_with(DhcpConfig::default());
        (stack, rx, tx)
    }

    /// [`bound_stack`], also handing out control of the link state the device reports.
    fn bound_stack_with_link() -> (Stack<'static>, Queue, Sent, Link) {
        bound_stack_with(DhcpConfig::default())
    }

    fn bound_stack_with(config: DhcpConfig) -> (Stack<'static>, Queue, Sent, Link) {
        let (mut stack, rx, tx, link) = test_stack_with_link();
        stack.iface(IFACE).set_dhcpv4(Some(config));

        // First poll: DISCOVER, from 0.0.0.0 to broadcast.
        let deadline = stack.poll(at(0));
        assert_eq!(deadline, at(10));
        assert_eq!(tx.borrow().len(), 1);
        let mut sent = parse_sent(&tx.borrow()[0]);
        assert_eq!(sent.src_ip, Ipv4Address::UNSPECIFIED);
        assert_eq!(sent.dst_ip, Ipv4Address::BROADCAST);
        assert_eq!(sent.dst_hw, EthernetAddress::BROADCAST);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.transaction_id(), XID);
            assert_eq!(packet.client_hardware_address(), OUR_HW);
            assert_eq!(
                packet.option(field::OPT_CLIENT_ID),
                Some(&[1, 0x02, 0, 0, 0, 0, 0x01][..])
            );
            assert_eq!(packet.option(field::OPT_PARAMETER_REQUEST_LIST), Some(&[1, 3, 6][..]));
        }

        // OFFER, unicast to the offered address (which isn't ours yet): REQUEST.
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Offer, XID, OFFERED_IP, &ack_options()));
        stack.poll(at(1));
        assert_eq!(tx.borrow().len(), 2);
        let mut sent = parse_sent(&tx.borrow()[1]);
        assert_eq!(sent.src_ip, Ipv4Address::UNSPECIFIED);
        assert_eq!(sent.dst_ip, Ipv4Address::BROADCAST);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Request);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.transaction_id(), XID);
            assert_eq!(packet.option(field::OPT_REQUESTED_IP), Some(&OFFERED_IP.octets()[..]));
            assert_eq!(
                packet.option(field::OPT_SERVER_IDENTIFIER),
                Some(&SERVER_IP.octets()[..])
            );
        }
        assert!(stack.iface(IFACE).dhcpv4_lease().is_none());
        let generation = stack.iface(IFACE).config_generation();

        // ACK: bound, address and route installed.
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Ack, XID, OFFERED_IP, &ack_options()));
        stack.poll(at(2));
        assert_eq!(tx.borrow().len(), 2);
        let lease = stack.iface(IFACE).dhcpv4_lease().cloned().unwrap();
        assert_eq!(lease.address, Ipv4Cidr::new(OFFERED_IP, 24));
        assert_eq!(lease.router, Some(SERVER_IP));
        assert_eq!(&lease.dns_servers[..], &[DNS_IP]);
        assert_eq!(lease.server.address, SERVER_IP);
        assert_eq!(lease.server.identifier, SERVER_IP);
        assert_eq!(
            ipv4_addrs(&mut stack),
            &[IfaceAddr {
                cidr: IpCidr::new(OFFERED_IP.into(), 24),
                origin: AddrOrigin::Dhcpv4,
                preferred_until: None
            }]
        );
        let route = stack.routes().get_default_ipv4_route().unwrap();
        assert_eq!(route.via_router, IpAddress::Ipv4(SERVER_IP));
        assert_eq!(route.iface, IFACE);
        assert_eq!(route.origin, RouteOrigin::Dhcpv4);
        assert_ne!(stack.iface(IFACE).config_generation(), generation);

        (stack, rx, tx, link)
    }

    /// The interface's IPv4 addresses, leaving out the automatic IPv6 link-local.
    fn ipv4_addrs(stack: &mut Stack) -> Vec<IfaceAddr> {
        stack
            .iface(IFACE)
            .ip_addrs()
            .iter()
            .filter(|a| matches!(a.cidr, IpCidr::Ipv4(_)))
            .copied()
            .collect()
    }

    /// An ARP request from the server for our leased address, which teaches the
    /// stack the server's MAC.
    fn arp_request_from_server() -> Vec<u8> {
        let mut request = vec![0; ETHERNET_HEADER_LEN + crate::wire::ARP_BUFFER_LEN];
        let mut eth = EthernetFrame::new_unchecked(&mut request[..]);
        eth.set_dst_addr(EthernetAddress::BROADCAST);
        eth.set_src_addr(SERVER_HW);
        eth.set_ethertype(EthernetProtocol::Arp);
        let mut arp = ArpPacket::new_unchecked(&mut request[ETHERNET_HEADER_LEN..]);
        arp.set_hardware_type(crate::wire::ArpHardware::Ethernet);
        arp.set_protocol_type(EthernetProtocol::Ipv4);
        arp.set_hardware_len(6);
        arp.set_protocol_len(4);
        arp.set_operation(crate::wire::ArpOperation::Request);
        arp.set_source_hardware_addr(SERVER_HW.as_bytes());
        arp.set_source_protocol_addr(&SERVER_IP.octets());
        arp.set_target_hardware_addr(&[0; 6]);
        arp.set_target_protocol_addr(&OFFERED_IP.octets());
        request
    }

    #[test]
    fn test_acquire_and_release() {
        let (mut stack, _rx, _tx) = bound_stack();

        // Turning the client off removes what it installed.
        let generation = stack.iface(IFACE).config_generation();
        stack.iface(IFACE).set_dhcpv4(None);
        assert!(stack.iface(IFACE).dhcpv4_lease().is_none());
        assert!(ipv4_addrs(&mut stack).is_empty());
        assert!(stack.routes().get_default_ipv4_route().is_none());
        assert_ne!(stack.iface(IFACE).config_generation(), generation);
    }

    #[test]
    #[cfg(feature = "hostname")]
    fn test_hostname_option() {
        let (mut stack, _rx, tx) = test_stack();

        // No hostname set: no host name option in the DISCOVER.
        stack.poll(at(0));
        assert_eq!(tx.borrow().len(), 1);
        let mut sent = parse_sent(&tx.borrow()[0]);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.option(field::OPT_HOST_NAME), None);
        }

        // Hostname set: the retried DISCOVER carries it.
        stack.set_hostname("xarxa-device");
        assert_eq!(stack.hostname(), Some("xarxa-device"));
        stack.poll(at(10));
        assert_eq!(tx.borrow().len(), 2);
        let mut sent = parse_sent(&tx.borrow()[1]);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.option(field::OPT_HOST_NAME), Some(&b"xarxa-device"[..]));
        }
    }

    #[test]
    fn test_manual_config_left_alone() {
        let (mut stack, _rx, _tx) = bound_stack();
        let manual = IpCidr::new(Ipv4Address::new(10, 0, 0, 1).into(), 8);
        stack.iface(IFACE).add_ip_addr(manual).unwrap();

        stack.iface(IFACE).set_dhcpv4(None);
        assert_eq!(ipv4_addrs(&mut stack), &[IfaceAddr::manual(manual)]);
    }

    #[test]
    fn test_renew() {
        // Cap the lease at 60 s so T1 comes at 30 s, while the server's neighbor
        // cache entry (60 s) is still fresh.
        let mut config = DhcpConfig::default();
        config.max_lease_duration = Some(Duration::from_secs(60));
        let (mut stack, rx, tx, _link) = bound_stack_with(config);

        // Learn the server's MAC, so the renewal isn't parked on ARP.
        rx.borrow_mut().push_back(arp_request_from_server());
        stack.poll(at(3));
        assert_eq!(tx.borrow().len(), 3); // the ARP reply

        // Nothing happens before T1.
        assert_eq!(stack.poll(at(31)), at(32));
        assert_eq!(tx.borrow().len(), 3);

        // At T1 a REQUEST is unicast to the server, from the leased address, with
        // the leased address in ciaddr and no requested-ip or server-id options.
        stack.poll(at(32));
        assert_eq!(tx.borrow().len(), 4);
        let mut sent = parse_sent(&tx.borrow()[3]);
        assert_eq!(sent.src_ip, OFFERED_IP);
        assert_eq!(sent.dst_ip, SERVER_IP);
        assert_eq!(sent.dst_hw, SERVER_HW);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Request);
        {
            let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
            assert_eq!(packet.client_ip(), OFFERED_IP);
            assert_eq!(packet.option(field::OPT_REQUESTED_IP), None);
            assert_eq!(packet.option(field::OPT_SERVER_IDENTIFIER), None);
        }

        // The server extends the lease: nothing changes on the interface, and
        // the next renewal is half the new lease away.
        let generation = stack.iface(IFACE).config_generation();
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Ack, XID, OFFERED_IP, &ack_options()));
        stack.poll(at(33));
        assert_eq!(stack.iface(IFACE).config_generation(), generation);
        assert!(stack.iface(IFACE).dhcpv4_lease().is_some());
        assert_eq!(stack.poll(at(34)), at(63));
    }

    #[test]
    fn test_rebind_broadcasts() {
        let (mut stack, _rx, tx) = bound_stack();

        // Past T2 (7/8 of the 600 s lease) with no answer from the server, the
        // REQUEST is broadcast instead.
        let mut t = 302;
        while t < 530 {
            stack.poll(at(t));
            t += 1;
        }
        let sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(sent.src_ip, OFFERED_IP);
        assert_eq!(sent.dst_ip, Ipv4Address::BROADCAST);
        assert!(stack.iface(IFACE).dhcpv4_lease().is_some());
    }

    #[test]
    fn test_expire() {
        let (mut stack, _rx, tx) = bound_stack();

        // Unanswered renewals and rebinds until the lease expires: the address and
        // route go away, and discovery starts over with a fresh DISCOVER.
        let mut t = 302;
        while t < 700 {
            stack.poll(at(t));
            t += 1;
        }
        assert!(stack.iface(IFACE).dhcpv4_lease().is_none());
        assert!(ipv4_addrs(&mut stack).is_empty());
        assert!(stack.routes().get_default_ipv4_route().is_none());
        let mut sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
        assert_eq!(sent.src_ip, Ipv4Address::UNSPECIFIED);
    }

    #[test]
    fn test_nak_restarts_discovery() {
        let (mut stack, rx, tx) = test_stack();
        stack.poll(at(0));
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Offer, XID, OFFERED_IP, &ack_options()));
        stack.poll(at(1));
        assert_eq!(tx.borrow().len(), 2); // DISCOVER, REQUEST

        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Nak, XID, OFFERED_IP, &[]));
        stack.poll(at(2));
        assert!(stack.iface(IFACE).dhcpv4_lease().is_none());
        // Back in discovery: a DISCOVER goes out right away.
        assert_eq!(tx.borrow().len(), 3);
        let mut sent = parse_sent(&tx.borrow()[2]);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
    }

    #[test]
    fn test_wrong_xid_ignored() {
        let (mut stack, rx, tx) = test_stack();
        stack.poll(at(0));
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Offer, XID + 1, OFFERED_IP, &ack_options()));
        stack.poll(at(1));
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_discover_retransmit() {
        let (mut stack, _rx, tx) = test_stack();
        stack.poll(at(0));
        stack.poll(at(9));
        assert_eq!(tx.borrow().len(), 1);
        stack.poll(at(10));
        assert_eq!(tx.borrow().len(), 2);
        let mut sent = parse_sent(&tx.borrow()[1]);
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
    }

    #[test]
    fn test_restart() {
        let (mut stack, _rx, tx) = bound_stack();
        stack.iface(IFACE).restart_dhcpv4();
        assert!(stack.iface(IFACE).dhcpv4_lease().is_none());
        assert!(ipv4_addrs(&mut stack).is_empty());
        stack.poll(at(3));
        let mut sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
    }

    /// The same restart runs by itself when the link comes back, so a client that may
    /// have moved networks does not keep using a lease from the old one.
    #[test]
    fn test_restart_on_link_up() {
        let (mut stack, _rx, tx, link) = bound_stack_with_link();
        assert!(stack.iface(IFACE).dhcpv4_lease().is_some());

        link.set(LinkState::Down);
        stack.poll(at(3));
        link.set(LinkState::Up);
        stack.poll(at(4));

        assert!(
            stack.iface(IFACE).dhcpv4_lease().is_none(),
            "a lease must not survive the link going away"
        );
        let mut sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
    }

    /// Every link-up sends a DISCOVER right away, even mid-backoff: a DISCOVER
    /// spent on a down link never reached the wire, and waiting out its timeout
    /// delays the lease by up to `DISCOVER_TIMEOUT` after the link comes up.
    #[test]
    fn test_link_up_discovers_at_once() {
        let (mut stack, _rx, tx, link) = bound_stack_with_link();

        link.set(LinkState::Down);
        stack.poll(at(3));
        link.set(LinkState::Up);
        stack.poll(at(4));
        let after_first = tx.borrow().len();
        let mut sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);

        link.set(LinkState::Down);
        stack.poll(at(5));
        link.set(LinkState::Up);
        stack.poll(at(6));
        assert_eq!(
            tx.borrow().len(),
            after_first + 1,
            "each link-up sends a fresh DISCOVER"
        );
        let mut sent = parse_sent(tx.borrow().last().unwrap());
        assert_eq!(message_type(&mut sent), DhcpMessageType::Discover);
    }

    #[test]
    fn test_extra_options() {
        let (mut stack, _rx, tx) = test_stack();
        let mut config = DhcpConfig::default();
        config.outgoing_options = &[DhcpOption {
            kind: field::OPT_HOST_NAME,
            data: b"xarxa",
        }];
        config.parameter_request_list = Some(&[1, 3, 6, 42]);
        stack.iface(IFACE).set_dhcpv4(Some(config));
        stack.poll(at(0));
        let mut sent = parse_sent(&tx.borrow()[0]);
        let packet = DhcpPacket::new_checked(&mut sent.dhcp).unwrap();
        assert_eq!(packet.option(field::OPT_HOST_NAME), Some(&b"xarxa"[..]));
        assert_eq!(
            packet.option(field::OPT_PARAMETER_REQUEST_LIST),
            Some(&[1, 3, 6, 42][..])
        );
    }

    #[test]
    #[cfg(feature = "dhcpv4-options")]
    fn test_lease_options() {
        let (mut stack, rx, _tx) = test_stack();
        stack.poll(at(0)); // DISCOVER

        let mut options = ack_options();
        options.push(DhcpOption {
            kind: field::OPT_NTP_SERVERS,
            data: &[192, 168, 1, 2],
        });
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Offer, XID, OFFERED_IP, &options));
        stack.poll(at(1)); // REQUEST
        rx.borrow_mut()
            .push_back(reply(DhcpMessageType::Ack, XID, OFFERED_IP, &options));
        stack.poll(at(2));

        let lease = stack.iface(IFACE).dhcpv4_lease().cloned().unwrap();
        assert_eq!(lease.options.get(field::OPT_NTP_SERVERS), Some(&[192, 168, 1, 2][..]));
        assert_eq!(lease.options.get(field::OPT_SUBNET_MASK), Some(&[255, 255, 255, 0][..]));
        assert_eq!(lease.options.get(field::OPT_HOST_NAME), None);

        // Every option from the ACK is there, in order, the ones the client
        // parses itself included.
        let kinds: Vec<u8> = lease.options.iter().map(|o| o.kind).collect();
        assert_eq!(
            kinds,
            &[
                field::OPT_DHCP_MESSAGE_TYPE,
                field::OPT_SERVER_IDENTIFIER,
                field::OPT_SUBNET_MASK,
                field::OPT_ROUTER,
                field::OPT_DOMAIN_NAME_SERVER,
                field::OPT_IP_LEASE_TIME,
                field::OPT_NTP_SERVERS,
            ]
        );
    }

    #[test]
    #[cfg(feature = "dhcpv4-options")]
    fn test_lease_options_full() {
        let mut options = DhcpLeaseOptions::new();
        // Never fits: the buffer can't hold its own size plus two.
        let data = [0xaa; DHCP_OPTIONS_BUF_SIZE];
        assert!(options.push(DhcpOption { kind: 42, data: &data }).is_err());
        // A dropped option doesn't stop later ones.
        assert!(options.push(DhcpOption { kind: 1, data: &[7] }).is_ok());
        assert_eq!(options.get(1), Some(&[7][..]));
        assert_eq!(options.get(42), None);
    }

    /// A device that computes the IPv4 and UDP checksums itself gets both fields
    /// zeroed in the messages the client sends.
    #[test]
    fn test_checksum_offload() {
        let mut caps = ChecksumCapabilities::default();
        caps.ipv4 = ChecksumOffload::BOTH;
        caps.udp = ChecksumOffload::BOTH;
        let (mut stack, _rx, tx, _link) = test_stack_with_checksum(caps);
        stack.poll(at(0));

        let mut frame = tx.borrow()[0].clone();
        let ip = Ipv4Packet::new_checked(&mut frame[ETHERNET_HEADER_LEN..]).unwrap();
        assert_eq!(ip.checksum(), 0);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let udp = UdpPacket::new_checked(&mut frame[ETHERNET_HEADER_LEN + IPV4_HEADER_LEN..]).unwrap();
        assert_eq!(udp.dst_port(), DHCP_SERVER_PORT);
        assert_eq!(udp.checksum(), 0);
    }
}
