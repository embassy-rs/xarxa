/*! Low-level packet access and construction.

The `wire` module deals with the packet *representation*. It provides functions to extract
fields from sequences of octets, and to insert fields into sequences of octets. This
happens through the `Packet` family of structures, e.g. [EthernetFrame] or [Ipv4Packet].

[EthernetFrame]: struct.EthernetFrame.html
[Ipv4Packet]: struct.Ipv4Packet.html

The functions in the `wire` module are designed for use together with `-Cpanic=abort`.

The `Packet` family of data structures guarantees that, if the `Packet::check_len()` method
returned `Ok(())`, then no accessor or setter method will panic; however, the guarantee
provided by `Packet::check_len()` may no longer hold after changing certain fields,
which are listed in the documentation for the specific packet.

The `Packet::new_checked` method is a shorthand for a combination of `Packet::new_unchecked`
and `Packet::check_len`.
When parsing untrusted input, it is *necessary* to use `Packet::new_checked()`;
so long as the buffer is not modified, no accessor will fail.
When emitting output, though, it is *incorrect* to use `Packet::new_checked()`;
the length check is likely to succeed on a zeroed buffer, but fail on a buffer
filled with data from a previous packet, such as when reusing buffers, resulting
in nondeterministic panics with some network devices but not others.
The buffer length for emission is not calculated by the `Packet` layer.
*/

mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest = ::core::ops::RangeFrom<usize>;
}

/// Read `n` bytes at `*offset` and advance it. For parsers of headers whose
/// layout depends on their own fields.
#[cfg(feature = "medium-ieee802154")]
pub(crate) fn take<'a>(buf: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
    let bytes = buf.get(*offset..*offset + n).ok_or(Error)?;
    *offset += n;
    Ok(bytes)
}

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
mod arp;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
mod dhcpv4;
#[cfg(feature = "dns")]
pub(crate) mod dns;
mod ethernet;
#[cfg(feature = "ipv4")]
mod icmpv4;
#[cfg(feature = "ipv6")]
mod icmpv6;
#[cfg(feature = "medium-ieee802154")]
mod ieee802154;
#[cfg(all(feature = "ipv4", feature = "multicast"))]
mod igmp;
pub(crate) mod ip;
#[cfg(feature = "ipv4")]
pub(crate) mod ipv4;
#[cfg(feature = "ipv6")]
pub(crate) mod ipv6;
#[cfg(feature = "ipv6")]
mod ipv6ext;
#[cfg(all(feature = "ipv6", feature = "multicast"))]
mod mld;
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
mod ndisc;
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
mod ndiscoption;
#[cfg(feature = "medium-ieee802154")]
pub(crate) mod sixlowpan;
#[cfg(feature = "tcp")]
mod tcp;
#[cfg(any(
    feature = "udp",
    feature = "dhcpv4",
    feature = "dhcpv4-server",
    feature = "medium-ieee802154"
))]
mod udp;

use core::fmt;

use crate::iface::Medium;

pub use self::ethernet::{
    Address as EthernetAddress, EtherType as EthernetProtocol, Frame as EthernetFrame,
    HEADER_LEN as ETHERNET_HEADER_LEN,
};

/// The headroom every egress packet reserves for the link-layer header below IP.
///
/// The Ethernet header in a build that drives Ethernet interfaces, since an IP
/// packet may end up going out of one. Zero in a build that only drives
/// [`Medium::Ip`] interfaces, which prepend nothing.
#[cfg(feature = "medium-ethernet")]
pub const LINK_HEADER_LEN: usize = ETHERNET_HEADER_LEN;

/// The headroom every egress packet reserves for the link-layer header below IP.
///
/// The Ethernet header in a build that drives Ethernet interfaces, since an IP
/// packet may end up going out of one. Zero in a build that only drives
/// [`Medium::Ip`] interfaces, which prepend nothing.
#[cfg(not(feature = "medium-ethernet"))]
pub const LINK_HEADER_LEN: usize = 0;

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
pub use self::arp::{
    BUFFER_LEN as ARP_BUFFER_LEN, Hardware as ArpHardware, Operation as ArpOperation, Packet as ArpPacket,
};

#[cfg(any(feature = "dhcpv4", feature = "dhcpv4-server"))]
pub(crate) use self::dhcpv4::field as dhcpv4_field;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
pub use self::dhcpv4::{
    CLIENT_PORT as DHCP_CLIENT_PORT, DhcpOption, Flags as DhcpFlags, HEADER_LEN as DHCP_HEADER_LEN,
    MAGIC_NUMBER as DHCP_MAGIC_NUMBER, MessageType as DhcpMessageType, OpCode as DhcpOpCode,
    OptionWriter as DhcpOptionWriter, Packet as DhcpPacket, SERVER_PORT as DHCP_SERVER_PORT,
};

pub use self::ip::checksum;
pub use self::ip::{
    Address as IpAddress, Cidr as IpCidr, Endpoint as IpEndpoint, ListenEndpoint as IpListenEndpoint,
    Protocol as IpProtocol, Version as IpVersion,
};

#[cfg(feature = "ipv4")]
pub use self::ipv4::{
    Address as Ipv4Address, Cidr as Ipv4Cidr, FRAGMENT_PAYLOAD_ALIGNMENT as IPV4_FRAGMENT_PAYLOAD_ALIGNMENT,
    HEADER_LEN as IPV4_HEADER_LEN, MIN_MTU as IPV4_MIN_MTU, MULTICAST_ALL_ROUTERS as IPV4_MULTICAST_ALL_ROUTERS,
    MULTICAST_ALL_SYSTEMS as IPV4_MULTICAST_ALL_SYSTEMS, Packet as Ipv4Packet,
};

#[cfg(feature = "ipv4")]
pub(crate) use self::ipv4::AddressExt as Ipv4AddressExt;

#[cfg(feature = "ipv6")]
pub use self::ipv6::{
    Address as Ipv6Address, Cidr as Ipv6Cidr, HEADER_LEN as IPV6_HEADER_LEN,
    LINK_LOCAL_ALL_MLDV2_ROUTERS as IPV6_LINK_LOCAL_ALL_MLDV2_ROUTERS,
    LINK_LOCAL_ALL_NODES as IPV6_LINK_LOCAL_ALL_NODES, LINK_LOCAL_ALL_ROUTERS as IPV6_LINK_LOCAL_ALL_ROUTERS,
    MIN_MTU as IPV6_MIN_MTU, Packet as Ipv6Packet,
};
#[cfg(feature = "ipv6")]
pub(crate) use self::ipv6::{AddressExt as Ipv6AddressExt, MulticastScope as Ipv6MulticastScope};

#[cfg(feature = "ipv6")]
pub use self::ipv6ext::{
    ExtHeader as Ipv6ExtHeader, OptionFailureAction as Ipv6OptionFailureAction, OptionType as Ipv6OptionType,
    OptionsIter as Ipv6OptionsIter, RouterAlert as Ipv6RouterAlert,
};

#[cfg(feature = "ipv4")]
pub use self::icmpv4::{
    DstUnreachable as Icmpv4DstUnreachable, Message as Icmpv4Message, Packet as Icmpv4Packet,
    ParamProblem as Icmpv4ParamProblem, Redirect as Icmpv4Redirect, TimeExceeded as Icmpv4TimeExceeded,
};

#[cfg(feature = "ipv6")]
pub use self::icmpv6::{
    DstUnreachable as Icmpv6DstUnreachable, Message as Icmpv6Message, Packet as Icmpv6Packet,
    ParamProblem as Icmpv6ParamProblem, TimeExceeded as Icmpv6TimeExceeded,
};

#[cfg(all(feature = "ipv4", feature = "multicast"))]
pub use self::igmp::{BUFFER_LEN as IGMP_BUFFER_LEN, IgmpVersion, Message as IgmpMessage, Packet as IgmpPacket};

#[cfg(all(feature = "ipv6", feature = "multicast"))]
pub use self::mld::{
    ADDRESS_RECORD_LEN as MLD_ADDRESS_RECORD_LEN, AddressRecord as MldAddressRecord, RecordType as MldRecordType,
};

#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
pub use self::ndisc::{NeighborFlags as NdiscNeighborFlags, RouterFlags as NdiscRouterFlags};

#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
pub use self::ndiscoption::{NdiscOption, PrefixInfoFlags as NdiscPrefixInfoFlags, Type as NdiscOptionType};

#[cfg(feature = "medium-ieee802154")]
pub use self::ieee802154::{
    Address as Ieee802154Address, FrameType as Ieee802154FrameType, FrameVersion as Ieee802154FrameVersion,
    MAX_HEADER_LEN as IEEE802154_MAX_HEADER_LEN, Pan as Ieee802154Pan, Repr as Ieee802154Repr,
};

#[cfg(feature = "medium-ieee802154")]
pub use self::sixlowpan::{
    AddressContext as SixlowpanAddressContext, NextHeader as SixlowpanNextHeader, SixlowpanPacket,
    frag::{
        FIRST_FRAGMENT_HEADER_SIZE as SIXLOWPAN_FIRST_FRAGMENT_HEADER_SIZE, Key as SixlowpanFragKey,
        NEXT_FRAGMENT_HEADER_SIZE as SIXLOWPAN_NEXT_FRAGMENT_HEADER_SIZE, Repr as SixlowpanFragRepr,
    },
    iphc::{MAX_HEADER_LEN as SIXLOWPAN_IPHC_MAX_HEADER_LEN, Repr as SixlowpanIphcRepr},
    nhc::{
        ExtHeaderId as SixlowpanExtHeaderId, ExtHeaderRepr as SixlowpanExtHeaderRepr, NhcPacket as SixlowpanNhcPacket,
        UdpNhcRepr as SixlowpanUdpNhcRepr,
    },
};

#[cfg(feature = "tcp")]
pub use self::tcp::{
    Control as TcpControl, HEADER_LEN as TCP_HEADER_LEN, Packet as TcpPacket, SeqNumber as TcpSeqNumber, TcpOption,
};

#[cfg(any(
    feature = "udp",
    feature = "dhcpv4",
    feature = "dhcpv4-server",
    feature = "medium-ieee802154"
))]
pub use self::udp::{HEADER_LEN as UDP_HEADER_LEN, Packet as UdpPacket};

#[cfg(feature = "dns")]
pub use self::dns::{
    Flags as DnsFlags, HEADER_LEN as DNS_HEADER_LEN, Opcode as DnsOpcode, Packet as DnsPacket, Question as DnsQuestion,
    Rcode as DnsRcode, Record as DnsRecord, RecordData as DnsRecordData, Type as DnsType,
};

/// Parsing a packet failed.
///
/// Either it is malformed, or it is not supported by xarxa.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error;

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire::Error")
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// A hardware (link-layer) address.
///
/// Which variants exist depends on the enabled `medium-*` features. In a build
/// that only drives [`Medium::Ip`] interfaces this type has a single variant and
/// takes up no space.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareAddress {
    /// An Ethernet (MAC) address. Requires the `medium-ethernet` feature.
    #[cfg(feature = "medium-ethernet")]
    Ethernet(EthernetAddress),
    /// No address, for interfaces that send and receive bare IP packets.
    /// Requires the `medium-ip` feature.
    #[cfg(feature = "medium-ip")]
    Ip,
    /// An IEEE 802.15.4 address. Requires the `medium-ieee802154` feature.
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154(Ieee802154Address),
}

impl HardwareAddress {
    /// The medium this kind of address belongs to.
    pub const fn medium(&self) -> Medium {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(_) => Medium::Ethernet,
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => Medium::Ip,
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(_) => Medium::Ieee802154,
        }
    }

    /// The address as bytes. Empty for [`Ip`](Self::Ip).
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.as_bytes(),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => &[],
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.as_bytes(),
        }
    }

    /// Query whether the address is an unicast address.
    ///
    /// `false` for [`Ip`](Self::Ip).
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_unicast(),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => false,
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.is_unicast(),
        }
    }

    /// Query whether the address is the broadcast address of its medium.
    ///
    /// `false` for [`Ip`](Self::Ip).
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => addr.is_broadcast(),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => false,
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.is_broadcast(),
        }
    }

    /// Convert the address to a modified EUI-64 interface identifier.
    ///
    /// `None` for [`Ip`](Self::Ip), and for a short or absent 802.15.4 address.
    pub fn as_eui_64(&self) -> Option<[u8; 8]> {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => Some(addr.as_eui_64()),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => None,
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => addr.as_eui_64(),
        }
    }

    /// The IEEE 802.15.4 address, or `None` if this is not one.
    #[cfg(feature = "medium-ieee802154")]
    pub const fn ieee802154(&self) -> Option<Ieee802154Address> {
        match self {
            HardwareAddress::Ieee802154(addr) => Some(*addr),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "medium-ieee802154")]
    pub(crate) fn ieee802154_or_panic(&self) -> Ieee802154Address {
        match self {
            HardwareAddress::Ieee802154(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("hardware address is not an IEEE 802.15.4 address"),
        }
    }

    /// The Ethernet address, or `None` if this is not one.
    #[cfg(feature = "medium-ethernet")]
    pub const fn ethernet(&self) -> Option<EthernetAddress> {
        match self {
            HardwareAddress::Ethernet(addr) => Some(*addr),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    #[cfg(feature = "medium-ethernet")]
    pub(crate) fn ethernet_or_panic(&self) -> EthernetAddress {
        match self {
            HardwareAddress::Ethernet(addr) => *addr,
            #[allow(unreachable_patterns)]
            _ => panic!("hardware address is not an Ethernet address"),
        }
    }

    /// Convert to the address type drivers report, [`crate::driver::HardwareAddress`].
    ///
    /// Returns `None` for an IEEE 802.15.4 address that is not an extended
    /// address: drivers report extended addresses only.
    pub fn to_driver(&self) -> Option<crate::driver::HardwareAddress> {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => Some(crate::driver::HardwareAddress::Ethernet(addr.0)),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => Some(crate::driver::HardwareAddress::Ip),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => match addr {
                Ieee802154Address::Extended(bytes) => Some(crate::driver::HardwareAddress::Ieee802154(*bytes)),
                _ => None,
            },
        }
    }

    /// Convert from the address type drivers report, [`crate::driver::HardwareAddress`].
    ///
    /// Returns `None` if the build does not have the `medium-*` feature the
    /// address kind belongs to.
    pub fn from_driver(addr: crate::driver::HardwareAddress) -> Option<Self> {
        match addr {
            #[cfg(feature = "medium-ethernet")]
            crate::driver::HardwareAddress::Ethernet(bytes) => Some(HardwareAddress::Ethernet(EthernetAddress(bytes))),
            #[cfg(feature = "medium-ip")]
            crate::driver::HardwareAddress::Ip => Some(HardwareAddress::Ip),
            #[cfg(feature = "medium-ieee802154")]
            crate::driver::HardwareAddress::Ieee802154(bytes) => {
                Some(HardwareAddress::Ieee802154(Ieee802154Address::Extended(bytes)))
            }
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

impl fmt::Display for HardwareAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => write!(f, "{addr}"),
            #[cfg(feature = "medium-ip")]
            HardwareAddress::Ip => write!(f, "none"),
            #[cfg(feature = "medium-ieee802154")]
            HardwareAddress::Ieee802154(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(feature = "medium-ieee802154")]
impl From<Ieee802154Address> for HardwareAddress {
    fn from(addr: Ieee802154Address) -> Self {
        HardwareAddress::Ieee802154(addr)
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for HardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        HardwareAddress::Ethernet(addr)
    }
}

/// The longest hardware address of any enabled medium: 8 with
/// `medium-ieee802154`, 6 otherwise.
#[cfg(not(feature = "medium-ieee802154"))]
pub const MAX_HARDWARE_ADDRESS_LEN: usize = 6;
/// The longest hardware address of any enabled medium: 8 with
/// `medium-ieee802154`, 6 otherwise.
#[cfg(feature = "medium-ieee802154")]
pub const MAX_HARDWARE_ADDRESS_LEN: usize = 8;

/// Unparsed hardware address.
///
/// Used to make NDISC parsing agnostic of the hardware medium in use.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RawHardwareAddress {
    len: u8,
    data: [u8; MAX_HARDWARE_ADDRESS_LEN],
}

impl RawHardwareAddress {
    /// Create a new `RawHardwareAddress` from a byte slice.
    ///
    /// # Panics
    /// Panics if `addr.len() > MAX_HARDWARE_ADDRESS_LEN`.
    pub fn from_bytes(addr: &[u8]) -> Self {
        let mut data = [0u8; MAX_HARDWARE_ADDRESS_LEN];
        data[..addr.len()].copy_from_slice(addr);

        Self {
            len: addr.len() as u8,
            data,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Parse the address as an address of the given medium.
    ///
    /// Errors:
    /// - `Error` if the length is wrong for the medium: 6 bytes for Ethernet,
    ///   8 (an extended address) for IEEE 802.15.4, or if the medium has no
    ///   addresses.
    pub fn parse(&self, medium: Medium) -> Result<HardwareAddress> {
        match medium {
            #[cfg(feature = "medium-ethernet")]
            Medium::Ethernet => {
                if self.len() != 6 {
                    return Err(Error);
                }
                Ok(HardwareAddress::Ethernet(EthernetAddress::from_bytes(self.as_bytes())))
            }
            #[cfg(feature = "medium-ieee802154")]
            Medium::Ieee802154 => {
                if self.len() != 8 {
                    return Err(Error);
                }
                Ok(HardwareAddress::Ieee802154(Ieee802154Address::from_bytes(
                    self.as_bytes(),
                )))
            }
            #[cfg(feature = "medium-ip")]
            Medium::Ip => Err(Error),
        }
    }
}

impl core::fmt::Display for RawHardwareAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        for (i, &b) in self.as_bytes().iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

#[cfg(feature = "medium-ethernet")]
impl From<EthernetAddress> for RawHardwareAddress {
    fn from(addr: EthernetAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

#[cfg(feature = "medium-ieee802154")]
impl From<Ieee802154Address> for RawHardwareAddress {
    fn from(addr: Ieee802154Address) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

impl From<HardwareAddress> for RawHardwareAddress {
    fn from(addr: HardwareAddress) -> Self {
        Self::from_bytes(addr.as_bytes())
    }
}

#[cfg(test)]
mod test {
    #[allow(unused_imports)]
    use super::*;

    /// A build that only drives IP interfaces pays nothing for hardware addresses.
    #[test]
    #[cfg(all(
        feature = "medium-ip",
        not(feature = "medium-ethernet"),
        not(feature = "medium-ieee802154")
    ))]
    fn test_hardware_address_is_zero_sized() {
        assert_eq!(core::mem::size_of::<super::HardwareAddress>(), 0);
    }

    #[test]
    #[cfg(feature = "medium-ethernet")]
    fn test_parse_hardware_address_ethernet() {
        let parse = |bytes: &[u8]| RawHardwareAddress::from_bytes(bytes).parse(Medium::Ethernet);
        assert_eq!(
            parse(&[0u8; 6]),
            Ok(HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 0])))
        );
        assert_eq!(parse(&[1u8; 5]), Err(Error));
        // A 7-byte address only fits `RawHardwareAddress` with `medium-ieee802154`.
        #[cfg(feature = "medium-ieee802154")]
        assert_eq!(parse(&[1u8; 7]), Err(Error));
    }

    #[test]
    #[cfg(feature = "medium-ieee802154")]
    fn test_parse_hardware_address_ieee802154() {
        let parse = |bytes: &[u8]| RawHardwareAddress::from_bytes(bytes).parse(Medium::Ieee802154);
        assert_eq!(
            parse(&[0u8; 8]),
            Ok(HardwareAddress::Ieee802154(Ieee802154Address::Extended([0; 8])))
        );
        assert_eq!(parse(&[1u8; 2]), Err(Error));
        assert_eq!(parse(&[1u8; 1]), Err(Error));
    }
}
