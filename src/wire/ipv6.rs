#![deny(missing_docs)]

use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};

pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv6. See [RFC 8200 § 5].
///
/// [RFC 8200 § 5]: https://tools.ietf.org/html/rfc8200#section-5
pub const MIN_MTU: usize = 1280;

/// Size of IPv6 adderess in octets.
///
/// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc4291#section-2
pub const ADDR_SIZE: usize = 16;

/// The link-local [all nodes multicast address].
///
/// [all nodes multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const LINK_LOCAL_ALL_NODES: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// The link-local [all routers multicast address].
///
/// [all routers multicast address]: https://tools.ietf.org/html/rfc4291#section-2.7.1
pub const LINK_LOCAL_ALL_ROUTERS: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// The link-local [all MLVDv2-capable routers multicast address].
///
/// [all MLVDv2-capable routers multicast address]: https://tools.ietf.org/html/rfc3810#section-11
pub const LINK_LOCAL_ALL_MLDV2_ROUTERS: Address = Address::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16);

/// The [scope] of an address.
///
/// [scope]: https://www.rfc-editor.org/rfc/rfc4291#section-2.7
#[repr(u8)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MulticastScope {
    /// Interface Local scope
    InterfaceLocal = 0x1,
    /// Link local scope
    LinkLocal = 0x2,
    /// Administratively configured
    AdminLocal = 0x4,
    /// Single site scope
    SiteLocal = 0x5,
    /// Organization scope
    OrganizationLocal = 0x8,
    /// Global scope
    Global = 0xE,
    /// Unknown scope
    Unknown = 0xFF,
}

impl From<u8> for MulticastScope {
    fn from(value: u8) -> Self {
        match value {
            0x1 => Self::InterfaceLocal,
            0x2 => Self::LinkLocal,
            0x4 => Self::AdminLocal,
            0x5 => Self::SiteLocal,
            0x8 => Self::OrganizationLocal,
            0xE => Self::Global,
            _ => Self::Unknown,
        }
    }
}

pub use core::net::Ipv6Addr as Address;

pub(crate) trait AddressExt {
    /// Query whether the IPv6 address is an [unicast address].
    ///
    /// [unicast address]: https://tools.ietf.org/html/rfc4291#section-2.5
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_is_unicast(&self) -> bool;

    /// Query whether the IPv6 address is a [global unicast address].
    ///
    /// [global unicast address]: https://datatracker.ietf.org/doc/html/rfc3587
    fn is_global_unicast(&self) -> bool;

    /// Query whether the IPv6 address is in the [link-local] scope.
    ///
    /// [link-local]: https://tools.ietf.org/html/rfc4291#section-2.5.6
    fn is_link_local(&self) -> bool;

    /// Helper function used to mask an address given a prefix.
    ///
    /// # Panics
    /// This function panics if `mask` is greater than 128.
    fn mask(&self, mask: u8) -> [u8; ADDR_SIZE];

    /// The solicited node for the given unicast address.
    ///
    /// # Panics
    /// This function panics if the given address is not
    /// unicast.
    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn solicited_node(&self) -> Address;

    /// The Ethernet address this multicast address maps to (RFC 2464 §7).
    ///
    /// The mapping keeps only the low 32 bits of the group, so distinct groups
    /// can map to the same Ethernet address.
    ///
    /// # Panics
    /// Panics if the address is not multicast.
    #[cfg(feature = "medium-ethernet")]
    fn multicast_ethernet_addr(&self) -> super::EthernetAddress;

    /// Return the scope of the address.
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_multicast_scope(&self) -> MulticastScope;

    /// Query whether the IPv6 address is a [solicited-node multicast address].
    ///
    /// [Solicited-node multicast address]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.7.1
    fn is_solicited_node_multicast(&self) -> bool;

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    fn prefix_len(&self) -> Option<u8>;
}

impl AddressExt for Address {
    fn x_is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    fn is_global_unicast(&self) -> bool {
        (self.octets()[0] >> 5) == 0b001
    }

    fn is_link_local(&self) -> bool {
        self.octets()[0..8] == [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    fn mask(&self, mask: u8) -> [u8; ADDR_SIZE] {
        assert!(mask <= 128);
        let mut bytes = [0u8; ADDR_SIZE];
        let idx = (mask as usize) / 8;
        let modulus = (mask as usize) % 8;
        let octets = self.octets();
        let (first, second) = octets.split_at(idx);
        bytes[0..idx].copy_from_slice(first);
        if idx < ADDR_SIZE {
            let part = second[0];
            bytes[idx] = part & (!(0xff >> modulus) as u8);
        }
        bytes
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    fn solicited_node(&self) -> Address {
        assert!(self.x_is_unicast());
        let o = self.octets();
        Address::from([
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, o[13], o[14], o[15],
        ])
    }

    #[cfg(feature = "medium-ethernet")]
    fn multicast_ethernet_addr(&self) -> super::EthernetAddress {
        assert!(self.is_multicast());
        let b = self.octets();
        super::EthernetAddress([0x33, 0x33, b[12], b[13], b[14], b[15]])
    }

    fn x_multicast_scope(&self) -> MulticastScope {
        if self.is_multicast() {
            return MulticastScope::from(self.octets()[1] & 0b1111);
        }

        if self.is_link_local() {
            MulticastScope::LinkLocal
        } else if self.is_unique_local() || self.is_global_unicast() {
            // ULA are considered global scope
            // https://www.rfc-editor.org/rfc/rfc6724#section-3.1
            MulticastScope::Global
        } else {
            MulticastScope::Unknown
        }
    }

    fn is_solicited_node_multicast(&self) -> bool {
        self.octets()[0..13]
            == [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
            ]
    }

    fn prefix_len(&self) -> Option<u8> {
        let mut ones = true;
        let mut prefix_len = 0;
        for byte in self.octets() {
            let mut mask = 0x80;
            for _ in 0..8 {
                let one = byte & mask != 0;
                if ones {
                    // Expect 1s until first 0
                    if one {
                        prefix_len += 1;
                    } else {
                        ones = false;
                    }
                } else if one {
                    // 1 where 0 was expected
                    return None;
                }
                mask >>= 1;
            }
        }
        Some(prefix_len)
    }
}

/// A specification of an IPv6 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Address,
    prefix_len: u8,
}

impl Cidr {
    /// The [solicited node prefix].
    ///
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Cidr = Cidr {
        address: Address::new(0xff02, 0, 0, 0, 0, 1, 0xff00, 0),
        prefix_len: 104,
    };

    /// The link-local address prefix.
    pub const LINK_LOCAL_PREFIX: Cidr = Cidr {
        address: Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 10,
    };

    /// Create an IPv6 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 128.
    pub const fn new(address: Address, prefix_len: u8) -> Cidr {
        core::assert!(prefix_len <= 128);
        Cidr { address, prefix_len }
    }

    /// Return the address of this IPv6 CIDR block.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv6 CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Query whether the subnetwork described by this IPv6 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        // right shift by 128 is not legal
        if self.prefix_len == 0 {
            return true;
        }

        self.address.mask(self.prefix_len) == addr.mask(self.prefix_len)
    }

    /// Query whether the subnetwork described by this IPV6 CIDR block contains
    /// the subnetwork described by the given IPv6 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// A read/write wrapper around an Internet Protocol version 6 packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

// Ranges and constants describing the IPv6 header
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc2460#section-3 for details.
mod field {
    use crate::wire::field::*;
    // 4-bit version number, 8-bit traffic class, and the
    // 20-bit flow label.
    pub const VER_TC_FLOW: Field = 0..4;
    // 16-bit value representing the length of the payload.
    // Note: Options are included in this length.
    pub const LENGTH: Field = 4..6;
    // 8-bit value identifying the type of header following this
    // one. Note: The same numbers are used in IPv4.
    pub const NXT_HDR: usize = 6;
    // 8-bit value decremented by each node that forwards this
    // packet. The packet is discarded when the value is 0.
    pub const HOP_LIMIT: usize = 7;
    // IPv6 address of the source node.
    pub const SRC_ADDR: Field = 8..24;
    // IPv6 address of the destination node.
    pub const DST_ADDR: Field = 24..40;
}

/// Length of an IPv6 header.
pub const HEADER_LEN: usize = field::DST_ADDR.end;

impl<'a> Packet<'a> {
    /// Create a raw octet buffer with an IPv6 packet structure.
    #[inline]
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    #[inline]
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    ///
    /// The result of this check is invalidated by calling [set_payload_len].
    ///
    /// [set_payload_len]: #method.set_payload_len
    #[inline]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.len();
        if len < field::DST_ADDR.end || len < self.total_len() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the header length.
    #[inline]
    pub const fn header_len(&self) -> usize {
        // This is not a strictly necessary function, but it makes
        // code more readable.
        field::DST_ADDR.end
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.buffer[field::VER_TC_FLOW.start] >> 4
    }

    /// Return the traffic class.
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((NetworkEndian::read_u16(&self.buffer[0..2]) & 0x0ff0) >> 4) as u8
    }

    /// Return the flow label field.
    #[inline]
    pub fn flow_label(&self) -> u32 {
        NetworkEndian::read_u24(&self.buffer[1..4]) & 0x000fffff
    }

    /// Return the payload length field.
    #[inline]
    pub fn payload_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::LENGTH])
    }

    /// Return the payload length added to the known header length.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.payload_len() as usize
    }

    /// Return the next header field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.buffer[field::NXT_HDR])
    }

    /// Return the hop limit field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.buffer[field::HOP_LIMIT]
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Address {
        Address::from_octets(self.buffer[field::SRC_ADDR].try_into().unwrap())
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Address {
        Address::from_octets(self.buffer[field::DST_ADDR].try_into().unwrap())
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let range = self.header_len()..self.total_len();
        &self.buffer[range]
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        // Make sure to retain the lower order bits which contain
        // the higher order bits of the traffic class
        self.buffer[0] = (self.buffer[0] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the traffic class field.
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        // Put the higher order 4-bits of value in the lower order
        // 4-bits of the first byte
        self.buffer[0] = (self.buffer[0] & 0xf0) | ((value & 0xf0) >> 4);
        // Put the lower order 4-bits of value in the higher order
        // 4-bits of the second byte
        self.buffer[1] = (self.buffer[1] & 0x0f) | ((value & 0x0f) << 4);
    }

    /// Set the flow label field.
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        // Retain the lower order 4-bits of the traffic class
        let raw = (((self.buffer[1] & 0xf0) as u32) << 16) | (value & 0x0fffff);
        NetworkEndian::write_u24(&mut self.buffer[1..4], raw);
    }

    /// Set the payload length field.
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::LENGTH], value);
    }

    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        self.buffer[field::NXT_HDR] = value.into();
    }

    /// Set the hop limit field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.buffer[field::HOP_LIMIT] = value;
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        self.buffer[field::SRC_ADDR].copy_from_slice(&value.octets());
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        self.buffer[field::DST_ADDR].copy_from_slice(&value.octets());
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..self.total_len();
        &mut self.buffer[range]
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_1: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_2: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_3: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 3);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_4: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 4);
    #[allow(unused)]
    pub(crate) const MOCK_UNSPECIFIED: Address = Address::UNSPECIFIED;

    const LINK_LOCAL_ADDR: Address = Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const UNIQUE_LOCAL_ADDR: Address = Address::new(0xfd00, 0, 0, 201, 1, 1, 1, 1);
    const GLOBAL_UNICAST_ADDR: Address = Address::new(0x2001, 0xdb8, 0x3, 0, 0, 0, 0, 1);

    const TEST_SOL_NODE_MCAST_ADDR: Address = Address::new(0xff02, 0, 0, 0, 0, 1, 0xff01, 101);

    #[test]
    fn test_basic_multicast() {
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_unspecified());
        assert!(LINK_LOCAL_ALL_ROUTERS.is_multicast());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_link_local());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_loopback());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_unique_local());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_global_unicast());
        assert!(!LINK_LOCAL_ALL_ROUTERS.is_solicited_node_multicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_unspecified());
        assert!(LINK_LOCAL_ALL_NODES.is_multicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_link_local());
        assert!(!LINK_LOCAL_ALL_NODES.is_loopback());
        assert!(!LINK_LOCAL_ALL_NODES.is_unique_local());
        assert!(!LINK_LOCAL_ALL_NODES.is_global_unicast());
        assert!(!LINK_LOCAL_ALL_NODES.is_solicited_node_multicast());
    }

    #[test]
    fn test_basic_link_local() {
        assert!(!LINK_LOCAL_ADDR.is_unspecified());
        assert!(!LINK_LOCAL_ADDR.is_multicast());
        assert!(LINK_LOCAL_ADDR.is_link_local());
        assert!(!LINK_LOCAL_ADDR.is_loopback());
        assert!(!LINK_LOCAL_ADDR.is_unique_local());
        assert!(!LINK_LOCAL_ADDR.is_global_unicast());
        assert!(!LINK_LOCAL_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_basic_loopback() {
        assert!(!Address::LOCALHOST.is_unspecified());
        assert!(!Address::LOCALHOST.is_multicast());
        assert!(!Address::LOCALHOST.is_link_local());
        assert!(Address::LOCALHOST.is_loopback());
        assert!(!Address::LOCALHOST.is_unique_local());
        assert!(!Address::LOCALHOST.is_global_unicast());
        assert!(!Address::LOCALHOST.is_solicited_node_multicast());
    }

    #[test]
    fn test_unique_local() {
        assert!(!UNIQUE_LOCAL_ADDR.is_unspecified());
        assert!(!UNIQUE_LOCAL_ADDR.is_multicast());
        assert!(!UNIQUE_LOCAL_ADDR.is_link_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_loopback());
        assert!(UNIQUE_LOCAL_ADDR.is_unique_local());
        assert!(!UNIQUE_LOCAL_ADDR.is_global_unicast());
        assert!(!UNIQUE_LOCAL_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_global_unicast() {
        assert!(!GLOBAL_UNICAST_ADDR.is_unspecified());
        assert!(!GLOBAL_UNICAST_ADDR.is_multicast());
        assert!(!GLOBAL_UNICAST_ADDR.is_link_local());
        assert!(!GLOBAL_UNICAST_ADDR.is_loopback());
        assert!(!GLOBAL_UNICAST_ADDR.is_unique_local());
        assert!(GLOBAL_UNICAST_ADDR.is_global_unicast());
        assert!(!GLOBAL_UNICAST_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_sollicited_node_multicast() {
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_unspecified());
        assert!(TEST_SOL_NODE_MCAST_ADDR.is_multicast());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_link_local());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_loopback());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_unique_local());
        assert!(!TEST_SOL_NODE_MCAST_ADDR.is_global_unicast());
        assert!(TEST_SOL_NODE_MCAST_ADDR.is_solicited_node_multicast());
    }

    #[test]
    fn test_mask() {
        let addr = Address::new(0x0123, 0x4567, 0x89ab, 0, 0, 0, 0, 1);
        assert_eq!(addr.mask(11), [0x01, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(addr.mask(15), [0x01, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            addr.mask(26),
            [0x01, 0x23, 0x45, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            addr.mask(128),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(
            addr.mask(127),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn test_cidr() {
        // fe80::1/56
        // 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        let cidr = Cidr::new(LINK_LOCAL_ADDR, 56);

        let inside_subnet = [
            // fe80::2
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            ],
            // fe80::1122:3344:5566:7788
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            // fe80::ff00:0:0:0
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            // fe80::ff
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
            ],
        ];

        let outside_subnet = [
            // fe80:0:0:101::1
            [
                0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ],
            // ::1
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ],
            // ff02::1
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ],
            // ff02::2
            [
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            ],
        ];

        let subnets = [
            // fe80::ffff:ffff:ffff:ffff/65
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                65,
            ),
            // fe80::1/128
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                128,
            ),
            // fe80::1234:5678/96
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
                ],
                96,
            ),
        ];

        let not_subnets = [
            // fe80::101:ffff:ffff:ffff:ffff/55
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                55,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/56
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                56,
            ),
            // fe80::101:ffff:ffff:ffff:ffff/57
            (
                [
                    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
                57,
            ),
            // ::1/128
            (
                [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                128,
            ),
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets.iter().map(|&(a, p)| Cidr::new(Address::from(a), p)) {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets.iter().map(|&(a, p)| Cidr::new(Address::from(a), p)) {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(LINK_LOCAL_ADDR, 0);
        assert!(cidr_without_prefix.contains_addr(&Address::LOCALHOST));
    }

    #[test]
    fn test_scope() {
        use super::*;
        assert_eq!(
            Address::new(0xff01, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::InterfaceLocal
        );
        assert_eq!(
            Address::new(0xff02, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::LinkLocal
        );
        assert_eq!(
            Address::new(0xff03, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::Unknown
        );
        assert_eq!(
            Address::new(0xff04, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::AdminLocal
        );
        assert_eq!(
            Address::new(0xff05, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::SiteLocal
        );
        assert_eq!(
            Address::new(0xff08, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::OrganizationLocal
        );
        assert_eq!(
            Address::new(0xff0e, 0, 0, 0, 0, 0, 0, 1).x_multicast_scope(),
            MulticastScope::Global
        );

        assert_eq!(LINK_LOCAL_ALL_NODES.x_multicast_scope(), MulticastScope::LinkLocal);

        // For source address selection, unicast addresses also have a scope:
        assert_eq!(LINK_LOCAL_ADDR.x_multicast_scope(), MulticastScope::LinkLocal);
        assert_eq!(GLOBAL_UNICAST_ADDR.x_multicast_scope(), MulticastScope::Global);
        assert_eq!(UNIQUE_LOCAL_ADDR.x_multicast_scope(), MulticastScope::Global);
    }

    static REPR_PACKET_BYTES: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
    ];
    static REPR_PAYLOAD_BYTES: [u8; 12] = [0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff];

    #[test]
    fn test_packet_deconstruction() {
        let mut bytes = REPR_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.check_len(), Ok(()));
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0);
        assert_eq!(packet.flow_label(), 0);
        assert_eq!(packet.total_len(), 0x34);
        assert_eq!(packet.payload_len() as usize, REPR_PAYLOAD_BYTES.len());
        assert_eq!(packet.next_header(), Protocol::Udp);
        assert_eq!(packet.hop_limit(), 0x40);
        assert_eq!(packet.src_addr(), Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(packet.dst_addr(), LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.payload(), &REPR_PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_packet_construction() {
        let mut bytes = [0xff; 52];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        // Version, Traffic Class, and Flow Label are not
        // byte aligned. make sure the setters and getters
        // do not interfere with each other.
        packet.set_version(6);
        assert_eq!(packet.version(), 6);
        packet.set_traffic_class(0x99);
        assert_eq!(packet.version(), 6);
        assert_eq!(packet.traffic_class(), 0x99);
        packet.set_flow_label(0x54321);
        assert_eq!(packet.traffic_class(), 0x99);
        assert_eq!(packet.flow_label(), 0x54321);
        packet.set_payload_len(0xc);
        packet.set_next_header(Protocol::Udp);
        packet.set_hop_limit(0xfe);
        packet.set_src_addr(LINK_LOCAL_ALL_ROUTERS);
        packet.set_dst_addr(LINK_LOCAL_ALL_NODES);
        packet.payload_mut().copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(packet.check_len(), Ok(()));
        let mut expected_bytes = [
            0x69, 0x95, 0x43, 0x21, 0x00, 0x0c, 0x11, 0xfe, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let start = expected_bytes.len() - REPR_PAYLOAD_BYTES.len();
        expected_bytes[start..].copy_from_slice(&REPR_PAYLOAD_BYTES[..]);
        assert_eq!(&bytes[..], &expected_bytes[..]);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        bytes.push(0);

        assert_eq!(
            Packet::new_unchecked(&mut bytes).payload().len(),
            REPR_PAYLOAD_BYTES.len()
        );
        assert_eq!(
            Packet::new_unchecked(&mut bytes).payload_mut().len(),
            REPR_PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = vec![];
        bytes.extend(&REPR_PACKET_BYTES[..]);
        Packet::new_unchecked(&mut bytes).set_payload_len(0x80);

        assert_eq!(Packet::new_checked(&mut bytes).unwrap_err(), Error);
    }
}
