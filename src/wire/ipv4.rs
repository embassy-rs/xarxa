use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

use super::{Error, Result};
use crate::wire::ip::checksum;

pub use super::IpProtocol as Protocol;

/// Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1].
///
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
// RFC 791 states the following:
//
// > Every internet module must be able to forward a datagram of 68
// > octets without further fragmentation... Every internet destination
// > must be able to receive a datagram of 576 octets either in one piece
// > or in fragments to be reassembled.
//
// As a result, we can assume that every host we send packets to can
// accept a packet of the following size.
pub const MIN_MTU: usize = 576;

/// The payload of every fragment but the last is a multiple of this, in octets.
/// Fragment offsets are counted in units of it. See [RFC 791 § 3.1].
///
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
pub const FRAGMENT_PAYLOAD_ALIGNMENT: usize = 8;

/// Minimum IHL length 5x32 bit words or 20 bytes
/// [RFC 791 § 3.1]: https://tools.ietf.org/html/rfc791#section-3.1
const MINIMUM_IHL_BYTES: u8 = 20;

/// All multicast-capable nodes
pub const MULTICAST_ALL_SYSTEMS: Address = Address::new(224, 0, 0, 1);

/// All multicast-capable routers
pub const MULTICAST_ALL_ROUTERS: Address = Address::new(224, 0, 0, 2);

pub use core::net::Ipv4Addr as Address;

pub(crate) trait AddressExt {
    /// Query whether the address is an unicast address.
    ///
    /// `x_` prefix is to avoid a collision with the still-unstable method in `core::ip`.
    fn x_is_unicast(&self) -> bool;

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    fn prefix_len(&self) -> Option<u8>;

    /// The Ethernet address this multicast address maps to (RFC 1112 §6.4).
    ///
    /// The mapping drops the top 5 bits of the group, so distinct groups can
    /// map to the same Ethernet address.
    ///
    /// # Panics
    /// Panics if the address is not multicast.
    #[cfg(feature = "medium-ethernet")]
    fn multicast_ethernet_addr(&self) -> super::EthernetAddress;
}

impl AddressExt for Address {
    /// Query whether the address is an unicast address.
    fn x_is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    #[cfg(feature = "medium-ethernet")]
    fn multicast_ethernet_addr(&self) -> super::EthernetAddress {
        assert!(self.is_multicast());
        let b = self.octets();
        super::EthernetAddress([0x01, 0x00, 0x5e, b[1] & 0x7F, b[2], b[3]])
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

/// A specification of an IPv4 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Cidr {
    address: Address,
    prefix_len: u8,
}

impl Cidr {
    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub const fn new(address: Address, prefix_len: u8) -> Cidr {
        core::assert!(prefix_len <= 32);
        Cidr { address, prefix_len }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Address, netmask: Address) -> Result<Cidr> {
        let netmask = netmask.to_bits();
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Ok(Cidr {
                address: addr,
                prefix_len: netmask.count_ones() as u8,
            })
        } else {
            Err(Error)
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub const fn netmask(&self) -> Address {
        if self.prefix_len == 0 {
            return Address::new(0, 0, 0, 0);
        }

        let number = 0xffffffffu32 << (32 - self.prefix_len);
        Address::from_bits(number)
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Address> {
        let network = self.network();

        if network.prefix_len == 31 || network.prefix_len == 32 {
            return None;
        }

        let network_number = network.address.to_bits();
        let number = network_number | 0xffffffffu32 >> network.prefix_len;
        Some(Address::from_bits(number))
    }

    /// Return the network block of this IPv4 CIDR.
    pub const fn network(&self) -> Cidr {
        Cidr {
            address: Address::from_bits(self.address.to_bits() & self.netmask().to_bits()),
            prefix_len: self.prefix_len,
        }
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        self.address.to_bits() & self.netmask().to_bits() == addr.to_bits() & self.netmask().to_bits()
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the subnetwork described by the given IPv4 CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    buffer: &'a mut [u8],
}

mod field {
    use crate::wire::field::*;

    pub const VER_IHL: usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const IDENT: Field = 4..6;
    pub const FLG_OFF: Field = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

pub const HEADER_LEN: usize = field::DST_ADDR.end;

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(Error)` if the buffer is too short.
    /// Returns `Err(Error)` if the header length is greater
    /// than total length.
    /// Returns `Err(Error)` if the header length is less than minimum allowed IHL
    ///
    /// The result of this check is invalidated by calling [set_header_len]
    /// and [set_total_len].
    ///
    /// [set_header_len]: #method.set_header_len
    /// [set_total_len]: #method.set_total_len
    #[allow(clippy::if_same_then_else)]
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.len();
        if len < field::DST_ADDR.end {
            Err(Error)
        } else if len < self.header_len() as usize {
            Err(Error)
        } else if self.header_len() as u16 > self.total_len() {
            Err(Error)
        } else if len < self.total_len() as usize {
            Err(Error)
        } else if self.header_len() < MINIMUM_IHL_BYTES {
            Err(Error)
        } else {
            Ok(())
        }
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        self.buffer[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buffer[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        self.buffer[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        self.buffer[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline]
    pub fn ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline]
    pub fn dont_frag(&self) -> bool {
        NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub fn more_frags(&self) -> bool {
        NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.buffer[field::TTL]
    }

    /// Return the next_header (protocol) field.
    #[inline]
    pub fn next_header(&self) -> Protocol {
        Protocol::from(self.buffer[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
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

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        checksum::data(&self.buffer[..self.header_len() as usize]) == !0
    }

    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        &self.buffer[range]
    }

    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        self.buffer[field::VER_IHL] = (self.buffer[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.buffer[field::VER_IHL] = (self.buffer[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        self.buffer[field::DSCP_ECN] = (self.buffer[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        self.buffer[field::DSCP_ECN] = (self.buffer[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut self.buffer[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut self.buffer[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut self.buffer[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let raw = NetworkEndian::read_u16(&self.buffer[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut self.buffer[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.buffer[field::TTL] = value
    }

    /// Set the next header (protocol) field.
    #[inline]
    pub fn set_next_header(&mut self, value: Protocol) {
        self.buffer[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Address) {
        self.buffer[field::SRC_ADDR].copy_from_slice(&value.octets())
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Address) {
        self.buffer[field::DST_ADDR].copy_from_slice(&value.octets())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = !checksum::data(&self.buffer[..self.header_len() as usize]);
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        &mut self.buffer[range]
    }
}

impl<'a> AsRef<[u8]> for Packet<'a> {
    fn as_ref(&self) -> &[u8] {
        self.buffer
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_1: Address = Address::new(192, 168, 1, 1);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_2: Address = Address::new(192, 168, 1, 2);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_3: Address = Address::new(192, 168, 1, 3);
    #[allow(unused)]
    pub(crate) const MOCK_IP_ADDR_4: Address = Address::new(192, 168, 1, 4);
    #[allow(unused)]
    pub(crate) const MOCK_UNSPECIFIED: Address = Address::UNSPECIFIED;

    static PACKET_BYTES: [u8; 30] = [
        0x45, 0x00, 0x00, 0x1e, 0x01, 0x02, 0x62, 0x03, 0x1a, 0x01, 0xd5, 0x6e, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
        0x23, 0x24, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
    ];

    static PAYLOAD_BYTES: [u8; 10] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes);
        assert_eq!(packet.version(), 4);
        assert_eq!(packet.header_len(), 20);
        assert_eq!(packet.dscp(), 0);
        assert_eq!(packet.ecn(), 0);
        assert_eq!(packet.total_len(), 30);
        assert_eq!(packet.ident(), 0x102);
        assert!(packet.more_frags());
        assert!(packet.dont_frag());
        assert_eq!(packet.frag_offset(), 0x203 * 8);
        assert_eq!(packet.hop_limit(), 0x1a);
        assert_eq!(packet.next_header(), Protocol::Icmp);
        assert_eq!(packet.checksum(), 0xd56e);
        assert_eq!(packet.src_addr(), Address::new(0x11, 0x12, 0x13, 0x14));
        assert_eq!(packet.dst_addr(), Address::new(0x21, 0x22, 0x23, 0x24));
        assert!(packet.verify_checksum());
        assert_eq!(packet.payload(), &PAYLOAD_BYTES[..]);
    }

    #[test]
    fn test_construct() {
        let mut bytes = [0xa5; 30];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_version(4);
        packet.set_header_len(20);
        packet.clear_flags();
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(30);
        packet.set_ident(0x102);
        packet.set_more_frags(true);
        packet.set_dont_frag(true);
        packet.set_frag_offset(0x203 * 8);
        packet.set_hop_limit(0x1a);
        packet.set_next_header(Protocol::Icmp);
        packet.set_src_addr(Address::new(0x11, 0x12, 0x13, 0x14));
        packet.set_dst_addr(Address::new(0x21, 0x22, 0x23, 0x24));
        packet.fill_checksum();
        packet.payload_mut().copy_from_slice(&PAYLOAD_BYTES[..]);
        assert_eq!(bytes, PACKET_BYTES);
    }

    #[test]
    fn test_overlong() {
        let mut bytes = [0u8; 31];
        bytes[..30].copy_from_slice(&PACKET_BYTES[..]);

        assert_eq!(Packet::new_unchecked(&mut bytes).payload().len(), PAYLOAD_BYTES.len());
        assert_eq!(
            Packet::new_unchecked(&mut bytes).payload_mut().len(),
            PAYLOAD_BYTES.len()
        );
    }

    #[test]
    fn test_total_len_overflow() {
        let mut bytes = PACKET_BYTES;
        Packet::new_unchecked(&mut bytes).set_total_len(128);

        assert_eq!(Packet::new_checked(&mut bytes).unwrap_err(), Error);
    }

    static REPR_PACKET_BYTES: [u8; 24] = [
        0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0xd2, 0x79, 0x11, 0x12, 0x13, 0x14, 0x21, 0x22,
        0x23, 0x24, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_parse_total_len_less_than_header_len() {
        let mut bytes = [0; 40];
        bytes[0] = 0x09;
        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_parse_small_ihl() {
        let mut bytes = REPR_PACKET_BYTES;
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_header_len(16);

        assert_eq!(Packet::new_checked(&mut bytes), Err(Error));
    }

    #[test]
    fn test_unspecified() {
        assert!(Address::UNSPECIFIED.is_unspecified());
        assert!(!Address::UNSPECIFIED.is_broadcast());
        assert!(!Address::UNSPECIFIED.is_multicast());
        assert!(!Address::UNSPECIFIED.is_link_local());
        assert!(!Address::UNSPECIFIED.is_loopback());
    }

    #[test]
    fn test_broadcast() {
        assert!(!Address::BROADCAST.is_unspecified());
        assert!(Address::BROADCAST.is_broadcast());
        assert!(!Address::BROADCAST.is_multicast());
        assert!(!Address::BROADCAST.is_link_local());
        assert!(!Address::BROADCAST.is_loopback());
    }

    #[test]
    fn test_cidr() {
        let cidr = Cidr::new(Address::new(192, 168, 1, 10), 24);

        let inside_subnet = [
            [192, 168, 1, 0],
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            [192, 168, 1, 10],
            [192, 168, 1, 127],
            [192, 168, 1, 255],
        ];

        let outside_subnet = [
            [192, 168, 0, 0],
            [127, 0, 0, 1],
            [192, 168, 2, 0],
            [192, 168, 0, 255],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
        ];

        let subnets = [
            ([192, 168, 1, 0], 32),
            ([192, 168, 1, 255], 24),
            ([192, 168, 1, 10], 30),
        ];

        let not_subnets = [
            ([192, 168, 1, 10], 23),
            ([127, 0, 0, 1], 8),
            ([192, 168, 1, 0], 0),
            ([192, 168, 0, 255], 32),
        ];

        for addr in inside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(cidr.contains_addr(&addr));
        }

        for addr in outside_subnet.iter().map(|a| Address::from_octets(*a)) {
            assert!(!cidr.contains_addr(&addr));
        }

        for subnet in subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(cidr.contains_subnet(&subnet));
        }

        for subnet in not_subnets
            .iter()
            .map(|&(a, p)| Cidr::new(Address::new(a[0], a[1], a[2], a[3]), p))
        {
            assert!(!cidr.contains_subnet(&subnet));
        }

        let cidr_without_prefix = Cidr::new(cidr.address(), 0);
        assert!(cidr_without_prefix.contains_addr(&Address::new(127, 0, 0, 1)));
    }

    #[test]
    fn test_cidr_from_netmask() {
        assert!(Cidr::from_netmask(Address::new(0, 0, 0, 0), Address::new(1, 0, 2, 0)).is_err());
        assert!(Cidr::from_netmask(Address::new(0, 0, 0, 0), Address::new(0, 0, 0, 0)).is_err());
        assert_eq!(
            Cidr::from_netmask(Address::new(0, 0, 0, 1), Address::new(255, 255, 255, 0)).unwrap(),
            Cidr::new(Address::new(0, 0, 0, 1), 24)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(192, 168, 0, 1), Address::new(255, 255, 0, 0)).unwrap(),
            Cidr::new(Address::new(192, 168, 0, 1), 16)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(172, 16, 0, 1), Address::new(255, 240, 0, 0)).unwrap(),
            Cidr::new(Address::new(172, 16, 0, 1), 12)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(255, 255, 255, 1), Address::new(255, 255, 255, 0)).unwrap(),
            Cidr::new(Address::new(255, 255, 255, 1), 24)
        );
        assert_eq!(
            Cidr::from_netmask(Address::new(255, 255, 255, 255), Address::new(255, 255, 255, 255)).unwrap(),
            Cidr::new(Address::new(255, 255, 255, 255), 32)
        );
    }

    #[test]
    fn test_cidr_netmask() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).netmask(),
            Address::new(0, 0, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).netmask(),
            Address::new(255, 255, 255, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 32).netmask(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8).netmask(),
            Address::new(255, 0, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16).netmask(),
            Address::new(255, 255, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16).netmask(),
            Address::new(255, 255, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17).netmask(),
            Address::new(255, 255, 128, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 0), 12).netmask(),
            Address::new(255, 240, 0, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24).netmask(),
            Address::new(255, 255, 255, 0)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 255), 32).netmask(),
            Address::new(255, 255, 255, 255)
        );
    }

    #[test]
    fn test_cidr_broadcast() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).broadcast().unwrap(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).broadcast().unwrap(),
            Address::new(0, 0, 0, 255)
        );
        assert_eq!(Cidr::new(Address::new(0, 0, 0, 0), 32).broadcast(), None);
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8).broadcast().unwrap(),
            Address::new(127, 255, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16).broadcast().unwrap(),
            Address::new(192, 168, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16).broadcast().unwrap(),
            Address::new(192, 168, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17).broadcast().unwrap(),
            Address::new(192, 168, 127, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 1), 12).broadcast().unwrap(),
            Address::new(172, 31, 255, 255)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24).broadcast().unwrap(),
            Address::new(255, 255, 255, 255)
        );
        assert_eq!(Cidr::new(Address::new(255, 255, 255, 254), 31).broadcast(), None);
        assert_eq!(Cidr::new(Address::new(255, 255, 255, 255), 32).broadcast(), None);
    }

    #[test]
    fn test_cidr_network() {
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 0).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 0)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 1), 24).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 24)
        );
        assert_eq!(
            Cidr::new(Address::new(0, 0, 0, 0), 32).network(),
            Cidr::new(Address::new(0, 0, 0, 0), 32)
        );
        assert_eq!(
            Cidr::new(Address::new(127, 0, 0, 0), 8).network(),
            Cidr::new(Address::new(127, 0, 0, 0), 8)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 0, 0), 16).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 16)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 16).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 16)
        );
        assert_eq!(
            Cidr::new(Address::new(192, 168, 1, 1), 17).network(),
            Cidr::new(Address::new(192, 168, 0, 0), 17)
        );
        assert_eq!(
            Cidr::new(Address::new(172, 16, 0, 1), 12).network(),
            Cidr::new(Address::new(172, 16, 0, 0), 12)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 1), 24).network(),
            Cidr::new(Address::new(255, 255, 255, 0), 24)
        );
        assert_eq!(
            Cidr::new(Address::new(255, 255, 255, 255), 32).network(),
            Cidr::new(Address::new(255, 255, 255, 255), 32)
        );
    }
}
