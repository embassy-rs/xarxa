use core::convert::From;
use core::fmt;

use super::{Error, Result};
#[cfg(feature = "ipv4")]
use crate::wire::{Ipv4Address, Ipv4AddressExt, Ipv4Cidr};
#[cfg(feature = "ipv6")]
use crate::wire::{Ipv6Address, Ipv6AddressExt, Ipv6Cidr};

/// Internet protocol version.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Version {
    #[cfg(feature = "ipv4")]
    Ipv4,
    #[cfg(feature = "ipv6")]
    Ipv6,
}

impl Version {
    /// Return the version of an IP packet stored in the provided buffer.
    ///
    /// This function never returns `Ok(IpVersion::Unspecified)`; instead,
    /// unknown versions result in `Err(Error)`.
    pub const fn of_packet(data: &[u8]) -> Result<Version> {
        match data[0] >> 4 {
            #[cfg(feature = "ipv4")]
            4 => Ok(Version::Ipv4),
            #[cfg(feature = "ipv6")]
            6 => Ok(Version::Ipv6),
            _ => Err(Error),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Version::Ipv4 => write!(f, "IPv4"),
            #[cfg(feature = "ipv6")]
            Version::Ipv6 => write!(f, "IPv6"),
        }
    }
}

open_enum! {
    /// IP datagram encapsulated protocol.
    pub enum Protocol(u8) {
        HopByHop  = 0x00,
        Icmp      = 0x01,
        Igmp      = 0x02,
        Tcp       = 0x06,
        Udp       = 0x11,
        Ipv6Route = 0x2b,
        Ipv6Frag  = 0x2c,
        IpSecEsp  = 0x32,
        IpSecAh   = 0x33,
        Icmpv6    = 0x3a,
        Ipv6NoNxt = 0x3b,
        Ipv6Opts  = 0x3c
    }
}

/// An internetworking address.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Address {
    /// An IPv4 address.
    #[cfg(feature = "ipv4")]
    Ipv4(Ipv4Address),
    /// An IPv6 address.
    #[cfg(feature = "ipv6")]
    Ipv6(Ipv6Address),
}

impl Address {
    /// Create an address wrapping an IPv4 address with the given octets.
    #[cfg(feature = "ipv4")]
    pub const fn v4(a0: u8, a1: u8, a2: u8, a3: u8) -> Address {
        Address::Ipv4(Ipv4Address::new(a0, a1, a2, a3))
    }

    /// Create an address wrapping an IPv6 address with the given octets.
    #[cfg(feature = "ipv6")]
    #[allow(clippy::too_many_arguments)]
    pub const fn v6(a0: u16, a1: u16, a2: u16, a3: u16, a4: u16, a5: u16, a6: u16, a7: u16) -> Address {
        Address::Ipv6(Ipv6Address::new(a0, a1, a2, a3, a4, a5, a6, a7))
    }

    /// Return the protocol version.
    pub const fn version(&self) -> Version {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(_) => Version::Ipv4,
            #[cfg(feature = "ipv6")]
            Address::Ipv6(_) => Version::Ipv6,
        }
    }

    /// Query whether the address is a valid unicast address.
    pub fn is_unicast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => addr.x_is_unicast(),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => addr.x_is_unicast(),
        }
    }

    /// Query whether the address is a valid multicast address.
    pub const fn is_multicast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => addr.is_multicast(),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => addr.is_multicast(),
        }
    }

    /// Query whether the address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => addr.is_broadcast(),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(_) => false,
        }
    }

    /// Query whether the address falls into the "unspecified" range.
    pub fn is_unspecified(&self) -> bool {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => addr.is_unspecified(),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => addr.is_unspecified(),
        }
    }

    /// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
    /// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
    pub fn prefix_len(&self) -> Option<u8> {
        match self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => addr.prefix_len(),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => addr.prefix_len(),
        }
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::IpAddr> for Address {
    fn from(x: ::core::net::IpAddr) -> Address {
        match x {
            ::core::net::IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
            ::core::net::IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
        }
    }
}

impl From<Address> for ::core::net::IpAddr {
    fn from(x: Address) -> ::core::net::IpAddr {
        match x {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(ipv4) => ::core::net::IpAddr::V4(ipv4),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(ipv6) => ::core::net::IpAddr::V6(ipv6),
        }
    }
}

#[cfg(feature = "ipv4")]
impl From<Ipv4Address> for Address {
    fn from(ipv4: Ipv4Address) -> Address {
        Address::Ipv4(ipv4)
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Address> for Address {
    fn from(addr: Ipv6Address) -> Self {
        Address::Ipv6(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => write!(f, "{addr}"),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => write!(f, "{addr}"),
        }
    }
}

/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum Cidr {
    #[cfg(feature = "ipv4")]
    Ipv4(Ipv4Cidr),
    #[cfg(feature = "ipv6")]
    Ipv6(Ipv6Cidr),
}

impl Cidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given prefix length is invalid for the given address.
    pub const fn new(addr: Address, prefix_len: u8) -> Cidr {
        match addr {
            #[cfg(feature = "ipv4")]
            Address::Ipv4(addr) => Cidr::Ipv4(Ipv4Cidr::new(addr, prefix_len)),
            #[cfg(feature = "ipv6")]
            Address::Ipv6(addr) => Cidr::Ipv6(Ipv6Cidr::new(addr, prefix_len)),
        }
    }

    /// Return the IP address of this CIDR block.
    pub const fn address(&self) -> Address {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::Ipv4(cidr) => Address::Ipv4(cidr.address()),
            #[cfg(feature = "ipv6")]
            Cidr::Ipv6(cidr) => Address::Ipv6(cidr.address()),
        }
    }

    /// Return the prefix length of this CIDR block.
    pub const fn prefix_len(&self) -> u8 {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::Ipv4(cidr) => cidr.prefix_len(),
            #[cfg(feature = "ipv6")]
            Cidr::Ipv6(cidr) => cidr.prefix_len(),
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Address) -> bool {
        match (self, addr) {
            #[cfg(feature = "ipv4")]
            (Cidr::Ipv4(cidr), Address::Ipv4(addr)) => cidr.contains_addr(addr),
            #[cfg(feature = "ipv6")]
            (Cidr::Ipv6(cidr), Address::Ipv6(addr)) => cidr.contains_addr(addr),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Cidr) -> bool {
        match (self, subnet) {
            #[cfg(feature = "ipv4")]
            (Cidr::Ipv4(cidr), Cidr::Ipv4(other)) => cidr.contains_subnet(other),
            #[cfg(feature = "ipv6")]
            (Cidr::Ipv6(cidr), Cidr::Ipv6(other)) => cidr.contains_subnet(other),
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}

#[cfg(feature = "ipv4")]
impl From<Ipv4Cidr> for Cidr {
    fn from(addr: Ipv4Cidr) -> Self {
        Cidr::Ipv4(addr)
    }
}

#[cfg(feature = "ipv6")]
impl From<Ipv6Cidr> for Cidr {
    fn from(addr: Ipv6Cidr) -> Self {
        Cidr::Ipv6(addr)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "ipv4")]
            Cidr::Ipv4(cidr) => write!(f, "{cidr}"),
            #[cfg(feature = "ipv6")]
            Cidr::Ipv6(cidr) => write!(f, "{cidr}"),
        }
    }
}

/// An internet endpoint address.
///
/// `Endpoint` names one peer: both the address and the port are meant to be
/// specified. [`UNSPECIFIED`](Self::UNSPECIFIED) is the one exception, a
/// sentinel for "no endpoint given" where an API defaults it from elsewhere.
/// [`UdpSocket::send_with`](crate::udp::UdpSocket::send_with) takes the socket's
/// connected remote for it.
///
/// See also [`ListenEndpoint`], the endpoint of a *bind*, whose address is
/// optional so that it can match more than one of our addresses.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Endpoint {
    pub addr: Address,
    pub port: u16,
}

impl Endpoint {
    /// The wildcard endpoint: unspecified address, port zero. Not a destination
    /// anything can be sent to, but a sentinel for "no endpoint given".
    #[cfg(feature = "ipv4")]
    pub const UNSPECIFIED: Endpoint = Endpoint {
        addr: Address::Ipv4(Ipv4Address::UNSPECIFIED),
        port: 0,
    };

    /// The wildcard endpoint: unspecified address, port zero. Not a destination
    /// anything can be sent to, but a sentinel for "no endpoint given".
    #[cfg(not(feature = "ipv4"))]
    pub const UNSPECIFIED: Endpoint = Endpoint {
        addr: Address::Ipv6(Ipv6Address::UNSPECIFIED),
        port: 0,
    };

    /// Create an endpoint address from given address and port.
    pub const fn new(addr: Address, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }

    /// Query whether both the address and the port are specified.
    pub fn is_specified(&self) -> bool {
        !self.addr.is_unspecified() && self.port != 0
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::SocketAddr> for Endpoint {
    fn from(x: ::core::net::SocketAddr) -> Endpoint {
        Endpoint {
            addr: x.ip().into(),
            port: x.port(),
        }
    }
}

impl From<Endpoint> for ::core::net::SocketAddr {
    fn from(x: Endpoint) -> ::core::net::SocketAddr {
        ::core::net::SocketAddr::new(x.addr.into(), x.port)
    }
}

impl<T: Into<Address>> From<(T, u16)> for Endpoint {
    fn from((addr, port): (T, u16)) -> Endpoint {
        Endpoint {
            addr: addr.into(),
            port,
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

/// An internet endpoint address for listening.
///
/// In contrast with [`Endpoint`], `ListenEndpoint` allows leaving the address
/// unspecified, in order to listen on a given port at more than one of our
/// addresses. The address field has three states, which are exactly the three
/// ways a bind can be scoped:
///
/// - `None`: any address, of either IP version, a dual-stack bind.
/// - `Some(addr)` with an unspecified address (`0.0.0.0` / `::`): any address
///   of *that* version, and none of the other one.
/// - `Some(addr)` with a concrete address: that address alone.
///
/// An endpoint can be constructed from a port alone, in which case the address
/// is `None`, and from an (address, port) pair, in which case it is `Some`. So
/// `(Ipv4Address::UNSPECIFIED, 80)` is the "any IPv4 address" bind, and
/// `(Ipv6Address::UNSPECIFIED, 80)` the IPv6 one.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct ListenEndpoint {
    pub addr: Option<Address>,
    pub port: u16,
}

impl ListenEndpoint {
    /// The fully wildcard endpoint: any address of any version, port zero.
    pub const UNSPECIFIED: ListenEndpoint = ListenEndpoint { addr: None, port: 0 };

    /// The address, if it is a concrete one, neither absent nor unspecified. That
    /// is, one of our addresses rather than a filter over several.
    pub fn concrete_addr(&self) -> Option<Address> {
        self.addr.filter(|addr| !addr.is_unspecified())
    }

    /// The IP version this endpoint is restricted to, if it is restricted to one.
    pub fn version(&self) -> Option<Version> {
        self.addr.map(|addr| addr.version())
    }

    /// Query whether the endpoint names one concrete address and a nonzero port.
    pub fn is_specified(&self) -> bool {
        self.concrete_addr().is_some() && self.port != 0
    }
}

impl From<u16> for ListenEndpoint {
    fn from(port: u16) -> ListenEndpoint {
        ListenEndpoint { addr: None, port }
    }
}

impl From<Endpoint> for ListenEndpoint {
    fn from(endpoint: Endpoint) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(endpoint.addr),
            port: endpoint.port,
        }
    }
}

#[cfg(all(feature = "ipv4", feature = "ipv6"))]
impl From<::core::net::SocketAddr> for ListenEndpoint {
    fn from(x: ::core::net::SocketAddr) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(x.ip().into()),
            port: x.port(),
        }
    }
}

impl<T: Into<Address>> From<(T, u16)> for ListenEndpoint {
    fn from((addr, port): (T, u16)) -> ListenEndpoint {
        ListenEndpoint {
            addr: Some(addr.into()),
            port,
        }
    }
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(addr) = self.addr {
            write!(f, "{}:{}", addr, self.port)
        } else {
            write!(f, "*:{}", self.port)
        }
    }
}

pub mod checksum {
    use byteorder::{ByteOrder, NetworkEndian};

    use super::*;

    const fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    #[allow(unsafe_code)]
    pub fn data(data: &[u8]) -> u16 {
        // This is the same aligned native-endian scheme as lwIP's
        // LWIP_CHKSUM_ALGORITHM=2. The bulk path reads two Internet-checksum
        // words with each native u32 load. See RFC 1071 section 2(B).
        let mut accum: u32 = 0;
        let mut bytes = data;
        let odd = bytes.as_ptr().addr() & 1 != 0;
        let mut edge_bytes = [0u8; 2];

        // Align the bulk slice. Byte positions here deliberately describe the
        // native in-memory u16 representation, as in lwIP's implementation.
        if odd && !bytes.is_empty() {
            edge_bytes[1] = bytes[0];
            bytes = &bytes[1..];
        }

        // `bytes` now starts on a u16 boundary. Consume at most one u16 to
        // reach the native u32 alignment used by the bulk loop.
        if bytes.len() >= 2 && bytes.as_ptr().addr() & 3 != 0 {
            // SAFETY: the odd prefix above made the pointer u16-aligned and
            // the length check proves that two bytes remain.
            let word = unsafe { bytes.as_ptr().cast::<u16>().read() };
            accum += word as u32;
            bytes = &bytes[2..];
        }

        // Every u32 bit pattern is valid, and the derived slice stays within
        // the original allocation.
        let double_word_count = bytes.len() / 4;
        let double_words = if double_word_count == 0 {
            &[]
        } else {
            // SAFETY: the optional u16 prefix made the pointer u32-aligned.
            // `double_word_count * 4 <= bytes.len()`, and every possible
            // four-byte pattern is a valid u32.
            unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast::<u32>(), double_word_count) }
        };
        let (quad_words, remaining_double_words) = double_words.as_chunks::<4>();
        let mut accum_0 = accum;
        let mut accum_1 = 0u32;
        let mut accum_2 = 0u32;
        let mut accum_3 = 0u32;
        for words in quad_words {
            accum_0 += (words[0] & 0xffff) + (words[0] >> 16);
            accum_1 += (words[1] & 0xffff) + (words[1] >> 16);
            accum_2 += (words[2] & 0xffff) + (words[2] >> 16);
            accum_3 += (words[3] & 0xffff) + (words[3] >> 16);
        }
        accum = accum_0 + accum_1 + accum_2 + accum_3;
        for &double_word in remaining_double_words {
            accum += (double_word & 0xffff) + (double_word >> 16);
        }

        let mut tail = &bytes[double_word_count * 4..];
        if tail.len() >= 2 {
            // SAFETY: the bulk slice is u32-aligned and two bytes remain.
            let word = unsafe { tail.as_ptr().cast::<u16>().read() };
            accum += word as u32;
            tail = &tail[2..];
        }
        if let Some(&last) = tail.first() {
            edge_bytes[0] = last;
        }
        accum += u16::from_ne_bytes(edge_bytes) as u32;

        let mut collapsed = propagate_carries(accum);
        collapsed = propagate_carries(collapsed as u32);
        if odd {
            collapsed = collapsed.swap_bytes();
        }
        collapsed.to_be()
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    #[cfg(feature = "ipv4")]
    pub fn pseudo_header_v4(src_addr: &Ipv4Address, dst_addr: &Ipv4Address, next_header: Protocol, length: u32) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[data(&src_addr.octets()), data(&dst_addr.octets()), data(&proto_len[..])])
    }

    #[cfg(feature = "ipv6")]
    pub fn pseudo_header_v6(src_addr: &Ipv6Address, dst_addr: &Ipv6Address, next_header: Protocol, length: u32) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = next_header.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[data(&src_addr.octets()), data(&dst_addr.octets()), data(&proto_len[..])])
    }

    pub fn pseudo_header(src_addr: &Address, dst_addr: &Address, next_header: Protocol, length: u32) -> u16 {
        match (src_addr, dst_addr) {
            #[cfg(feature = "ipv4")]
            (Address::Ipv4(src_addr), Address::Ipv4(dst_addr)) => {
                pseudo_header_v4(src_addr, dst_addr, next_header, length)
            }
            #[cfg(feature = "ipv6")]
            (Address::Ipv6(src_addr), Address::Ipv6(dst_addr)) => {
                pseudo_header_v6(src_addr, dst_addr, next_header, length)
            }
            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::data;

        fn reference(bytes: &[u8]) -> u16 {
            let mut accum = 0u32;
            let mut chunks = bytes.chunks_exact(2);
            for chunk in &mut chunks {
                accum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            if let Some(&last) = chunks.remainder().first() {
                accum += (last as u32) << 8;
            }
            let sum = (accum >> 16) + (accum & 0xffff);
            ((sum >> 16) + (sum & 0xffff)) as u16
        }

        #[test]
        fn aligned_native_words_match_reference() {
            let mut storage = [0u8; 264];
            for (index, byte) in storage.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
            }

            for offset in 0..8 {
                for length in 0..=255 {
                    let bytes = &storage[offset..offset + length];
                    assert_eq!(data(bytes), reference(bytes), "offset={offset} length={length}");
                }
            }
        }

        #[test]
        fn maximum_ipv4_datagram_matches_reference() {
            let mut storage = vec![0xffu8; 65_542];
            for (index, byte) in storage.iter_mut().enumerate() {
                *byte ^= (index as u8).wrapping_mul(17);
            }

            for offset in 0..8 {
                let bytes = &storage[offset..offset + 65_535];
                assert_eq!(data(bytes), reference(bytes), "offset={offset}");
            }
        }
    }
}

#[cfg(all(test, feature = "ipv4", feature = "ipv6"))]
pub(crate) mod test {
    #![allow(unused)]

    use super::*;
    use crate::wire::{IpAddress, IpCidr, IpProtocol};
    use crate::wire::{Ipv4Address, Ipv6Address};

    #[test]
    fn to_prefix_len_ipv4() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv4Address::new(0, 0, 0, 0));
        test_eq(1, Ipv4Address::new(128, 0, 0, 0));
        test_eq(2, Ipv4Address::new(192, 0, 0, 0));
        test_eq(3, Ipv4Address::new(224, 0, 0, 0));
        test_eq(4, Ipv4Address::new(240, 0, 0, 0));
        test_eq(5, Ipv4Address::new(248, 0, 0, 0));
        test_eq(6, Ipv4Address::new(252, 0, 0, 0));
        test_eq(7, Ipv4Address::new(254, 0, 0, 0));
        test_eq(8, Ipv4Address::new(255, 0, 0, 0));
        test_eq(9, Ipv4Address::new(255, 128, 0, 0));
        test_eq(10, Ipv4Address::new(255, 192, 0, 0));
        test_eq(11, Ipv4Address::new(255, 224, 0, 0));
        test_eq(12, Ipv4Address::new(255, 240, 0, 0));
        test_eq(13, Ipv4Address::new(255, 248, 0, 0));
        test_eq(14, Ipv4Address::new(255, 252, 0, 0));
        test_eq(15, Ipv4Address::new(255, 254, 0, 0));
        test_eq(16, Ipv4Address::new(255, 255, 0, 0));
        test_eq(17, Ipv4Address::new(255, 255, 128, 0));
        test_eq(18, Ipv4Address::new(255, 255, 192, 0));
        test_eq(19, Ipv4Address::new(255, 255, 224, 0));
        test_eq(20, Ipv4Address::new(255, 255, 240, 0));
        test_eq(21, Ipv4Address::new(255, 255, 248, 0));
        test_eq(22, Ipv4Address::new(255, 255, 252, 0));
        test_eq(23, Ipv4Address::new(255, 255, 254, 0));
        test_eq(24, Ipv4Address::new(255, 255, 255, 0));
        test_eq(25, Ipv4Address::new(255, 255, 255, 128));
        test_eq(26, Ipv4Address::new(255, 255, 255, 192));
        test_eq(27, Ipv4Address::new(255, 255, 255, 224));
        test_eq(28, Ipv4Address::new(255, 255, 255, 240));
        test_eq(29, Ipv4Address::new(255, 255, 255, 248));
        test_eq(30, Ipv4Address::new(255, 255, 255, 252));
        test_eq(31, Ipv4Address::new(255, 255, 255, 254));
        test_eq(32, Ipv4Address::new(255, 255, 255, 255));
    }

    #[test]
    fn to_prefix_len_ipv4_error() {
        assert_eq!(None, IpAddress::from(Ipv4Address::new(255, 255, 255, 1)).prefix_len());
    }

    #[test]
    fn to_prefix_len_ipv6() {
        fn test_eq<A: Into<Address>>(prefix_len: u8, mask: A) {
            assert_eq!(Some(prefix_len), mask.into().prefix_len());
        }

        test_eq(0, Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 0));
        test_eq(
            128,
            Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
    }

    #[test]
    fn to_prefix_len_ipv6_error() {
        assert_eq!(
            None,
            IpAddress::from(Ipv6Address::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0, 1)).prefix_len()
        );
    }
}
