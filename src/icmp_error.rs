//! Delivery of ICMP error messages to the sockets whose packets provoked them.
//!
//! When an ICMP error (destination unreachable, packet too big, time exceeded, ...)
//! arrives (from the network or generated locally when neighbor resolution fails)
//! it contains a "quoted" packet inside we can use to identify which socket was the cause.

use crate::error::IcmpError;
#[cfg(feature = "tcp")]
use crate::wire::TcpSeqNumber;
#[cfg(all(feature = "ipv4", any(feature = "udp", feature = "tcp")))]
use crate::wire::{IPV4_HEADER_LEN, Icmpv4DstUnreachable, Icmpv4Message, Ipv4Packet};
#[cfg(all(feature = "ipv6", any(feature = "udp", feature = "tcp")))]
use crate::wire::{IPV6_HEADER_LEN, Icmpv6DstUnreachable, Icmpv6Message, Ipv6ExtHeader, Ipv6Packet};
#[cfg(any(feature = "udp", feature = "tcp"))]
use crate::wire::{IpAddr, IpProtocol, IpVersion};

impl IcmpError {
    /// Condense an ICMPv4 error message's type and code, `None` if the message is
    /// not an error to be delivered to sockets (informational messages, redirects).
    #[cfg(all(feature = "ipv4", any(feature = "udp", feature = "tcp")))]
    pub(crate) fn from_icmpv4(msg_type: Icmpv4Message, msg_code: u8) -> Option<IcmpError> {
        match msg_type {
            Icmpv4Message::DstUnreachable => Some(match Icmpv4DstUnreachable(msg_code) {
                Icmpv4DstUnreachable::NetUnreachable
                | Icmpv4DstUnreachable::DstNetUnknown
                | Icmpv4DstUnreachable::NetUnreachToS => IcmpError::NetUnreachable,
                Icmpv4DstUnreachable::HostUnreachable
                | Icmpv4DstUnreachable::DstHostUnknown
                | Icmpv4DstUnreachable::SrcHostIsolated
                | Icmpv4DstUnreachable::HostUnreachToS => IcmpError::HostUnreachable,
                Icmpv4DstUnreachable::ProtoUnreachable => IcmpError::ProtoUnreachable,
                Icmpv4DstUnreachable::PortUnreachable => IcmpError::PortUnreachable,
                Icmpv4DstUnreachable::FragRequired => IcmpError::PacketTooBig,
                _ => IcmpError::Other,
            }),
            Icmpv4Message::TimeExceeded | Icmpv4Message::ParamProblem | Icmpv4Message::SourceQuench => {
                Some(IcmpError::Other)
            }
            // Redirects are routing hints, not errors. Everything else is
            // informational.
            _ => None,
        }
    }

    /// Condense an ICMPv6 error message's type and code, `None` if the message is
    /// not an error to be delivered to sockets.
    #[cfg(all(feature = "ipv6", any(feature = "udp", feature = "tcp")))]
    pub(crate) fn from_icmpv6(msg_type: Icmpv6Message, msg_code: u8) -> Option<IcmpError> {
        match msg_type {
            Icmpv6Message::DstUnreachable => Some(match Icmpv6DstUnreachable(msg_code) {
                Icmpv6DstUnreachable::NoRoute | Icmpv6DstUnreachable::RejectRoute => IcmpError::NetUnreachable,
                Icmpv6DstUnreachable::AddrUnreachable | Icmpv6DstUnreachable::BeyondScope => IcmpError::HostUnreachable,
                Icmpv6DstUnreachable::PortUnreachable => IcmpError::PortUnreachable,
                _ => IcmpError::Other,
            }),
            Icmpv6Message::PktTooBig => Some(IcmpError::PacketTooBig),
            // RFC 4443 §2.4(a): an error of a type we do not know is still passed
            // to the process whose packet caused it.
            msg_type if msg_type.is_error() => Some(IcmpError::Other),
            _ => None,
        }
    }
}

/// The flow identity parsed out of the packet quoted in an ICMP error message.
///
/// The quoted packet is one *we sent*: its source is the local end of the flow,
/// its destination the remote end.
#[cfg(any(feature = "udp", feature = "tcp"))]
pub(crate) struct QuotedPacket {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: IpProtocol,
    pub src_port: u16,
    pub dst_port: u16,
    /// The first 4 bytes past the ports, as a TCP sequence number. Only
    /// meaningful when `protocol` is TCP (for UDP these bytes are the length and
    /// checksum fields).
    #[cfg(feature = "tcp")]
    pub tcp_seq: TcpSeqNumber,
}

/// Parse the packet quoted in an ICMP error message.
///
/// ICMP errors quote the offending packet's IP header plus at least 8 bytes of its
/// payload, which is enough for the ports (and, for TCP, the sequence number) that
/// identify the flow. Returns `None` if the quote is too truncated or malformed to
/// identify one.
#[cfg(any(feature = "udp", feature = "tcp"))]
pub(crate) fn parse_quoted_packet(quote: &mut [u8]) -> Option<QuotedPacket> {
    let (src_addr, dst_addr, protocol, l4_offset): (IpAddr, IpAddr, _, _) = match IpVersion::of_packet(quote).ok()? {
        #[cfg(feature = "ipv4")]
        IpVersion::V4 => {
            if quote.len() < IPV4_HEADER_LEN {
                return None;
            }
            let packet = Ipv4Packet::new_unchecked(quote);
            let header_len = packet.header_len() as usize;
            if header_len < IPV4_HEADER_LEN {
                return None;
            }
            (
                packet.src_addr().into(),
                packet.dst_addr().into(),
                packet.next_header(),
                header_len,
            )
        }
        #[cfg(feature = "ipv6")]
        IpVersion::V6 => {
            if quote.len() < IPV6_HEADER_LEN {
                return None;
            }
            let packet = Ipv6Packet::new_unchecked(quote);
            let src_addr = packet.src_addr();
            let dst_addr = packet.dst_addr();
            let mut protocol = packet.next_header();
            let mut l4_offset = IPV6_HEADER_LEN;
            if protocol == IpProtocol::HopByHop {
                let ext = Ipv6ExtHeader::new_checked(&quote[IPV6_HEADER_LEN..]).ok()?;
                protocol = ext.next_header();
                l4_offset += ext.header_len();
            }
            (src_addr.into(), dst_addr.into(), protocol, l4_offset)
        }
    };

    // The ports (and TCP sequence number) sit in the first 8 bytes of the quoted
    // L4 header, for both UDP and TCP.
    let l4 = quote.get(l4_offset..l4_offset + 8)?;
    Some(QuotedPacket {
        src_addr,
        dst_addr,
        protocol,
        src_port: u16::from_be_bytes([l4[0], l4[1]]),
        dst_port: u16::from_be_bytes([l4[2], l4[3]]),
        #[cfg(feature = "tcp")]
        tcp_seq: TcpSeqNumber(i32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]])),
    })
}

#[cfg(all(test, feature = "ipv4", feature = "ipv6", any(feature = "udp", feature = "tcp")))]
mod test {
    use super::*;
    use crate::wire::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_mapping() {
        assert_eq!(
            IcmpError::from_icmpv4(Icmpv4Message::DstUnreachable, 3),
            Some(IcmpError::PortUnreachable)
        );
        assert_eq!(
            IcmpError::from_icmpv4(Icmpv4Message::DstUnreachable, 1),
            Some(IcmpError::HostUnreachable)
        );
        assert_eq!(IcmpError::from_icmpv4(Icmpv4Message::EchoRequest, 0), None);
        assert_eq!(IcmpError::from_icmpv4(Icmpv4Message::Redirect, 0), None);
        assert_eq!(
            IcmpError::from_icmpv6(Icmpv6Message::DstUnreachable, 4),
            Some(IcmpError::PortUnreachable)
        );
        assert_eq!(
            IcmpError::from_icmpv6(Icmpv6Message::PktTooBig, 0),
            Some(IcmpError::PacketTooBig)
        );
        assert_eq!(IcmpError::from_icmpv6(Icmpv6Message::EchoReply, 0), None);
    }

    #[test]
    fn test_parse_quoted_truncated() {
        // A full IPv4 header but only 4 bytes of L4: not enough to identify a flow.
        let mut quote = vec![0u8; IPV4_HEADER_LEN + 4];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut quote[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(Ipv4Addr::new(10, 0, 0, 1));
            ip.set_dst_addr(Ipv4Addr::new(10, 0, 0, 2));
        }
        assert!(parse_quoted_packet(&mut quote).is_none());

        let mut quote = vec![0u8; IPV6_HEADER_LEN - 1];
        quote[0] = 6 << 4;
        assert!(parse_quoted_packet(&mut quote).is_none());
    }

    #[test]
    fn test_parse_quoted_v6_hop_by_hop() {
        let mut quote = vec![0u8; IPV6_HEADER_LEN + 8 + 8];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut quote[..]);
            ip.set_version(6);
            ip.set_next_header(IpProtocol::HopByHop);
            ip.set_src_addr(Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1));
            ip.set_dst_addr(Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2));
        }
        // Hop-by-hop: next header UDP, length 0, PadN(4).
        quote[IPV6_HEADER_LEN..IPV6_HEADER_LEN + 8].copy_from_slice(&[0x11, 0x00, 0x01, 0x04, 0, 0, 0, 0]);
        // UDP ports.
        quote[IPV6_HEADER_LEN + 8..IPV6_HEADER_LEN + 12].copy_from_slice(&[0x12, 0x34, 0x00, 0x35]);

        let parsed = parse_quoted_packet(&mut quote).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Udp);
        assert_eq!(parsed.src_port, 0x1234);
        assert_eq!(parsed.dst_port, 53);
    }
}
