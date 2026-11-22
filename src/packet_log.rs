//! Decode a packet and log it, one line per header.
//!
//! [`log_packet`] walks the headers of a packet with the `wire` parsers and logs
//! each one at trace level. Nothing is logged without the `log` or `defmt`
//! feature.
//!
//! With the `packet-log` feature, the stack calls it on every packet it receives
//! and sends.

use crate::driver::DriverBuf;
#[cfg(all(feature = "ipv4", feature = "multicast"))]
use crate::wire::IgmpPacket;
#[cfg(feature = "udp")]
use crate::wire::UdpPacket;
#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
use crate::wire::{ArpHardware, ArpPacket, EthernetAddress, Ipv4Addr};
#[cfg(feature = "dns")]
use crate::wire::{DnsFlags, DnsPacket, DnsQuestion, DnsRecord, DnsRecordData};
#[cfg(feature = "medium-ethernet")]
use crate::wire::{EthernetFrame, EthernetProtocol};
#[cfg(feature = "ipv4")]
use crate::wire::{
    Icmpv4DstUnreachable, Icmpv4Message, Icmpv4Packet, Icmpv4ParamProblem, Icmpv4Redirect, Icmpv4TimeExceeded,
    Ipv4Packet,
};
#[cfg(feature = "ipv6")]
use crate::wire::{
    Icmpv6DstUnreachable, Icmpv6Message, Icmpv6Packet, Icmpv6ParamProblem, Icmpv6TimeExceeded, Ipv6ExtHeader,
    Ipv6OptionsIter, Ipv6Packet,
};
#[cfg(feature = "medium-ieee802154")]
use crate::wire::{
    Ieee802154Address, Ieee802154FrameType, Ieee802154Repr, SixlowpanExtHeaderId, SixlowpanExtHeaderRepr,
    SixlowpanFragRepr, SixlowpanIphcRepr, SixlowpanNextHeader, SixlowpanNhcPacket, SixlowpanPacket,
    SixlowpanUdpNhcRepr,
};
use crate::wire::{IpProtocol, IpVersion};
#[cfg(all(feature = "ipv6", feature = "multicast"))]
use crate::wire::{MLD_ADDRESS_RECORD_LEN, MldAddressRecord};
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
use crate::wire::{NdiscOption, NdiscOptionType};
#[cfg(feature = "tcp")]
use crate::wire::{TcpOption, TcpPacket};

/// The outermost header of a packet given to [`log_packet`].
#[allow(unused)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// An Ethernet frame. Requires the `medium-ethernet` feature.
    #[cfg(feature = "medium-ethernet")]
    Ethernet,
    /// An IP packet of either version. The version is read from the first byte.
    Ip,
    /// An IPv4 packet. Requires the `ipv4` feature.
    #[cfg(feature = "ipv4")]
    Ipv4,
    /// An IPv6 packet. Requires the `ipv6` feature.
    #[cfg(feature = "ipv6")]
    Ipv6,
    /// An ARP packet. Requires the `medium-ethernet` and `ipv4` features.
    #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
    Arp,
    /// An IEEE 802.15.4 frame carrying 6LoWPAN. Requires the `medium-ieee802154` feature.
    #[cfg(feature = "medium-ieee802154")]
    Ieee802154,
}

/// Log a packet at trace level, one line per header.
///
/// `layer` says what the first header in the packet is. Headers are decoded
/// from there down to the transport layer. A header that fails to parse ends
/// the walk with a line saying so.
///
/// The packet is not modified. The parsers need a mutable slice, which is the
/// only reason this takes `&mut`.
pub fn log_packet(buf: &mut DriverBuf, layer: Layer) {
    log_layer(&mut buf[..], layer);
}

fn log_layer(buf: &mut [u8], layer: Layer) {
    match layer {
        #[cfg(feature = "medium-ethernet")]
        Layer::Ethernet => log_ethernet(buf),
        Layer::Ip => log_ip(buf),
        #[cfg(feature = "ipv4")]
        Layer::Ipv4 => log_ipv4(buf),
        #[cfg(feature = "ipv6")]
        Layer::Ipv6 => log_ipv6(buf),
        #[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
        Layer::Arp => log_arp(buf),
        #[cfg(feature = "medium-ieee802154")]
        Layer::Ieee802154 => log_ieee802154(buf),
    }
}

/// Log the MAC header, then walk the 6LoWPAN headers of the payload.
#[cfg(feature = "medium-ieee802154")]
fn log_ieee802154(buf: &mut [u8]) {
    let (repr, header_len) = match Ieee802154Repr::parse(buf) {
        Ok(x) => x,
        Err(_) => {
            trace!("IEEE802.15.4: malformed");
            return;
        }
    };
    trace!("{}", repr);
    if repr.frame_type != Ieee802154FrameType::Data || repr.security_enabled {
        return;
    }
    log_sixlowpan(&mut buf[header_len..], repr.src_addr, repr.dst_addr);
}

/// Log a 6LoWPAN packet: the fragment header if there is one, then the
/// compressed IPv6 header and the compressed headers below it.
///
/// Elided addresses are resolved against the frame's link-layer addresses.
/// An address compressed against an address context cannot be resolved here,
/// and ends the walk.
#[cfg(feature = "medium-ieee802154")]
fn log_sixlowpan(buf: &mut [u8], ll_src: Option<Ieee802154Address>, ll_dst: Option<Ieee802154Address>) {
    let len = buf.len();
    if len == 0 {
        trace!("6LoWPAN: empty");
        return;
    }
    match SixlowpanPacket::dispatch(buf) {
        Ok(SixlowpanPacket::FragmentHeader) => {
            let frag = match SixlowpanFragRepr::parse(buf) {
                Ok(f) => f,
                Err(_) => {
                    trace!("6LoWPAN fragment: malformed");
                    return;
                }
            };
            let header_len = frag.buffer_len();
            if frag.is_first_fragment() {
                trace!(
                    "6LoWPAN FRAG1 size={} tag={} payload={}",
                    frag.size(),
                    frag.tag(),
                    len - header_len
                );
                // Only the first fragment carries the headers. The rest are payload bytes,
                // which mean nothing without the packet they belong to.
                log_sixlowpan(&mut buf[header_len..], ll_src, ll_dst);
            } else {
                trace!(
                    "6LoWPAN FRAGN size={} tag={} offset={} payload={}",
                    frag.size(),
                    frag.tag(),
                    frag.offset() as usize * 8,
                    len - header_len
                );
            }
        }
        Ok(SixlowpanPacket::IphcHeader) => {
            let (iphc, header_len) = match SixlowpanIphcRepr::parse(buf, ll_src, ll_dst, &[]) {
                Ok(x) => x,
                Err(_) => {
                    trace!("6LoWPAN IPHC: malformed, or context-compressed addresses");
                    return;
                }
            };
            trace!(
                "6LoWPAN IPHC src={} dst={} nh={} hlim={} payload={}",
                iphc.src_addr,
                iphc.dst_addr,
                iphc.next_header,
                iphc.hop_limit,
                len - header_len
            );
            if let (Some(ecn), Some(dscp)) = (iphc.ecn, iphc.dscp) {
                trace!("  traffic class dscp={} ecn={}", dscp, ecn);
            }
            if let Some(flow_label) = iphc.flow_label {
                trace!("  flow label {}", flow_label);
            }
            log_sixlowpan_next_header(iphc.next_header, &mut buf[header_len..]);
        }
        Err(_) => trace!("6LoWPAN: unknown dispatch={:#04x} len={}", buf[0], len),
    }
}

/// Log what follows a 6LoWPAN header: either another compressed header, or an
/// uncompressed one, which from here on is an ordinary IPv6 payload.
#[cfg(feature = "medium-ieee802154")]
fn log_sixlowpan_next_header(next_header: SixlowpanNextHeader, buf: &mut [u8]) {
    match next_header {
        SixlowpanNextHeader::Compressed => log_sixlowpan_nhc(buf),
        SixlowpanNextHeader::Uncompressed(protocol) => log_transport(protocol, IpVersion::V6, buf),
    }
}

/// Log one compressed next header (NHC): an IPv6 extension header or a UDP
/// header, then whatever follows it.
#[cfg(feature = "medium-ieee802154")]
fn log_sixlowpan_nhc(buf: &mut [u8]) {
    let len = buf.len();
    if len == 0 {
        trace!("6LoWPAN NHC: empty");
        return;
    }
    match SixlowpanNhcPacket::dispatch(buf) {
        Ok(SixlowpanNhcPacket::ExtHeader) => {
            let (ext, header_len) = match SixlowpanExtHeaderRepr::parse(buf) {
                Ok(x) => x,
                Err(_) => {
                    trace!("6LoWPAN NHC ext header: malformed");
                    return;
                }
            };
            let total_len = header_len + ext.length as usize;
            if total_len > len {
                trace!("6LoWPAN NHC ext header: malformed");
                return;
            }
            trace!(
                "6LoWPAN NHC ext header id={:?} next={} len={}",
                ext.ext_header_id, ext.next_header, ext.length
            );
            // Only these two carry TLV options, the others carry header-specific fields.
            if matches!(
                ext.ext_header_id,
                SixlowpanExtHeaderId::HopByHopHeader | SixlowpanExtHeaderId::DestinationOptionsHeader
            ) {
                for opt in Ipv6OptionsIter::new(&buf[header_len..total_len]) {
                    match opt {
                        Ok((_, ty, data)) => trace!("  option type={} len={}", ty, data.len()),
                        Err(_) => {
                            trace!("  option: malformed");
                            break;
                        }
                    }
                }
            }
            log_sixlowpan_next_header(ext.next_header, &mut buf[total_len..]);
        }
        Ok(SixlowpanNhcPacket::UdpHeader) => {
            let (udp, header_len) = match SixlowpanUdpNhcRepr::parse(buf) {
                Ok(x) => x,
                Err(_) => {
                    trace!("6LoWPAN NHC UDP: malformed");
                    return;
                }
            };
            match udp.checksum {
                Some(checksum) => trace!(
                    "6LoWPAN NHC UDP src={} dst={} checksum={:#06x} payload={}",
                    udp.src_port,
                    udp.dst_port,
                    checksum,
                    len - header_len
                ),
                None => trace!(
                    "6LoWPAN NHC UDP src={} dst={} checksum=elided payload={}",
                    udp.src_port,
                    udp.dst_port,
                    len - header_len
                ),
            }
            #[cfg(feature = "dns")]
            if [udp.src_port, udp.dst_port]
                .iter()
                .any(|&port| port == 53 || port == 5353)
            {
                log_dns(&mut buf[header_len..]);
            }
            #[cfg(not(feature = "dns"))]
            let _ = header_len;
        }
        Err(_) => trace!("6LoWPAN NHC: unknown dispatch={:#04x} len={}", buf[0], len),
    }
}

#[cfg(feature = "medium-ethernet")]
fn log_ethernet(buf: &mut [u8]) {
    let mut frame = match EthernetFrame::new_checked(buf) {
        Ok(f) => f,
        Err(_) => {
            trace!("Ethernet: malformed");
            return;
        }
    };
    let ethertype = frame.ethertype();
    trace!(
        "Ethernet src={} dst={} type={}",
        frame.src_addr(),
        frame.dst_addr(),
        ethertype
    );
    let payload = frame.payload_mut();
    match ethertype {
        #[cfg(feature = "ipv4")]
        EthernetProtocol::Ipv4 => log_ipv4(payload),
        #[cfg(feature = "ipv6")]
        EthernetProtocol::Ipv6 => log_ipv6(payload),
        #[cfg(feature = "ipv4")]
        EthernetProtocol::Arp => log_arp(payload),
        _ => trace!("payload len={}", payload.len()),
    }
}

#[cfg(all(feature = "medium-ethernet", feature = "ipv4"))]
fn log_arp(buf: &mut [u8]) {
    let packet = match ArpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ARP: malformed");
            return;
        }
    };
    if packet.hardware_type() == ArpHardware::Ethernet
        && packet.protocol_type() == EthernetProtocol::Ipv4
        && packet.hardware_len() == 6
        && packet.protocol_len() == 4
    {
        let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        trace!(
            "ARP op={} sha={} spa={} tha={} tpa={}",
            packet.operation(),
            EthernetAddress::from_bytes(packet.source_hardware_addr()),
            ip(packet.source_protocol_addr()),
            EthernetAddress::from_bytes(packet.target_hardware_addr()),
            ip(packet.target_protocol_addr()),
        );
    } else {
        trace!(
            "ARP op={} hw={} proto={} hlen={} plen={}",
            packet.operation(),
            packet.hardware_type(),
            packet.protocol_type(),
            packet.hardware_len(),
            packet.protocol_len(),
        );
    }
}

fn log_ip(buf: &mut [u8]) {
    if buf.is_empty() {
        trace!("IP: empty");
        return;
    }
    match IpVersion::of_packet(buf) {
        #[cfg(feature = "ipv4")]
        Ok(IpVersion::V4) => log_ipv4(buf),
        #[cfg(feature = "ipv6")]
        Ok(IpVersion::V6) => log_ipv6(buf),
        #[allow(unreachable_patterns)]
        _ => trace!("IP: unknown version, len={}", buf.len()),
    }
}

#[cfg(feature = "ipv4")]
fn log_ipv4(buf: &mut [u8]) {
    let mut packet = match Ipv4Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("IPv4: malformed");
            return;
        }
    };
    let proto = packet.next_header();
    let fragment = packet.more_frags() || packet.frag_offset() != 0;
    trace!(
        "IPv4 src={} dst={} proto={} len={} ttl={} id={} dscp={} ecn={} df={} mf={} off={}",
        packet.src_addr(),
        packet.dst_addr(),
        proto,
        packet.total_len(),
        packet.hop_limit(),
        packet.ident(),
        packet.dscp(),
        packet.ecn(),
        packet.dont_frag(),
        packet.more_frags(),
        packet.frag_offset(),
    );
    let payload = packet.payload_mut();
    if fragment {
        trace!("fragment len={}", payload.len());
        return;
    }
    log_transport(proto, IpVersion::V4, payload);
}

#[cfg(feature = "ipv6")]
fn log_ipv6(buf: &mut [u8]) {
    let mut packet = match Ipv6Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("IPv6: malformed");
            return;
        }
    };
    let mut proto = packet.next_header();
    trace!(
        "IPv6 src={} dst={} nh={} plen={} hlim={} tc={} fl={}",
        packet.src_addr(),
        packet.dst_addr(),
        proto,
        packet.payload_len(),
        packet.hop_limit(),
        packet.traffic_class(),
        packet.flow_label(),
    );
    let mut payload = packet.payload_mut();

    // Walk the extension headers. They all share the (next header, length) prefix,
    // except that only Hop-by-Hop and Destination Options carry TLV options.
    loop {
        let has_options = match proto {
            IpProtocol::HopByHop | IpProtocol::Ipv6Opts => true,
            IpProtocol::Ipv6Route | IpProtocol::Ipv6Frag => false,
            _ => break,
        };
        let ext = match Ipv6ExtHeader::new_checked(payload) {
            Ok(e) => e,
            Err(_) => {
                trace!("{}: malformed", proto);
                return;
            }
        };
        let next = ext.next_header();
        let len = ext.header_len();
        trace!("{} next={} len={}", proto, next, len);
        if has_options {
            for opt in Ipv6OptionsIter::new(ext.data()) {
                match opt {
                    Ok((_, ty, data)) => trace!("  option type={} len={}", ty, data.len()),
                    Err(_) => {
                        trace!("  option: malformed");
                        return;
                    }
                }
            }
        }
        proto = next;
        payload = &mut payload[len..];
    }

    log_transport(proto, IpVersion::V6, payload);
}

fn log_transport(proto: IpProtocol, version: IpVersion, payload: &mut [u8]) {
    match (proto, version) {
        #[cfg(feature = "udp")]
        (IpProtocol::Udp, _) => log_udp(payload),
        #[cfg(feature = "tcp")]
        (IpProtocol::Tcp, _) => log_tcp(payload),
        #[cfg(feature = "ipv4")]
        (IpProtocol::Icmp, IpVersion::V4) => log_icmpv4(payload),
        #[cfg(feature = "ipv6")]
        (IpProtocol::Icmpv6, IpVersion::V6) => log_icmpv6(payload),
        #[cfg(all(feature = "ipv4", feature = "multicast"))]
        (IpProtocol::Igmp, IpVersion::V4) => log_igmp(payload),
        (IpProtocol::Ipv6NoNxt, _) => {}
        _ => trace!("{} payload len={}", proto, payload.len()),
    }
}

#[cfg(all(feature = "ipv4", feature = "multicast"))]
fn log_igmp(buf: &mut [u8]) {
    let packet = match IgmpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("IGMP: malformed");
            return;
        }
    };
    trace!(
        "IGMP type={} max_resp_code={} group={}",
        packet.msg_type(),
        packet.max_resp_code(),
        packet.group_addr()
    );
}

#[cfg(feature = "udp")]
fn log_udp(buf: &mut [u8]) {
    #[allow(unused_mut)]
    let mut p = match UdpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("UDP: malformed");
            return;
        }
    };
    trace!(
        "UDP src={} dst={} len={} payload={}",
        p.src_port(),
        p.dst_port(),
        p.len(),
        p.payload().len()
    );
    #[cfg(feature = "dns")]
    if [p.src_port(), p.dst_port()]
        .iter()
        .any(|&port| port == 53 || port == 5353)
    {
        log_dns(p.payload_mut());
    }
}

/// A DNS name in dotted text form, for logging. Labels are copied into a
/// fixed buffer so the name can be printed as one `str`.
#[cfg(feature = "dns")]
struct DnsName {
    buf: [u8; 255],
    len: usize,
}

#[cfg(feature = "dns")]
impl DnsName {
    fn parse(packet: &DnsPacket<'_>, name: &[u8]) -> Option<Self> {
        let mut out = Self { buf: [0; 255], len: 0 };
        for label in packet.parse_name(name) {
            let label = label.ok()?;
            if out.len + label.len() + 1 > out.buf.len() {
                return None;
            }
            out.buf[out.len..out.len + label.len()].copy_from_slice(label);
            out.len += label.len();
            out.buf[out.len] = b'.';
            out.len += 1;
        }
        Some(out)
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<non-utf8>")
    }
}

#[cfg(feature = "dns")]
fn log_dns(buf: &mut [u8]) {
    let packet = match DnsPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("DNS: malformed");
            return;
        }
    };
    trace!(
        "DNS id={:#06x} {} op={} rcode={} flags={:?} qd={} an={} ns={} ar={}",
        packet.transaction_id(),
        if packet.flags().contains(DnsFlags::RESPONSE) {
            "response"
        } else {
            "query"
        },
        packet.opcode(),
        packet.rcode(),
        packet.flags(),
        packet.question_count(),
        packet.answer_record_count(),
        packet.authority_record_count(),
        packet.additional_record_count(),
    );

    let mut payload = packet.payload();
    for _ in 0..packet.question_count() {
        let (rest, q) = match DnsQuestion::parse(payload) {
            Ok(x) => x,
            Err(_) => {
                trace!("  question: malformed");
                return;
            }
        };
        payload = rest;
        match DnsName::parse(&packet, q.name) {
            Some(name) => trace!("  question {} type={}", name.as_str(), q.type_),
            None => trace!("  question <malformed name> type={}", q.type_),
        }
    }

    for (section, count) in [
        ("answer", packet.answer_record_count()),
        ("authority", packet.authority_record_count()),
        ("additional", packet.additional_record_count()),
    ] {
        for _ in 0..count {
            let (rest, r) = match DnsRecord::parse(payload) {
                Ok(x) => x,
                Err(_) => {
                    trace!("  {}: malformed", section);
                    return;
                }
            };
            payload = rest;
            let name = DnsName::parse(&packet, r.name);
            let name = name.as_ref().map(DnsName::as_str).unwrap_or("<malformed name>");
            match r.data {
                #[cfg(feature = "ipv4")]
                DnsRecordData::A(addr) => trace!("  {} {} ttl={} A {}", section, name, r.ttl, addr),
                #[cfg(feature = "ipv6")]
                DnsRecordData::Aaaa(addr) => trace!("  {} {} ttl={} AAAA {}", section, name, r.ttl, addr),
                DnsRecordData::Cname(cname) => match DnsName::parse(&packet, cname) {
                    Some(cname) => trace!("  {} {} ttl={} CNAME {}", section, name, r.ttl, cname.as_str()),
                    None => trace!("  {} {} ttl={} CNAME <malformed name>", section, name, r.ttl),
                },
                DnsRecordData::Other(ty, data) => {
                    trace!("  {} {} ttl={} type={} len={}", section, name, r.ttl, ty, data.len())
                }
            }
        }
    }
}

#[cfg(feature = "tcp")]
fn log_tcp(buf: &mut [u8]) {
    let packet = match TcpPacket::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("TCP: malformed");
            return;
        }
    };

    // Flags as a short letter string, e.g. "SA" for SYN|ACK.
    let mut flags = [0u8; 9];
    let mut n = 0;
    for (set, letter) in [
        (packet.fin(), b'F'),
        (packet.syn(), b'S'),
        (packet.rst(), b'R'),
        (packet.psh(), b'P'),
        (packet.ack(), b'A'),
        (packet.urg(), b'U'),
        (packet.ece(), b'E'),
        (packet.cwr(), b'C'),
        (packet.ns(), b'N'),
    ] {
        if set {
            flags[n] = letter;
            n += 1;
        }
    }
    let flags = core::str::from_utf8(&flags[..n]).unwrap_or("");

    trace!(
        "TCP src={} dst={} flags={} seq={} ack={} win={} urg={} payload={}",
        packet.src_port(),
        packet.dst_port(),
        flags,
        packet.seq_number(),
        packet.ack_number(),
        packet.window_len(),
        packet.urgent_at(),
        packet.payload().len(),
    );

    let mut options = packet.options();
    while !options.is_empty() {
        let (rest, option) = match TcpOption::parse(options) {
            Ok(x) => x,
            Err(_) => {
                trace!("  option: malformed");
                return;
            }
        };
        match option {
            TcpOption::EndOfList => break,
            TcpOption::NoOperation => {}
            option => trace!("  option {:?}", option),
        }
        options = rest;
    }
}

#[cfg(feature = "ipv4")]
fn log_icmpv4(buf: &mut [u8]) {
    let mut packet = match Icmpv4Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ICMPv4: malformed");
            return;
        }
    };
    let ty = packet.msg_type();
    let code = packet.msg_code();
    match ty {
        Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply => trace!(
            "ICMPv4 type={} ident={} seq={} payload={}",
            ty,
            packet.echo_ident(),
            packet.echo_seq_no(),
            packet.data().len()
        ),
        Icmpv4Message::DstUnreachable => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4DstUnreachable::from(code))
        }
        Icmpv4Message::Redirect => trace!("ICMPv4 type={} code={}", ty, Icmpv4Redirect::from(code)),
        Icmpv4Message::TimeExceeded => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4TimeExceeded::from(code))
        }
        Icmpv4Message::ParamProblem => {
            trace!("ICMPv4 type={} code={}", ty, Icmpv4ParamProblem::from(code))
        }
        _ => trace!("ICMPv4 type={} code={} payload={}", ty, code, packet.data().len()),
    }
    if ty.is_error() {
        log_ipv4(packet.data_mut());
    }
}

#[cfg(feature = "ipv6")]
fn log_icmpv6(buf: &mut [u8]) {
    let mut packet = match Icmpv6Packet::new_checked(buf) {
        Ok(p) => p,
        Err(_) => {
            trace!("ICMPv6: malformed");
            return;
        }
    };
    let ty = packet.msg_type();
    let code = packet.msg_code();
    match ty {
        Icmpv6Message::EchoRequest | Icmpv6Message::EchoReply => trace!(
            "ICMPv6 type={} ident={} seq={} payload={}",
            ty,
            packet.echo_ident(),
            packet.echo_seq_no(),
            packet.payload().len()
        ),
        Icmpv6Message::DstUnreachable => {
            trace!("ICMPv6 type={} code={}", ty, Icmpv6DstUnreachable::from(code))
        }
        Icmpv6Message::PktTooBig => trace!("ICMPv6 type={} mtu={}", ty, packet.pkt_too_big_mtu()),
        Icmpv6Message::TimeExceeded => {
            trace!("ICMPv6 type={} code={}", ty, Icmpv6TimeExceeded::from(code))
        }
        Icmpv6Message::ParamProblem => trace!(
            "ICMPv6 type={} code={} ptr={}",
            ty,
            Icmpv6ParamProblem::from(code),
            packet.param_problem_ptr()
        ),
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        Icmpv6Message::RouterSolicit => trace!("ICMPv6 type={}", ty),
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        Icmpv6Message::RouterAdvert => trace!(
            "ICMPv6 type={} hop_limit={} flags={:?}",
            ty,
            packet.current_hop_limit(),
            packet.router_flags()
        ),
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        Icmpv6Message::NeighborSolicit => trace!("ICMPv6 type={} target={}", ty, packet.target_addr()),
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        Icmpv6Message::NeighborAdvert => trace!(
            "ICMPv6 type={} target={} flags={:?}",
            ty,
            packet.target_addr(),
            packet.neighbor_flags()
        ),
        #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
        Icmpv6Message::Redirect => trace!(
            "ICMPv6 type={} target={} dest={}",
            ty,
            packet.target_addr(),
            packet.dest_addr()
        ),
        #[cfg(feature = "multicast")]
        Icmpv6Message::MldQuery => trace!(
            "ICMPv6 type={} max_resp_code={} mcast_addr={} num_srcs={}",
            ty,
            packet.max_resp_code(),
            packet.mcast_addr(),
            packet.num_srcs()
        ),
        #[cfg(feature = "multicast")]
        Icmpv6Message::MldReport => trace!("ICMPv6 type={} records={}", ty, packet.nr_mcast_addr_rcrds()),
        _ => trace!("ICMPv6 type={} code={} payload={}", ty, code, packet.payload().len()),
    }

    if ty.is_error() {
        log_ipv6(packet.payload_mut());
        return;
    }

    #[cfg(feature = "multicast")]
    if ty == Icmpv6Message::MldReport {
        log_mld_records(packet.payload_mut());
    }

    #[cfg(any(feature = "medium-ethernet", feature = "medium-ieee802154"))]
    if matches!(
        ty,
        Icmpv6Message::RouterSolicit
            | Icmpv6Message::RouterAdvert
            | Icmpv6Message::NeighborSolicit
            | Icmpv6Message::NeighborAdvert
            | Icmpv6Message::Redirect
    ) {
        log_ndisc_options(packet.payload_mut());
    }
}

#[cfg(all(feature = "ipv6", feature = "multicast"))]
fn log_mld_records(mut buf: &mut [u8]) {
    while !buf.is_empty() {
        let record = match MldAddressRecord::new_checked(buf) {
            Ok(r) => r,
            Err(_) => {
                trace!("  mld record: malformed");
                return;
            }
        };
        trace!(
            "  mld record type={} addr={} srcs={}",
            record.record_type(),
            record.mcast_addr(),
            record.num_srcs()
        );
        // Each source is an address, the auxiliary data length is in 32-bit words.
        let len = MLD_ADDRESS_RECORD_LEN + record.num_srcs() as usize * 16 + record.aux_data_len() as usize * 4;
        if len > buf.len() {
            trace!("  mld record: malformed");
            return;
        }
        buf = &mut buf[len..];
    }
}

#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
fn log_ndisc_options(mut buf: &mut [u8]) {
    while !buf.is_empty() {
        let opt = match NdiscOption::new_checked(buf) {
            Ok(o) => o,
            Err(_) => {
                trace!("  ndisc option: malformed");
                return;
            }
        };
        let ty = opt.option_type();
        let len = opt.data_len() as usize * 8;
        match ty {
            NdiscOptionType::SourceLinkLayerAddr | NdiscOptionType::TargetLinkLayerAddr => {
                trace!("  ndisc option {} addr={}", ty, opt.link_layer_addr())
            }
            NdiscOptionType::PrefixInformation => trace!(
                "  ndisc option {} prefix={}/{} flags={:?}",
                ty,
                opt.prefix(),
                opt.prefix_len(),
                opt.prefix_flags()
            ),
            NdiscOptionType::Mtu => trace!("  ndisc option {} mtu={}", ty, opt.mtu()),
            _ => trace!("  ndisc option {} len={}", ty, len),
        }
        // `new_checked` guarantees `len <= buf.len()`.
        buf = &mut buf[len..];
    }
}

#[cfg(all(test, feature = "dns", feature = "ipv4"))]
mod test {
    use super::*;

    /// Decoding a CNAME + A response must walk every record without panicking.
    #[test]
    fn test_log_dns() {
        let mut bytes = [
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x08, 0x66,
            0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69,
            0x6e, 0x69, 0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
        ];
        log_dns(&mut bytes);
        let packet = DnsPacket::new_checked(&mut bytes).unwrap();
        let name = DnsName::parse(&packet, &[0xc0, 0x2e]).unwrap();
        assert_eq!(name.as_str(), "star-mini.c10r.facebook.com.");
        // Truncated: must report malformed, not panic.
        log_dns(&mut [
            0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
        ]);
    }
}

#[cfg(all(test, feature = "medium-ethernet", feature = "ipv4"))]
mod test_ethernet {
    use super::*;

    /// An Ethernet frame with an unknown ethertype, and truncated at every
    /// length: walked without panicking. (The old stack's tracer printed
    /// "EthernetII src=00-01-02-03-04-05 dst=05-04-03-02-01-00 type=0x0000".)
    #[test]
    fn test_log_ethernet() {
        let mut frame = [
            0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0xaa, 0xbb,
        ];
        log_ethernet(&mut frame);
        for len in 0..frame.len() {
            log_ethernet(&mut frame.clone()[..len]);
        }
    }

    /// An ARP request inside an Ethernet frame, whole and truncated.
    #[test]
    fn test_log_arp() {
        let mut frame = vec![
            0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x06,
        ];
        frame.extend_from_slice(&[
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21, 0x22, 0x23, 0x24,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x41, 0x42, 0x43, 0x44,
        ]);
        log_ethernet(&mut frame);
        for len in 0..frame.len() {
            log_ethernet(&mut frame.clone()[..len]);
        }
    }

    /// A bare IPv4 header with an unknown protocol (the old tracer printed
    /// "IPv4 src=10.0.0.1 dst=10.0.0.2 proto=0xff"), whole and truncated, on
    /// its own and inside an Ethernet frame.
    #[test]
    fn test_log_ipv4() {
        let mut packet = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0xff, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00,
            0x00, 0x02,
        ];
        Ipv4Packet::new_unchecked(&mut packet[..]).fill_checksum();
        log_ipv4(&mut packet);
        log_ip(&mut packet);
        for len in 0..packet.len() {
            log_ipv4(&mut packet.clone()[..len]);
            log_ip(&mut packet.clone()[..len]);
        }

        let mut frame = vec![
            0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x00,
        ];
        frame.extend_from_slice(&packet);
        log_ethernet(&mut frame);
        for len in 0..frame.len() {
            log_ethernet(&mut frame.clone()[..len]);
        }
    }
}

#[cfg(all(test, feature = "medium-ieee802154"))]
mod test_sixlowpan {
    use super::*;

    /// The whole compressed header chain of a first fragment must be walked
    /// without panicking: MAC, FRAG1, IPHC, NHC UDP.
    #[test]
    fn test_log_sixlowpan_frag() {
        let mut frame = [
            0x41, 0xcc, 0x92, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0xd9, 0x3e, 0x08, 0x28, 0x2f,
            0x82, 0x93, 0x32, 0xc1, 0x33, 0x00, 0x3f, 0x6e, 0x33, 0x02, 0x35, 0x3d, 0xf0, 0xd2, 0x5f, 0x1b, 0x39, 0xb4,
            0x6b, 0x4c, 0x6f, 0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72,
            0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c,
        ];
        log_ieee802154(&mut frame);

        // Truncated at every length: must report malformed, not panic.
        for len in 0..frame.len() {
            log_ieee802154(&mut frame.clone()[..len]);
        }
    }

    /// An NHC extension header followed by another compressed header.
    #[test]
    fn test_log_sixlowpan_nhc_ext_header() {
        let mut bytes = [0xe2, 0x3a, 0x6, 0x3, 0x0, 0xff, 0x0, 0x0, 0x0];
        log_sixlowpan_nhc(&mut bytes);
        for len in 0..bytes.len() {
            log_sixlowpan_nhc(&mut bytes.clone()[..len]);
        }
    }

    /// A compressed UDP header on its own.
    #[test]
    fn test_log_sixlowpan_nhc_udp() {
        let mut bytes = [0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4];
        log_sixlowpan_nhc(&mut bytes);
        for len in 0..bytes.len() {
            log_sixlowpan_nhc(&mut bytes.clone()[..len]);
        }
    }
}
