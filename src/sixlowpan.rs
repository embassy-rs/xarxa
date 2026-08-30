//! IEEE 802.15.4 interfaces carrying 6LoWPAN (feature `medium-ieee802154`).
//!
//! The medium is a link layer like Ethernet: ingress turns a frame into a
//! plain IPv6 packet before the core sees it, egress takes the finished IPv6
//! packet and turns it into a frame. Compression (RFC 6282) and decompression
//! happen in place, in the packet's own buffer: the compressed header chain is
//! written into the space the uncompressed one occupied, and the other way
//! around, with the headroom taking up the difference.

use crate::config::SIXLOWPAN_ADDRESS_CONTEXT_COUNT;
use crate::driver::PacketBuf;
use crate::iface::{Iface, IfaceHandle, IfaceState};
use crate::rand::Rand;
use crate::stack::{Stack, StackInner};
use crate::storage::{Full, Vec};
use crate::wire::ip::checksum;
use crate::wire::*;

/// The largest IPHC header this crate emits: the base, next header, hop limit,
/// and two full addresses. The traffic class, flow label and context
/// identifier are never carried.
#[cfg(not(feature = "sixlowpan-fragmentation"))]
const IPHC_MAX_EMITTED_LEN: usize = 2 + 1 + 1 + 16 + 16;

/// The most compressed extension headers one packet may carry: hop-by-hop,
/// routing and destination options.
const MAX_NHC_EXT_HEADERS: usize = 3;

/// The IP MTU of an 802.15.4 interface whose frames hold `link_mtu` bytes.
///
/// With fragmentation, the IPv6 minimum MTU: bigger packets are fragmented.
/// Without it, what fits in one frame after the worst-case compression: the
/// MAC header and the largest IPHC header this crate emits taken out, the
/// IPv6 header it replaces put back.
pub(crate) fn ip_mtu(link_mtu: usize) -> usize {
    #[cfg(feature = "sixlowpan-fragmentation")]
    {
        let _ = link_mtu;
        IPV6_MIN_MTU
    }
    #[cfg(not(feature = "sixlowpan-fragmentation"))]
    {
        (link_mtu + IPV6_HEADER_LEN).saturating_sub(IEEE802154_MAX_HEADER_LEN + IPHC_MAX_EMITTED_LEN)
    }
}

/// The per-interface 6LoWPAN state.
pub(crate) struct State {
    /// The PAN the interface is on. `None` accepts every PAN.
    pub pan_id: Option<Ieee802154Pan>,
    /// The sequence number of the next frame.
    pub sequence_no: u8,
    /// The address contexts decompression may refer to, by context identifier.
    pub sixlowpan_address_context: Vec<SixlowpanAddressContext, SIXLOWPAN_ADDRESS_CONTEXT_COUNT>,
    /// The datagram tag of the next fragmented packet.
    #[cfg(feature = "sixlowpan-fragmentation")]
    pub tag: u16,
}

impl State {
    pub(crate) fn new(rand: &mut Rand) -> Self {
        #[cfg(not(feature = "sixlowpan-fragmentation"))]
        let _ = &rand;
        Self {
            pan_id: None,
            sequence_no: (rand.rand_u32() & 0xff) as u8,
            sixlowpan_address_context: Vec::new(),
            #[cfg(feature = "sixlowpan-fragmentation")]
            tag: rand.rand_u16(),
        }
    }

    /// Return the next IEEE802.15.4 sequence number.
    pub(crate) fn next_ieee802154_seq_number(&mut self) -> u8 {
        let no = self.sequence_no;
        self.sequence_no = self.sequence_no.wrapping_add(1);
        no
    }

    /// Get the next tag for a 6LoWPAN fragment.
    #[cfg(feature = "sixlowpan-fragmentation")]
    pub(crate) fn get_sixlowpan_fragment_tag(&mut self) -> u16 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        tag
    }
}

impl Iface<'_, '_> {
    /// The PAN identifier of an IEEE 802.15.4 interface, `None` for any PAN.
    pub fn pan_id(&self) -> Option<Ieee802154Pan> {
        self.state().sixlowpan.pan_id
    }

    /// Set the PAN identifier of an IEEE 802.15.4 interface.
    ///
    /// With a PAN set, frames for another PAN are dropped, except broadcast
    /// ones. With `None`, the default, frames for every PAN are accepted.
    /// Sent frames carry the PAN, or a zero PAN with `None`.
    ///
    /// Does nothing on other media.
    pub fn set_pan_id(&mut self, pan_id: Option<Ieee802154Pan>) {
        self.state_mut().sixlowpan.pan_id = pan_id;
    }

    /// The 6LoWPAN address contexts, by context identifier.
    pub fn sixlowpan_address_context(&self) -> &[SixlowpanAddressContext] {
        &self.state().sixlowpan.sixlowpan_address_context
    }

    /// Replace the 6LoWPAN address contexts.
    ///
    /// Received packets whose addresses are compressed against a context
    /// identifier are resolved with the context at that index. Sent packets
    /// never use contexts.
    ///
    /// Errors:
    /// - `Full` if the contexts do not fit. Only possible without the `alloc`
    ///   feature, where the limit is
    ///   [`SIXLOWPAN_ADDRESS_CONTEXT_COUNT`].
    ///   The interface is left unchanged.
    pub fn set_sixlowpan_address_context(
        &mut self,
        contexts: impl IntoIterator<Item = SixlowpanAddressContext>,
    ) -> core::result::Result<(), Full> {
        let mut new: Vec<SixlowpanAddressContext, SIXLOWPAN_ADDRESS_CONTEXT_COUNT> = Vec::new();
        new.try_extend(contexts)?;
        self.state_mut().sixlowpan.sixlowpan_address_context = new;
        Ok(())
    }
}

// Ingress.
impl Stack<'_> {
    pub(crate) fn process_ieee802154(&mut self, iface: IfaceHandle, mut buf: PacketBuf) {
        let (ieee802154_repr, header_len) = check!(Ieee802154Repr::parse(&buf));

        if ieee802154_repr.frame_type != Ieee802154FrameType::Data {
            return;
        }

        // Link-layer security is not supported: the payload is ciphertext.
        if ieee802154_repr.security_enabled {
            trace!("IEEE802.15.4: dropping frame with security enabled");
            return;
        }

        // Drop frames when the user has set a PAN id and the PAN id from frame is not equal to this
        // When the user didn't set a PAN id (so it is None), then we accept all PAN id's.
        // We always accept the broadcast PAN id.
        let pan_id = self.ifaces.get(iface.index()).sixlowpan.pan_id;
        if pan_id.is_some()
            && ieee802154_repr.dst_pan_id != pan_id
            && ieee802154_repr.dst_pan_id != Some(Ieee802154Pan::BROADCAST)
        {
            debug!(
                "IEEE802.15.4: dropping {:?} because not our PAN id (or not broadcast)",
                ieee802154_repr
            );
            return;
        }

        buf.pull_front(header_len);
        self.process_sixlowpan(iface, &ieee802154_repr, buf)
    }

    fn process_sixlowpan(&mut self, iface: IfaceHandle, ieee802154_repr: &Ieee802154Repr, mut buf: PacketBuf) {
        let buf = match check!(SixlowpanPacket::dispatch(&buf)) {
            #[cfg(not(feature = "sixlowpan-reassembly"))]
            SixlowpanPacket::FragmentHeader => {
                debug!(
                    "Reassembly is not supported, \
                    use the `sixlowpan-reassembly` feature to add support."
                );
                return;
            }
            #[cfg(feature = "sixlowpan-reassembly")]
            SixlowpanPacket::FragmentHeader => {
                let Some(buf) = self.process_sixlowpan_fragment(iface, ieee802154_repr, buf) else {
                    return;
                };
                buf
            }
            SixlowpanPacket::IphcHeader => {
                let address_context = &self.ifaces.get(iface.index()).sixlowpan.sixlowpan_address_context;
                if sixlowpan_to_ipv6(
                    &mut buf,
                    ieee802154_repr.src_addr,
                    ieee802154_repr.dst_addr,
                    address_context,
                    None,
                )
                .is_err()
                {
                    debug!("sixlowpan decompress failed");
                    return;
                }
                buf
            }
        };

        self.process_ipv6(
            iface,
            Some(HardwareAddress::Ieee802154(
                ieee802154_repr.src_addr.unwrap_or(Ieee802154Address::Absent),
            )),
            buf,
        )
    }
}

/// A compressed extension header found by the parse pass of
/// [`sixlowpan_to_ipv6`].
#[derive(Clone, Copy)]
struct ExtInfo {
    /// The next header the IPv6 extension header names.
    next_header: IpProtocol,
    /// The offset of the header-specific data in the compressed packet.
    data_offset: usize,
    /// The length of the header-specific data.
    data_len: usize,
}

/// The length of the IPv6 extension header that carries `data_len` bytes of
/// header-specific data: the 2-byte prefix plus the data, padded to a multiple
/// of 8 (RFC 6282 §4.2).
fn ext_header_len(data_len: usize) -> usize {
    (2 + data_len).div_ceil(8) * 8
}

/// Decompress a 6LoWPAN packet into an IPv6 packet, in place.
///
/// `buf` starts at the IPHC header. On success it starts at the IPv6 header.
/// The uncompressed header chain is longer than the compressed one, so it is
/// written forward into the headroom after a parse pass has recorded where
/// everything is; the headroom is made if it is short.
///
/// `total_len` is the length of the whole IPv6 packet when this is the first
/// fragment of one, since the payload length and the UDP length fields can
/// not be measured then. `None` for a complete packet.
pub(crate) fn sixlowpan_to_ipv6(
    buf: &mut PacketBuf,
    ll_src_addr: Option<Ieee802154Address>,
    ll_dst_addr: Option<Ieee802154Address>,
    address_context: &[SixlowpanAddressContext],
    total_len: Option<usize>,
) -> Result<()> {
    // Parse everything first. The write pass below overwrites the compressed
    // headers, so nothing may be read from them after it starts.
    let (iphc_repr, iphc_len) = SixlowpanIphcRepr::parse(buf, ll_src_addr, ll_dst_addr, address_context)?;
    let first_next_header = decompress_next_header(iphc_repr.next_header, &buf[iphc_len..])?;

    let mut exts = [ExtInfo {
        next_header: IpProtocol::Ipv6NoNxt,
        data_offset: 0,
        data_len: 0,
    }; MAX_NHC_EXT_HEADERS];
    let mut n_ext = 0;
    let mut udp = None;
    let mut offset = iphc_len;
    let mut next_header = Some(iphc_repr.next_header);

    while let Some(nh) = next_header {
        match nh {
            SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(&buf[offset..])? {
                SixlowpanNhcPacket::ExtHeader => {
                    let (ext_repr, hdr_len) = SixlowpanExtHeaderRepr::parse(&buf[offset..])?;
                    let data_len = ext_repr.length as usize;
                    if offset + hdr_len + data_len > buf.len() {
                        return Err(Error);
                    }
                    let nh = decompress_next_header(ext_repr.next_header, &buf[offset + hdr_len + data_len..])?;
                    if n_ext == MAX_NHC_EXT_HEADERS {
                        return Err(Error);
                    }
                    exts[n_ext] = ExtInfo {
                        next_header: nh,
                        data_offset: offset + hdr_len,
                        data_len,
                    };
                    n_ext += 1;
                    next_header = Some(ext_repr.next_header);
                    offset += hdr_len + data_len;
                }
                SixlowpanNhcPacket::UdpHeader => {
                    let (udp_repr, hdr_len) = SixlowpanUdpNhcRepr::parse(&buf[offset..])?;
                    udp = Some(udp_repr);
                    offset += hdr_len;
                    next_header = None;
                }
            },
            // Whatever follows is carried verbatim.
            SixlowpanNextHeader::Uncompressed(_) => next_header = None,
        }
    }

    // The compressed header chain ends here.
    let compressed_len = offset;

    // Size the uncompressed chain.
    let mut uncompressed_len = IPV6_HEADER_LEN;
    for ext in &exts[..n_ext] {
        uncompressed_len += ext_header_len(ext.data_len);
    }
    if udp.is_some() {
        uncompressed_len += UDP_HEADER_LEN;
    }

    // Make room. The uncompressed chain is always longer: the IPHC header
    // alone frees at least 38 bytes, and a compressed extension header is at
    // most 1 byte shorter than its IPv6 form.
    let grow = uncompressed_len.checked_sub(compressed_len).ok_or(Error)?;
    if !buf.ensure_headroom(grow) {
        return Err(Error);
    }
    buf.push_front(grow);
    // Everything recorded above moved by `grow`. The payload, at the end of
    // the compressed chain, now sits exactly where the uncompressed chain ends.

    let packet_len = total_len.unwrap_or(buf.len());
    if packet_len < uncompressed_len {
        return Err(Error);
    }

    // Write forward. Each header's data is moved to its place before the
    // header bytes are written around it. The write of one header never
    // reaches the data of the next one that has not moved yet.
    {
        let mut ipv6 = Ipv6Packet::new_unchecked(&mut buf[..IPV6_HEADER_LEN]);
        ipv6.set_version(6);
        ipv6.set_traffic_class(0);
        ipv6.set_flow_label(0);
        ipv6.set_payload_len((packet_len - IPV6_HEADER_LEN) as u16);
        ipv6.set_next_header(first_next_header);
        ipv6.set_hop_limit(iphc_repr.hop_limit);
        ipv6.set_src_addr(iphc_repr.src_addr);
        ipv6.set_dst_addr(iphc_repr.dst_addr);
    }

    let mut dest = IPV6_HEADER_LEN;
    for ext in &exts[..n_ext] {
        let len = ext_header_len(ext.data_len);
        let src = ext.data_offset + grow;
        buf.copy_within(src..src + ext.data_len, dest + 2);
        buf[dest] = ext.next_header.into();
        buf[dest + 1] = (len / 8 - 1) as u8;
        // Restore the alignment with Pad1/PadN (RFC 8200 §4.2).
        let pad = &mut buf[dest + 2 + ext.data_len..dest + len];
        match pad.len() {
            0 => {}
            1 => pad[0] = Ipv6OptionType::Pad1.into(),
            n => {
                pad.fill(0);
                pad[0] = Ipv6OptionType::PadN.into();
                pad[1] = (n - 2) as u8;
            }
        }
        dest += len;
    }

    if let Some(udp) = udp {
        let udp_len = packet_len - dest;
        let checksum = match udp.checksum {
            Some(checksum) => checksum,
            // An elided checksum can only be computed over the whole datagram.
            None if total_len.is_some() => {
                debug!("6LoWPAN: elided UDP checksum on a fragmented packet");
                return Err(Error);
            }
            None => !checksum::combine(&[
                checksum::pseudo_header_v6(
                    &iphc_repr.src_addr,
                    &iphc_repr.dst_addr,
                    IpProtocol::Udp,
                    udp_len as u32,
                ),
                udp.src_port,
                udp.dst_port,
                udp_len as u16,
                checksum::data(&buf[dest + UDP_HEADER_LEN..]),
            ]),
        };
        let mut udp_packet = UdpPacket::new_unchecked(&mut buf[dest..]);
        udp_packet.set_src_port(udp.src_port);
        udp_packet.set_dst_port(udp.dst_port);
        udp_packet.set_len(udp_len as u16);
        udp_packet.set_checksum(checksum);
    }

    Ok(())
}

/// Convert a 6LoWPAN next header to an IPv6 next header.
///
/// `payload` starts right after the header whose next header field is being
/// converted: for a compressed next header, that is where the compressed
/// header it names starts.
#[inline]
fn decompress_next_header(next_header: SixlowpanNextHeader, payload: &[u8]) -> Result<IpProtocol> {
    match next_header {
        SixlowpanNextHeader::Compressed => match SixlowpanNhcPacket::dispatch(payload)? {
            SixlowpanNhcPacket::ExtHeader => {
                let (ext_repr, _) = SixlowpanExtHeaderRepr::parse(payload)?;
                Ok(ext_repr.ext_header_id.into())
            }
            SixlowpanNhcPacket::UdpHeader => Ok(IpProtocol::Udp),
        },
        SixlowpanNextHeader::Uncompressed(proto) => Ok(proto),
    }
}

/// An extension header found by the parse pass of [`ipv6_to_sixlowpan`].
#[derive(Clone, Copy)]
struct ExtHeader {
    ext_header_id: SixlowpanExtHeaderId,
    /// The offset of the header in the IPv6 packet.
    offset: usize,
    /// The length of the whole header.
    header_len: usize,
}

/// Compress an IPv6 packet into a 6LoWPAN packet, in place.
///
/// `buf` starts at the IPv6 header. On success it starts at the IPHC header.
/// The compressed header chain is written over the dead IPv6 header, spilling
/// into the headroom if it is longer than 40 bytes, then moved up against the
/// payload.
///
/// Returns the difference between the uncompressed and the compressed header
/// chain lengths, which fragmentation needs for its offsets.
pub(crate) fn ipv6_to_sixlowpan(buf: &mut PacketBuf, ieee_repr: &Ieee802154Repr) -> Result<usize> {
    // Parse the uncompressed chain.
    let packet = Ipv6Packet::new_checked(buf)?;
    let src_addr = packet.src_addr();
    let dst_addr = packet.dst_addr();
    let hop_limit = packet.hop_limit();
    let mut next_header = packet.next_header();

    let mut exts = [ExtHeader {
        ext_header_id: SixlowpanExtHeaderId::Reserved,
        offset: 0,
        header_len: 0,
    }; MAX_NHC_EXT_HEADERS];
    let mut n_ext = 0;
    let mut offset = IPV6_HEADER_LEN;
    loop {
        let ext_header_id = match next_header {
            IpProtocol::HopByHop => SixlowpanExtHeaderId::HopByHopHeader,
            IpProtocol::Ipv6Route => SixlowpanExtHeaderId::RoutingHeader,
            IpProtocol::Ipv6Opts => SixlowpanExtHeaderId::DestinationOptionsHeader,
            _ => break,
        };
        // Anything the parse stops at is carried inline.
        if n_ext == MAX_NHC_EXT_HEADERS {
            break;
        }
        let Ok(ext) = Ipv6ExtHeader::new_checked(&buf[offset..]) else {
            break;
        };
        let header_len = ext.header_len();
        if header_len - 2 > u8::MAX as usize {
            break;
        }
        exts[n_ext] = ExtHeader {
            ext_header_id,
            offset,
            header_len,
        };
        n_ext += 1;
        next_header = ext.next_header();
        offset += header_len;
    }

    let udp = if next_header == IpProtocol::Udp {
        match UdpPacket::new_checked(&mut buf[offset..]) {
            Ok(udp) => Some(SixlowpanUdpNhcRepr {
                src_port: udp.src_port(),
                dst_port: udp.dst_port(),
                // The checksum covers the same payload and pseudo-header as before.
                checksum: Some(udp.checksum()),
            }),
            Err(_) => None,
        }
    } else {
        None
    };

    // The uncompressed header chain ends here.
    let uncompressed_len = offset + if udp.is_some() { UDP_HEADER_LEN } else { 0 };

    // Size the compressed chain.
    let compressed_next = |more: bool| {
        if more {
            SixlowpanNextHeader::Compressed
        } else {
            SixlowpanNextHeader::Uncompressed(next_header)
        }
    };
    let iphc_repr = SixlowpanIphcRepr {
        src_addr,
        ll_src_addr: ieee_repr.src_addr,
        dst_addr,
        ll_dst_addr: ieee_repr.dst_addr,
        next_header: compressed_next(n_ext > 0 || udp.is_some()),
        hop_limit,
        ecn: None,
        dscp: None,
        flow_label: None,
    };
    let mut ext_reprs = [SixlowpanExtHeaderRepr {
        ext_header_id: SixlowpanExtHeaderId::Reserved,
        next_header: SixlowpanNextHeader::Compressed,
        length: 0,
    }; MAX_NHC_EXT_HEADERS];
    let mut compressed_len = iphc_repr.buffer_len();
    for (i, ext) in exts[..n_ext].iter().enumerate() {
        ext_reprs[i] = SixlowpanExtHeaderRepr {
            ext_header_id: ext.ext_header_id,
            next_header: compressed_next(i + 1 < n_ext || udp.is_some()),
            length: (ext.header_len - 2) as u8,
        };
        compressed_len += ext_reprs[i].buffer_len() + ext.header_len - 2;
    }
    if let Some(udp_repr) = &udp {
        compressed_len += udp_repr.buffer_len();
    }

    // Make room. The compressed chain is written into the dead IPv6 header,
    // ending where the header ended; what does not fit spills into the headroom.
    let extra = compressed_len.saturating_sub(IPV6_HEADER_LEN);
    if !buf.ensure_headroom(extra) {
        return Err(Error);
    }
    buf.push_front(extra);

    // Emit forward. `head` is the (moved) IPv6 header plus the spill, `rest`
    // the untouched extension headers, UDP header and payload.
    let (head, rest) = buf.split_at_mut(extra + IPV6_HEADER_LEN);
    let dest = &mut head[extra + IPV6_HEADER_LEN - compressed_len..];
    let mut pos = 0;
    {
        let len = iphc_repr.buffer_len();
        iphc_repr.emit(&mut dest[pos..pos + len]);
        pos += len;
    }
    for (ext, ext_repr) in exts[..n_ext].iter().zip(&ext_reprs) {
        let len = ext_repr.buffer_len();
        ext_repr.emit(&mut dest[pos..pos + len]);
        pos += len;
        let data = &rest[ext.offset - IPV6_HEADER_LEN + 2..ext.offset - IPV6_HEADER_LEN + ext.header_len];
        dest[pos..pos + data.len()].copy_from_slice(data);
        pos += data.len();
    }
    if let Some(udp_repr) = udp {
        let len = udp_repr.buffer_len();
        udp_repr.emit(&mut dest[pos..pos + len]);
        pos += len;
    }
    debug_assert_eq!(pos, compressed_len);

    // Close the gap between the compressed chain and the payload: the
    // uncompressed extension and UDP headers sit in between.
    let gap = uncompressed_len - IPV6_HEADER_LEN;
    let start = extra + IPV6_HEADER_LEN - compressed_len;
    buf.copy_within(start..start + compressed_len, start + gap);
    buf.pull_front(start + gap);

    Ok(uncompressed_len - compressed_len)
}

// Egress.
impl StackInner {
    /// Send an IPv6 packet to `ll_dst_a` on an IEEE 802.15.4 interface.
    pub(crate) fn dispatch_ieee802154(
        &mut self,
        iface: &mut IfaceState<'_>,
        ll_dst_a: Ieee802154Address,
        buf: PacketBuf,
    ) {
        let ll_src_a = iface.ieee802154_addr();

        // Create the IEEE802.15.4 header.
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(iface.sixlowpan.next_ieee802154_seq_number()),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: iface.sixlowpan.pan_id,
            dst_addr: Some(ll_dst_a),
            src_pan_id: iface.sixlowpan.pan_id,
            src_addr: Some(ll_src_a),
        };

        self.dispatch_sixlowpan(iface, buf, ieee_repr);
    }

    fn dispatch_sixlowpan(&mut self, iface: &mut IfaceState<'_>, mut buf: PacketBuf, ieee_repr: Ieee802154Repr) {
        let header_diff = match ipv6_to_sixlowpan(&mut buf, &ieee_repr) {
            Ok(header_diff) => header_diff,
            Err(_) => {
                debug!("6LoWPAN: compression failed, dropping");
                return;
            }
        };
        #[cfg(not(feature = "sixlowpan-fragmentation"))]
        let _ = header_diff;

        let total_size = buf.len();
        let ieee_len = ieee_repr.buffer_len();
        let mtu = iface.caps.max_transmission_unit;

        if total_size + ieee_len > mtu {
            #[cfg(feature = "sixlowpan-fragmentation")]
            self.fragment_sixlowpan(iface, buf, ieee_repr, header_diff);

            #[cfg(not(feature = "sixlowpan-fragmentation"))]
            debug!("Enable the `sixlowpan-fragmentation` feature for fragmentation support.");
        } else {
            if !buf.ensure_headroom(ieee_len) {
                debug!("6LoWPAN: no room for the MAC header, dropping");
                return;
            }
            buf.push_front(ieee_len);
            ieee_repr.emit(&mut buf[..ieee_len]);
            self.transmit_raw(iface, buf);
        }
    }
}

// Reassembly (feature `sixlowpan-reassembly`).
#[cfg(feature = "sixlowpan-reassembly")]
impl Stack<'_> {
    /// Add a 6LoWPAN fragment to the packet it belongs to.
    ///
    /// The first fragment is decompressed in its own buffer, then copied into
    /// the assembler. Returns the whole IPv6 packet once its last fragment is
    /// in, `None` while it is incomplete or if the fragment was dropped.
    fn process_sixlowpan_fragment(
        &mut self,
        iface: IfaceHandle,
        ieee802154_repr: &Ieee802154Repr,
        mut buf: PacketBuf,
    ) -> Option<PacketBuf> {
        use crate::reassembly::FragKey;

        // The key needs both link-layer addresses.
        if ieee802154_repr.src_addr.is_none() || ieee802154_repr.dst_addr.is_none() {
            return None;
        }

        let frag = check!(SixlowpanFragRepr::parse(&buf));

        // From RFC 4944 § 5.3: "The value of datagram_size SHALL be 40 octets more than the value
        // of Payload Length in the IPv6 header of the packet."
        if frag.size() < IPV6_HEADER_LEN as u16 {
            debug!("6LoWPAN: fragment size too small");
            return None;
        }
        // An IPv6 packet over the link MTU is not valid.
        if frag.size() as usize > IPV6_MIN_MTU {
            debug!("6LoWPAN: fragment size too large");
            return None;
        }

        let datagram_size = frag.size() as usize;
        let is_first_fragment = frag.is_first_fragment();
        // The offset of this fragment in increments of 8 octets.
        let offset = frag.offset() as usize * 8;
        // The key specifies to which 6LoWPAN fragment it belongs too.
        // It is based on the link layer addresses, the tag and the size.
        let key = FragKey::Sixlowpan(frag.key(ieee802154_repr));
        let header_len = frag.buffer_len();

        // We reserve a spot in the packet assembler set and add the required
        // information to the packet assembler.
        let frag_slot = match self
            .fragments
            .assembler
            .get(&key, self.inner.now + self.fragments.reassembly_timeout)
        {
            Ok(frag) => frag,
            Err(_) => {
                debug!("No available packet assembler for fragmented packet");
                return None;
            }
        };

        buf.pull_front(header_len);

        if is_first_fragment {
            // The first fragment contains the total size of the IPv6 packet.
            // However, we received a packet that is compressed following the 6LoWPAN
            // standard. This means we need to convert the IPv6 packet size to a 6LoWPAN
            // packet size. The packet size can be different because of first the
            // compression of the IP header and when UDP is used (because the UDP header
            // can also be compressed). Other headers are not compressed by 6LoWPAN.
            if frag_slot.set_total_size(datagram_size).is_err() {
                debug!("No available packet assembler for fragmented packet");
                return None;
            }

            // Decompress the headers in the fragment's own buffer, then copy
            // them into the assembler.
            let address_context = &self.ifaces.get(iface.index()).sixlowpan.sixlowpan_address_context;
            if sixlowpan_to_ipv6(
                &mut buf,
                ieee802154_repr.src_addr,
                ieee802154_repr.dst_addr,
                address_context,
                Some(datagram_size),
            )
            .is_err()
            {
                debug!("sixlowpan decompress failed");
                return None;
            }
            if let Err(e) = frag_slot.add(&buf, 0) {
                debug!("fragmentation error: {:?}", e);
                return None;
            }
        } else {
            // Add the fragment to the packet assembler.
            if let Err(e) = frag_slot.add(&buf, offset) {
                debug!("fragmentation error: {:?}", e);
                return None;
            }
        }

        match frag_slot.assemble() {
            Some(payload) => {
                trace!("6LoWPAN: fragmented packet now complete");
                Some(payload)
            }
            None => None,
        }
    }
}

#[cfg(feature = "sixlowpan-fragmentation")]
impl StackInner {
    /// Fragment a compressed 6LoWPAN packet that does not fit one frame, and
    /// start transmitting the fragments.
    ///
    /// `buf` starts at the IPHC header. `header_diff` is what compression took
    /// off the header chain, so `buf.len() + header_diff` is the size of the
    /// IPv6 datagram.
    fn fragment_sixlowpan(
        &mut self,
        iface: &mut IfaceState<'_>,
        buf: PacketBuf,
        ieee_repr: Ieee802154Repr,
        header_diff: usize,
    ) {
        if !iface.fragmenter.is_empty() {
            debug!("Fragmentation buffer is busy. Dropping");
            return;
        }

        let total_size = buf.len();
        let ieee_len = ieee_repr.buffer_len();
        let mtu = iface.caps.max_transmission_unit;

        // We calculate how much data we can send in the first fragment and the other
        // fragments. The eventual IPv6 sizes of these fragments need to be a multiple of eight
        // (except for the last fragment) since the offset field in the fragment is an offset
        // in multiples of 8 octets. This is explained in [RFC 4944 § 5.3].
        //
        // [RFC 4944 § 5.3]: https://datatracker.ietf.org/doc/html/rfc4944#section-5.3
        let frag1_size = (mtu + header_diff)
            .checked_sub(ieee_len + SIXLOWPAN_FIRST_FRAGMENT_HEADER_SIZE)
            .map(|n| n / 8 * 8)
            .and_then(|n| n.checked_sub(header_diff))
            .unwrap_or(0);
        let fragn_size = mtu
            .checked_sub(ieee_len + SIXLOWPAN_NEXT_FRAGMENT_HEADER_SIZE)
            .map(|n| n / 8 * 8)
            .unwrap_or(0);
        if frag1_size == 0 || fragn_size == 0 {
            debug!("MTU too small to fragment. Dropping");
            return;
        }

        let tag = iface.sixlowpan.get_sixlowpan_fragment_tag();

        let frag = &mut iface.fragmenter;
        frag.sixlowpan.ll_dst_addr = unwrap!(ieee_repr.dst_addr);
        frag.sixlowpan.ll_src_addr = unwrap!(ieee_repr.src_addr);
        frag.packet_len = total_size;

        // The datagram size that we need to set in the first fragment header is equal to the
        // IPv6 payload length + 40.
        frag.sixlowpan.datagram_size = (total_size + header_diff) as u16;
        frag.sixlowpan.datagram_tag = tag;
        frag.sixlowpan.frag1_size = frag1_size;
        frag.sixlowpan.fragn_size = fragn_size;
        frag.sixlowpan.header_diff = header_diff;
        frag.sixlowpan.datagram_offset = 0;
        frag.sent_bytes = 0;
        frag.buffer = Some(buf);

        // Transmit as many fragments as the device takes now. The rest go
        // out on the next polls.
        self.sixlowpan_egress(iface);
    }

    /// Process fragments that still need to be sent for 6LoWPAN packets.
    ///
    /// Fragments go out while the device has room for them and the pool has
    /// buffers. The rest wait in the fragmenter for the next poll.
    pub(crate) fn sixlowpan_egress(&mut self, iface: &mut IfaceState<'_>) {
        if iface.fragmenter.is_empty() {
            return;
        }

        while !iface.fragmenter.finished() {
            if !iface.can_transmit() {
                trace!("fragmenter: device has no room, fragments wait");
                return;
            }
            if !self.dispatch_ieee802154_frag(iface) {
                return;
            }
        }

        // Reset the buffer when we transmitted everything.
        iface.fragmenter.reset();
    }

    /// Transmit the next fragment of the packet in the interface's fragmenter.
    ///
    /// Returns `false` if no packet buffer is free, leaving the fragmenter as it was.
    fn dispatch_ieee802154_frag(&mut self, iface: &mut IfaceState<'_>) -> bool {
        // Create the IEEE802.15.4 header.
        let ieee_repr = Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(iface.sixlowpan.next_ieee802154_seq_number()),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: iface.sixlowpan.pan_id,
            dst_addr: Some(iface.fragmenter.sixlowpan.ll_dst_addr),
            src_pan_id: iface.sixlowpan.pan_id,
            src_addr: Some(iface.fragmenter.sixlowpan.ll_src_addr),
        };
        let ieee_len = ieee_repr.buffer_len();

        let frag = &mut iface.fragmenter;
        let first = frag.sent_bytes == 0;
        let remaining = frag.packet_len - frag.sent_bytes;
        let (frag_repr, frag_size) = if first {
            (
                SixlowpanFragRepr::FirstFragment {
                    size: frag.sixlowpan.datagram_size,
                    tag: frag.sixlowpan.datagram_tag,
                },
                remaining.min(frag.sixlowpan.frag1_size),
            )
        } else {
            (
                SixlowpanFragRepr::Fragment {
                    size: frag.sixlowpan.datagram_size,
                    tag: frag.sixlowpan.datagram_tag,
                    offset: (frag.sixlowpan.datagram_offset / 8) as u8,
                },
                remaining.min(frag.sixlowpan.fragn_size),
            )
        };
        let frag_len = frag_repr.buffer_len();

        let Some(mut tx_buffer) = PacketBuf::try_new() else {
            trace!("fragmenter: no packet buffer, fragments wait");
            return false;
        };
        tx_buffer.set_len(ieee_len + frag_len + frag_size);
        ieee_repr.emit(&mut tx_buffer[..ieee_len]);
        frag_repr.emit(&mut tx_buffer[ieee_len..ieee_len + frag_len]);

        // NOTE(unwrap): the fragmenter is not empty, checked by the caller.
        let buffer = unwrap!(frag.buffer.as_ref());
        tx_buffer[ieee_len + frag_len..].copy_from_slice(&buffer[frag.sent_bytes..][..frag_size]);
        // The packet's metadata rides on its first fragment.
        if first {
            tx_buffer.set_meta(buffer.meta());
        }

        frag.sent_bytes += frag_size;
        // The offsets count uncompressed bytes: the first fragment carries the
        // whole header chain, which was `header_diff` bytes longer.
        frag.sixlowpan.datagram_offset += frag_size + if first { frag.sixlowpan.header_diff } else { 0 };

        self.transmit_raw(iface, tx_buffer);
        true
    }
}

#[cfg(all(
    test,
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "ipv6",
    feature = "raw-ethernet",
    feature = "raw-ip",
    feature = "udp",
    feature = "tcp"
))]
// The fragmentation and reassembly vectors and helpers are only used with the features.
#[cfg_attr(
    not(all(feature = "sixlowpan-fragmentation", feature = "sixlowpan-reassembly")),
    allow(unused_imports, dead_code)
)]
mod test {
    use super::*;
    use crate::iface::Medium;
    use crate::iface::{AddrOrigin, IfaceHandle};
    use crate::stack::test::{icmpv6_echo, inject, ipv6_packet, udp_datagram};
    use crate::test_device::{Queue, Room, Sent, TestDevice};
    use crate::time::{Duration, Instant};
    use crate::udp::{RecvError, SendError};
    use std::vec::Vec;

    const MTU: usize = 125;
    const PAN: Ieee802154Pan = Ieee802154Pan(0xbeef);

    /// The link-layer address of the old example, whose link-local address the
    /// test vectors are addressed to.
    const OUR_LL: Ieee802154Address = Ieee802154Address::Extended([0x1a, 0x0b, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42]);
    /// OUR_LL as a link-local address.
    const OUR_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0x180b, 0x4242, 0x4242, 0x4242);
    /// The sender of the echo request test vector.
    const PEER_LL: Ieee802154Address = Ieee802154Address::Extended([0x26, 0x1c, 0x29, 0x57, 0x34, 0xa6, 0x3a, 0x62]);
    const PEER_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0x241c, 0x2957, 0x34a6, 0x3a62);

    /// The Contiki-NG node of the fragmentation test vectors, and the address
    /// the vectors are addressed to.
    const CONTIKI_LL: Ieee802154Address = Ieee802154Address::Extended([0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a]);
    const CONTIKI_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0x4042, 0x4242, 0x4242, 0x0b1a);
    const VECTOR_LL: Ieee802154Address = Ieee802154Address::Extended([0x90, 0xfc, 0x48, 0xc2, 0xa4, 0x41, 0xfc, 0x76]);
    const VECTOR_LINK_LOCAL: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0x92fc, 0x48c2, 0xa441, 0xfc76);
    /// The old test harness's own address.
    const ZERO_LL: Ieee802154Address = Ieee802154Address::Extended([0; 8]);
    const TWO_LL: Ieee802154Address = Ieee802154Address::Extended([0x02; 8]);

    /// A stack with one IEEE 802.15.4 interface of address `hw` on `pan_id`.
    fn test_stack(
        hw: Ieee802154Address,
        pan_id: Option<Ieee802154Pan>,
    ) -> (Stack<'static>, IfaceHandle, Queue, Sent, Room) {
        let driver = TestDevice::new(Medium::Ieee802154).with_mtu(MTU);
        let (rx, tx, room) = (driver.rx.clone(), driver.tx.clone(), driver.room.clone());
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = driver.install(&mut stack, HardwareAddress::Ieee802154(hw));
        stack.iface(handle).set_pan_id(pan_id);
        // Drain the solicited-node multicast reports the link-local address
        // triggers, so the tests only see the frames they provoke.
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();
        (stack, handle, rx, tx, room)
    }

    fn fill_neighbor(stack: &mut Stack, iface: IfaceHandle, addr: Ipv6Address, ll: Ieee802154Address) {
        stack
            .inner
            .neighbor_cache
            .fill((iface, addr.into()), HardwareAddress::Ieee802154(ll), Instant::ZERO);
    }

    fn mac_repr(src: Ieee802154Address, dst: Ieee802154Address, pan: Option<Ieee802154Pan>) -> Ieee802154Repr {
        Ieee802154Repr {
            frame_type: Ieee802154FrameType::Data,
            security_enabled: false,
            frame_pending: false,
            ack_request: false,
            sequence_number: Some(1),
            pan_id_compression: true,
            frame_version: Ieee802154FrameVersion::Ieee802154_2003,
            dst_pan_id: pan,
            dst_addr: Some(dst),
            src_pan_id: pan,
            src_addr: Some(src),
        }
    }

    /// A data frame from `src` to `dst` carrying a 6LoWPAN payload.
    fn frame(src: Ieee802154Address, dst: Ieee802154Address, pan: Ieee802154Pan, payload: &[u8]) -> Vec<u8> {
        let repr = mac_repr(src, dst, Some(pan));
        let len = repr.buffer_len();
        let mut bytes = vec![0; len + payload.len()];
        repr.emit(&mut bytes[..len]);
        bytes[len..].copy_from_slice(payload);
        bytes
    }

    /// The MAC header and the payload of a transmitted frame.
    fn parse_frame(frame: &[u8]) -> (Ieee802154Repr, Vec<u8>) {
        let (repr, header_len) = Ieee802154Repr::parse(frame).unwrap();
        (repr, frame[header_len..].to_vec())
    }

    /// Compress an IPv6 packet in a buffer with `headroom` bytes in front, as
    /// if sent from `src` to `dst`. Returns the 6LoWPAN bytes (IPHC first) and
    /// the header difference.
    fn compress(packet: &[u8], src: Ieee802154Address, dst: Ieee802154Address, headroom: usize) -> (Vec<u8>, usize) {
        let mut buf = PacketBuf::try_new().unwrap();
        buf.reserve(headroom);
        buf.set_len(packet.len());
        buf.copy_from_slice(packet);
        let header_diff = ipv6_to_sixlowpan(&mut buf, &mac_repr(src, dst, None)).unwrap();
        (buf.to_vec(), header_diff)
    }

    /// Decompress a 6LoWPAN packet (IPHC first) in a buffer with `headroom`
    /// bytes in front, as received from `src` at `dst`.
    fn decompress(
        payload: &[u8],
        src: Ieee802154Address,
        dst: Ieee802154Address,
        context: &[SixlowpanAddressContext],
        headroom: usize,
        total_len: Option<usize>,
    ) -> Result<Vec<u8>> {
        let mut buf = PacketBuf::try_new().unwrap();
        buf.reserve(headroom);
        buf.set_len(payload.len());
        buf.copy_from_slice(payload);
        sixlowpan_to_ipv6(&mut buf, Some(src), Some(dst), context, total_len)?;
        Ok(buf.to_vec())
    }

    /// The IPv6 packet an unfragmented transmitted frame carries.
    fn ipv6_of_frame(frame: &[u8]) -> Vec<u8> {
        let (repr, payload) = parse_frame(frame);
        assert_eq!(SixlowpanPacket::dispatch(&payload), Ok(SixlowpanPacket::IphcHeader));
        decompress(&payload, repr.src_addr.unwrap(), repr.dst_addr.unwrap(), &[], 0, None).unwrap()
    }

    /// Check the fragment headers of transmitted frames and put their
    /// payloads together. Returns `(datagram size, tag, offsets, compressed bytes)`.
    #[cfg(feature = "sixlowpan-fragmentation")]
    fn reassemble_frames(frames: &[Vec<u8>]) -> (u16, u16, Vec<usize>, Vec<u8>) {
        let mut compressed = Vec::new();
        let mut offsets = Vec::new();
        let mut size_tag = None;
        for (i, frame) in frames.iter().enumerate() {
            assert!(frame.len() <= MTU, "frame of {} octets exceeds the MTU", frame.len());
            let (_, payload) = parse_frame(frame);
            let frag = SixlowpanFragRepr::parse(&payload).unwrap();
            assert_eq!(frag.is_first_fragment(), i == 0);
            let st = *size_tag.get_or_insert((frag.size(), frag.tag()));
            assert_eq!((frag.size(), frag.tag()), st);
            offsets.push(frag.offset() as usize * 8);
            compressed.extend_from_slice(&payload[frag.buffer_len()..]);
        }
        let (size, tag) = size_tag.unwrap();
        (size, tag, offsets, compressed)
    }

    /// The fragments of an IPv6 packet as frames from `src` to `dst`, cut the
    /// way the stack cuts them, in order.
    #[cfg(feature = "sixlowpan-reassembly")]
    fn fragments(packet: &[u8], src: Ieee802154Address, dst: Ieee802154Address, tag: u16) -> Vec<Vec<u8>> {
        let (compressed, header_diff) = compress(packet, src, dst, 0);
        let ieee_len = mac_repr(src, dst, Some(PAN)).buffer_len();
        let size = packet.len() as u16;
        let frag1_size = (MTU - ieee_len - SIXLOWPAN_FIRST_FRAGMENT_HEADER_SIZE + header_diff) / 8 * 8 - header_diff;
        let fragn_size = (MTU - ieee_len - SIXLOWPAN_NEXT_FRAGMENT_HEADER_SIZE) / 8 * 8;
        let mut frames = Vec::new();
        let mut sent = 0;
        let mut offset = 0;
        while sent < compressed.len() {
            let (repr, len) = if sent == 0 {
                (SixlowpanFragRepr::FirstFragment { size, tag }, frag1_size)
            } else {
                (
                    SixlowpanFragRepr::Fragment {
                        size,
                        tag,
                        offset: (offset / 8) as u8,
                    },
                    fragn_size,
                )
            };
            let len = len.min(compressed.len() - sent);
            let mut payload = vec![0; repr.buffer_len() + len];
            repr.emit(&mut payload[..]);
            payload[repr.buffer_len()..].copy_from_slice(&compressed[sent..sent + len]);
            frames.push(frame(src, dst, PAN, &payload));
            offset += len + if sent == 0 { header_diff } else { 0 };
            sent += len;
        }
        frames
    }

    /// The old `icmp_echo_request` test vector: a frame from PEER_LL to OUR_LL
    /// on PAN 0xbeef, carrying an echo request with a 56-byte payload.
    const ECHO_REQUEST_FRAME: [u8; 91] = [
        0x41, 0xcc, 0x3b, 0xef, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0x62, 0x3a, 0xa6, 0x34, 0x57,
        0x29, 0x1c, 0x26, 0x6a, 0x33, 0x0a, 0x62, 0x17, 0x3a, 0x80, 0x00, 0xb0, 0xe3, 0x00, 0x04, 0x00, 0x01, 0x82,
        0xf2, 0x82, 0x64, 0x00, 0x00, 0x00, 0x00, 0x66, 0x23, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37,
    ];

    /// Check that a transmitted frame is the echo reply to ECHO_REQUEST_FRAME.
    fn check_echo_reply(frame: &[u8], pan: Option<Ieee802154Pan>) {
        let (repr, _) = parse_frame(frame);
        assert_eq!(repr.dst_addr, Some(PEER_LL));
        assert_eq!(repr.src_addr, Some(OUR_LL));
        assert_eq!(repr.dst_pan_id, Some(pan.unwrap_or(Ieee802154Pan(0))));
        assert!(repr.pan_id_compression);

        let mut packet = ipv6_of_frame(frame);
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        assert_eq!(ip.src_addr(), OUR_LINK_LOCAL);
        assert_eq!(ip.dst_addr(), PEER_LINK_LOCAL);
        assert_eq!(ip.next_header(), IpProtocol::Icmpv6);
        assert_eq!(ip.hop_limit(), 64);
        assert_eq!(ip.payload_len(), 64);
        let mut payload = ip.payload().to_vec();
        let icmp = Icmpv6Packet::new_checked(&mut payload[..]).unwrap();
        assert!(icmp.verify_checksum(&OUR_LINK_LOCAL, &PEER_LINK_LOCAL));
        assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
        assert_eq!(icmp.echo_ident(), 4);
        assert_eq!(icmp.echo_seq_no(), 1);
        assert_eq!(icmp.payload(), &ECHO_REQUEST_FRAME[35..]);
    }

    #[test]
    fn test_auto_link_local() {
        let (mut stack, iface, _rx, _tx, _room) = test_stack(OUR_LL, Some(PAN));
        let addrs = stack.iface(iface).ip_addrs().to_vec();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].cidr, IpCidr::new(OUR_LINK_LOCAL.into(), 64));
        assert_eq!(addrs[0].origin, AddrOrigin::LinkLocal);
        assert_eq!(stack.iface(iface).pan_id(), Some(PAN));
        assert_eq!(stack.iface(iface).hardware_addr(), HardwareAddress::Ieee802154(OUR_LL));
    }

    #[test]
    fn test_ip_mtu() {
        let (mut stack, iface, _rx, _tx, _room) = test_stack(OUR_LL, None);
        #[cfg(feature = "sixlowpan-fragmentation")]
        assert_eq!(stack.iface(iface).ip_mtu(), IPV6_MIN_MTU);
        #[cfg(not(feature = "sixlowpan-fragmentation"))]
        assert_eq!(stack.iface(iface).ip_mtu(), MTU - 17);
    }

    #[test]
    fn ieee802154_wrong_pan_id() {
        let (mut stack, iface, rx, tx, _room) = test_stack(OUR_LL, Some(PAN));
        fill_neighbor(&mut stack, iface, PEER_LINK_LOCAL, PEER_LL);

        // The old test vector: PAN 0xbeff, no payload.
        let data = [
            0x41, 0xcc, 0x3b, 0xff, 0xbe, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x0b, 0x1a, 0x62, 0x3a, 0xa6, 0x34, 0x57,
            0x29, 0x1c, 0x26,
        ];
        inject(&mut stack, &rx, data.to_vec());
        assert!(tx.borrow().is_empty());

        // A valid echo request for another PAN is dropped...
        let mut wrong_pan = ECHO_REQUEST_FRAME.to_vec();
        wrong_pan[3] = 0xff;
        inject(&mut stack, &rx, wrong_pan);
        assert!(tx.borrow().is_empty());

        // ...one for the broadcast PAN is answered.
        let mut broadcast_pan = ECHO_REQUEST_FRAME.to_vec();
        broadcast_pan[3] = 0xff;
        broadcast_pan[4] = 0xff;
        inject(&mut stack, &rx, broadcast_pan);
        assert_eq!(tx.borrow().len(), 1);
        check_echo_reply(&tx.borrow()[0], Some(PAN));
    }

    #[test]
    fn icmp_echo_request() {
        for pan in [Some(PAN), None] {
            let (mut stack, iface, rx, tx, _room) = test_stack(OUR_LL, pan);
            fill_neighbor(&mut stack, iface, PEER_LINK_LOCAL, PEER_LL);
            inject(&mut stack, &rx, ECHO_REQUEST_FRAME.to_vec());
            assert_eq!(tx.borrow().len(), 1);
            check_echo_reply(&tx.borrow()[0], pan);
        }
    }

    /// The reply to an unresolved neighbor waits for a neighbor solicitation,
    /// sent as a broadcast frame with a 16-byte source link-layer address option.
    #[test]
    fn test_neighbor_solicit() {
        let (mut stack, _iface, rx, tx, _room) = test_stack(OUR_LL, Some(PAN));
        inject(&mut stack, &rx, ECHO_REQUEST_FRAME.to_vec());
        assert_eq!(tx.borrow().len(), 1);
        let (repr, _) = parse_frame(&tx.borrow()[0]);
        assert_eq!(repr.dst_addr, Some(Ieee802154Address::BROADCAST));
        assert_eq!(repr.src_addr, Some(OUR_LL));

        let mut packet = ipv6_of_frame(&tx.borrow()[0]);
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        assert_eq!(ip.src_addr(), OUR_LINK_LOCAL);
        assert_eq!(ip.dst_addr(), PEER_LINK_LOCAL.solicited_node());
        assert_eq!(ip.hop_limit(), 255);
        let mut payload = ip.payload().to_vec();
        let mut icmp = Icmpv6Packet::new_checked(&mut payload[..]).unwrap();
        assert!(icmp.verify_checksum(&OUR_LINK_LOCAL, &PEER_LINK_LOCAL.solicited_node()));
        assert_eq!(icmp.msg_type(), Icmpv6Message::NeighborSolicit);
        assert_eq!(icmp.target_addr(), PEER_LINK_LOCAL);
        let opt = NdiscOption::new_checked(icmp.payload_mut()).unwrap();
        assert_eq!(opt.option_type(), NdiscOptionType::SourceLinkLayerAddr);
        assert_eq!(opt.data_len(), 2);
        assert_eq!(
            opt.link_layer_addr().parse(Medium::Ieee802154),
            Ok(HardwareAddress::Ieee802154(OUR_LL))
        );
        assert_eq!(icmp.payload().len(), 16);
    }

    /// An NDISC message from `src` to `dst`, as an IPv6 packet with hop limit 255.
    fn ndisc_packet(
        msg_type: Icmpv6Message,
        src: Ipv6Address,
        dst: Ipv6Address,
        target: Ipv6Address,
        option_type: NdiscOptionType,
        ll: Ieee802154Address,
    ) -> Vec<u8> {
        let mut icmp_bytes = vec![0; 24 + 16];
        {
            let mut icmp = Icmpv6Packet::new_unchecked(&mut icmp_bytes[..]);
            icmp.set_msg_type(msg_type);
            icmp.set_msg_code(0);
            icmp.clear_reserved();
            if msg_type == Icmpv6Message::NeighborAdvert {
                icmp.set_neighbor_flags(NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE);
            }
            icmp.set_target_addr(target);
            {
                let mut opt = NdiscOption::new_unchecked(icmp.payload_mut());
                opt.set_option_type(option_type);
                opt.set_data_len(2);
                opt.set_link_layer_addr(RawHardwareAddress::from(ll));
            }
            icmp.fill_checksum(&src, &dst);
        }
        let mut packet = ipv6_packet(src, dst, IpProtocol::Icmpv6, &icmp_bytes);
        Ipv6Packet::new_unchecked(&mut packet[..]).set_hop_limit(255);
        packet
    }

    /// A neighbor solicitation for our address is answered with an
    /// advertisement carrying our extended address, and fills the cache.
    #[test]
    fn test_ndisc_solicit_answered() {
        let (mut stack, _iface, rx, tx, _room) = test_stack(OUR_LL, Some(PAN));
        let ns = ndisc_packet(
            Icmpv6Message::NeighborSolicit,
            PEER_LINK_LOCAL,
            OUR_LINK_LOCAL.solicited_node(),
            OUR_LINK_LOCAL,
            NdiscOptionType::SourceLinkLayerAddr,
            PEER_LL,
        );
        let (compressed, _) = compress(&ns, PEER_LL, Ieee802154Address::BROADCAST, 0);
        inject(
            &mut stack,
            &rx,
            frame(PEER_LL, Ieee802154Address::BROADCAST, PAN, &compressed),
        );

        assert_eq!(tx.borrow().len(), 1);
        let (repr, _) = parse_frame(&tx.borrow()[0]);
        assert_eq!(repr.dst_addr, Some(PEER_LL));
        let mut packet = ipv6_of_frame(&tx.borrow()[0]);
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        assert_eq!(
            (ip.src_addr(), ip.dst_addr(), ip.hop_limit()),
            (OUR_LINK_LOCAL, PEER_LINK_LOCAL, 255)
        );
        let mut payload = ip.payload().to_vec();
        let mut icmp = Icmpv6Packet::new_checked(&mut payload[..]).unwrap();
        assert!(icmp.verify_checksum(&OUR_LINK_LOCAL, &PEER_LINK_LOCAL));
        assert_eq!(icmp.msg_type(), Icmpv6Message::NeighborAdvert);
        assert_eq!(icmp.target_addr(), OUR_LINK_LOCAL);
        let opt = NdiscOption::new_checked(icmp.payload_mut()).unwrap();
        assert_eq!(opt.option_type(), NdiscOptionType::TargetLinkLayerAddr);
        assert_eq!(opt.data_len(), 2);
        assert_eq!(
            opt.link_layer_addr().parse(Medium::Ieee802154),
            Ok(HardwareAddress::Ieee802154(OUR_LL))
        );

        // The peer is resolved now: an echo request is answered directly.
        tx.borrow_mut().clear();
        inject(&mut stack, &rx, ECHO_REQUEST_FRAME.to_vec());
        assert_eq!(tx.borrow().len(), 1);
        check_echo_reply(&tx.borrow()[0], Some(PAN));
    }

    /// Frames with link-layer security are dropped.
    #[test]
    fn test_security_frame_dropped() {
        let (mut stack, _iface, rx, tx, _room) = test_stack(OUR_LL, None);
        let data = [
            0x69, 0xdc, 0x32, 0xcd, 0xab, 0xbf, 0x9b, 0x15, 0x06, 0x00, 0x4b, 0x12, 0x00, 0xc7, 0xd9, 0xb5, 0x14, 0x00,
            0x4b, 0x12, 0x00, 0x05, 0x31, 0x01, 0x00, 0x00, 0x3e, 0xe8, 0xfb, 0x85, 0xe4, 0xcc, 0xf4, 0x48, 0x90, 0xfe,
            0x56, 0x66, 0xf7, 0x1c, 0x65, 0x9e, 0xf9, 0x93, 0xc8, 0x34, 0x2e,
        ];
        inject(&mut stack, &rx, data.to_vec());
        assert!(tx.borrow().is_empty());
    }

    /// An IPv4 packet routed to an 802.15.4 interface is dropped, not sent.
    #[test]
    fn test_ipv4_dropped() {
        let (mut stack, iface, _rx, tx, _room) = test_stack(OUR_LL, None);
        let our_v4 = Ipv4Address::new(192, 168, 1, 1);
        let remote_v4 = Ipv4Address::new(192, 168, 1, 2);
        stack.iface(iface).add_ip_addr(IpCidr::new(our_v4.into(), 24)).unwrap();
        tx.borrow_mut().clear();
        let udp = stack.add_udp_socket().unwrap();
        let mut socket = stack.udp_socket(udp);
        socket.bind(1234, IpListenEndpoint::UNSPECIFIED).unwrap();
        assert_eq!(
            socket.send_slice(b"hello", IpEndpoint::new(remote_v4.into(), 5678)),
            Ok(())
        );
        stack.poll(Instant::ZERO);
        assert!(tx.borrow().is_empty());
    }

    /// A UDP datagram to the all-nodes group, with an 8-bit compressed
    /// multicast destination, reaches the socket.
    #[test]
    fn test_handle_udp_broadcast() {
        let (mut stack, _iface, rx, _tx, _room) = test_stack(OUR_LL, Some(PAN));
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(68, IpListenEndpoint::UNSPECIFIED).unwrap();

        let src = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dst = IPV6_LINK_LOCAL_ALL_NODES;
        let datagram = udp_datagram(src.into(), 67, dst.into(), 68, b"Hello");
        let packet = ipv6_packet(src, dst, IpProtocol::Udp, &datagram);
        let (compressed, _) = compress(&packet, PEER_LL, Ieee802154Address::BROADCAST, 0);
        {
            let (iphc, header_len) =
                SixlowpanIphcRepr::parse(&compressed, Some(PEER_LL), Some(Ieee802154Address::BROADCAST), &[]).unwrap();
            assert_eq!(iphc.dst_addr, dst);
            assert_eq!(iphc.next_header, SixlowpanNextHeader::Compressed);
            // The base, 8 inline source bytes, and the multicast destination
            // compressed to a single byte.
            assert_eq!(header_len, 2 + 8 + 1);
        }
        inject(
            &mut stack,
            &rx,
            frame(PEER_LL, Ieee802154Address::BROADCAST, PAN, &compressed),
        );

        let mut socket = stack.udp_socket(udp);
        let received = socket.recv().unwrap();
        assert_eq!(&*received, b"Hello");
        assert_eq!(received.meta().endpoint, IpEndpoint::new(src.into(), 67));
        assert_eq!(received.meta().local_address, Some(dst.into()));
    }

    /// A UDP datagram whose NHC header elides the checksum is delivered, with
    /// the checksum computed on the way in.
    #[test]
    fn test_elided_udp_checksum() {
        let (mut stack, _iface, rx, _tx, _room) = test_stack(OUR_LL, Some(PAN));
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(6969, IpListenEndpoint::UNSPECIFIED).unwrap();

        // IPHC: TF elided, NH compressed, hop limit 64, both addresses elided.
        let mut payload = vec![0x7e, 0x33];
        // UDP NHC: checksum elided, both ports inline.
        payload.push(0xf4);
        payload.extend_from_slice(&1234u16.to_be_bytes());
        payload.extend_from_slice(&6969u16.to_be_bytes());
        payload.extend_from_slice(b"no checksum");
        inject(&mut stack, &rx, frame(PEER_LL, OUR_LL, PAN, &payload));

        let mut socket = stack.udp_socket(udp);
        let received = socket.recv().unwrap();
        assert_eq!(&*received, b"no checksum");
        assert_eq!(received.meta().endpoint, IpEndpoint::new(PEER_LINK_LOCAL.into(), 1234));
    }

    static SIXLOWPAN_COMPRESSED_RPL_DAO: [u8; 99] = [
        0x61, 0xdc, 0x45, 0xcd, 0xab, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x00, 0x7e, 0xf7, 0x00, 0xe0, 0x3a, 0x06, 0x63, 0x04, 0x00, 0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e,
        0x63, 0x1e, 0x40, 0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x01, 0x05, 0x12, 0x00, 0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00,
        0x03, 0x00, 0x03, 0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    static SIXLOWPAN_UNCOMPRESSED_RPL_DAO: [u8; 114] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03,
        0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x3a, 0x00, 0x63, 0x04, 0x00, 0x1e, 0x08, 0x00, 0x9b, 0x02, 0x3e, 0x63, 0x1e, 0x40,
        0x00, 0xf1, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
        0x05, 0x12, 0x00, 0x80, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x03, 0x00, 0x03,
        0x00, 0x03, 0x06, 0x14, 0x00, 0x00, 0x00, 0x1e, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    ];

    /// The context-compressed addresses and the NHC hop-by-hop header with an
    /// inline next header decompress in place, with any headroom.
    #[test]
    fn test_sixlowpan_decompress_hop_by_hop_with_icmpv6() {
        let address_context = [SixlowpanAddressContext([0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])];
        let (repr, payload) = parse_frame(&SIXLOWPAN_COMPRESSED_RPL_DAO);
        for headroom in [0, 14, 64] {
            let packet = decompress(
                &payload,
                repr.src_addr.unwrap(),
                repr.dst_addr.unwrap(),
                &address_context,
                headroom,
                None,
            )
            .unwrap();
            assert_eq!(&packet[..], &SIXLOWPAN_UNCOMPRESSED_RPL_DAO[..]);
        }
        // Without the context the addresses cannot be resolved.
        assert!(decompress(&payload, repr.src_addr.unwrap(), repr.dst_addr.unwrap(), &[], 0, None).is_err());
    }

    /// The address contexts set on the interface are used to decompress
    /// context-compressed addresses: an echo request whose addresses are
    /// both compressed against context 0 is answered.
    #[test]
    fn test_address_context_on_iface() {
        let context = SixlowpanAddressContext([0xfd, 0, 0, 0, 0, 0, 0, 0]);
        let mut our = [0u8; 16];
        our[..8].copy_from_slice(&context.0);
        our[8..].copy_from_slice(&OUR_LL.as_eui_64().unwrap());
        let our = Ipv6Address::from_octets(our);
        let mut peer = [0u8; 16];
        peer[..8].copy_from_slice(&context.0);
        peer[8..].copy_from_slice(&PEER_LL.as_eui_64().unwrap());
        let peer = Ipv6Address::from_octets(peer);

        let (mut stack, iface, rx, tx, _room) = test_stack(OUR_LL, None);
        stack.iface(iface).add_ip_addr(IpCidr::new(our.into(), 64)).unwrap();
        fill_neighbor(&mut stack, iface, peer, PEER_LL);
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();

        // IPHC: next header inline, hop limit 64, CID present, both addresses
        // fully elided against context 0.
        let mut payload = vec![0x7a, 0xf7, 0x00, 0x3a];
        payload.extend_from_slice(&icmpv6_echo(Icmpv6Message::EchoRequest, 7, 8, b"ctx", peer, our));

        // Without the context the frame is dropped.
        assert_eq!(stack.iface(iface).sixlowpan_address_context(), &[]);
        inject(&mut stack, &rx, frame(PEER_LL, OUR_LL, PAN, &payload));
        assert!(tx.borrow().is_empty());

        stack.iface(iface).set_sixlowpan_address_context([context]).unwrap();
        assert_eq!(stack.iface(iface).sixlowpan_address_context(), &[context]);
        inject(&mut stack, &rx, frame(PEER_LL, OUR_LL, PAN, &payload));
        assert_eq!(tx.borrow().len(), 1);
        let mut packet = ipv6_of_frame(&tx.borrow()[0]);
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        assert_eq!((ip.src_addr(), ip.dst_addr()), (our, peer));
        let mut l4 = ip.payload().to_vec();
        let icmp = Icmpv6Packet::new_checked(&mut l4[..]).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
        assert_eq!((icmp.echo_ident(), icmp.echo_seq_no()), (7, 8));
    }

    /// Global addresses are carried inline, and the hop-by-hop header is
    /// compressed with its next header inline. The compressed chain is longer
    /// than the IPv6 header it replaces, so it spills into the headroom.
    #[test]
    fn test_sixlowpan_compress_hop_by_hop_with_icmpv6() {
        let (repr, _) = parse_frame(&SIXLOWPAN_COMPRESSED_RPL_DAO);
        let mut expected = vec![0x7e, 0x00];
        expected.extend_from_slice(&SIXLOWPAN_UNCOMPRESSED_RPL_DAO[8..40]);
        expected.extend_from_slice(&[0xe0, 0x3a, 0x06]);
        expected.extend_from_slice(&SIXLOWPAN_UNCOMPRESSED_RPL_DAO[42..]);
        for headroom in [0, 14, 64] {
            let (compressed, header_diff) = compress(
                &SIXLOWPAN_UNCOMPRESSED_RPL_DAO,
                repr.src_addr.unwrap(),
                repr.dst_addr.unwrap(),
                headroom,
            );
            assert_eq!(compressed, expected);
            assert_eq!(header_diff, 48 - 43);
        }
    }

    /// An NHC extension header whose data is not 8-aligned decompresses to a
    /// padded IPv6 extension header.
    #[test]
    fn test_decompress_padding() {
        let echo = icmpv6_echo(
            Icmpv6Message::EchoRequest,
            1,
            2,
            b"ping",
            PEER_LINK_LOCAL,
            OUR_LINK_LOCAL,
        );
        // IPHC: NH compressed, hop limit 64, addresses elided; NHC hop-by-hop
        // with 3 data bytes and ICMPv6 inline.
        let mut payload = vec![0x7e, 0x33, 0xe0, 0x3a, 0x03, 0x01, 0x01, 0x00];
        payload.extend_from_slice(&echo);
        let packet = decompress(&payload, PEER_LL, OUR_LL, &[], 0, None).unwrap();
        let mut expected = ipv6_packet(PEER_LINK_LOCAL, OUR_LINK_LOCAL, IpProtocol::HopByHop, &[]);
        expected.extend_from_slice(&[0x3a, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00]);
        expected.extend_from_slice(&echo);
        Ipv6Packet::new_unchecked(&mut expected[..]).set_payload_len((8 + echo.len()) as u16);
        assert_eq!(packet, expected);

        // A 5-byte data: one byte of padding is Pad1.
        let mut payload = vec![0x7e, 0x33, 0xe0, 0x3a, 0x05, 0x01, 0x03, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&echo);
        let packet = decompress(&payload, PEER_LL, OUR_LL, &[], 0, None).unwrap();
        assert_eq!(&packet[40..48], &[0x3a, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00]);
    }

    /// Compress then decompress every address mode, hop limit encoding, UDP
    /// port encoding and extension header case, through every headroom path.
    #[test]
    fn test_roundtrip_matrix() {
        let short_ll = Ieee802154Address::Short([0x12, 0x34]);
        // (address, link-layer address it is sent with, compressed size)
        let unicast: &[(Ipv6Address, Ieee802154Address, usize)] = &[
            (OUR_LINK_LOCAL, OUR_LL, 0),
            (Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x1234), short_ll, 0),
            (Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x5678), OUR_LL, 2),
            (Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), OUR_LL, 8),
            (Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), OUR_LL, 16),
        ];
        let multicast: &[(Ipv6Address, Ieee802154Address, usize)] = &[
            (IPV6_LINK_LOCAL_ALL_NODES, Ieee802154Address::BROADCAST, 1),
            (
                Ipv6Address::new(0xff05, 0, 0, 0, 0, 0, 0x0001, 0x0203),
                Ieee802154Address::BROADCAST,
                4,
            ),
            (
                Ipv6Address::new(0xff05, 0, 0, 0, 0, 0x0001, 0x0203, 0x0405),
                Ieee802154Address::BROADCAST,
                6,
            ),
            (
                Ipv6Address::new(0xff15, 0x1234, 0, 0, 0, 0, 0, 1),
                Ieee802154Address::BROADCAST,
                16,
            ),
        ];
        let hbh = [0x01, 0x04, 0, 0, 0, 0];

        let mut cases = 0;
        for &(src, src_ll, src_len) in unicast.iter().chain([(Ipv6Address::UNSPECIFIED, OUR_LL, 0)].iter()) {
            for &(dst, dst_ll, dst_len) in unicast.iter().chain(multicast) {
                for hop_limit in [1u8, 64, 255, 17] {
                    for (kind, ports) in [
                        (0, None),
                        (1, Some((1234, 5678))),
                        (1, Some((0xf0b1, 0xf0b2))),
                        (1, Some((0xf012, 5678))),
                        (1, Some((1234, 0xf0ff))),
                        (2, None),
                        (3, Some((0xf0b1, 0xf0b2))),
                    ] {
                        // The upper layer: an echo request, a UDP datagram, or
                        // either behind a hop-by-hop header.
                        let (next_header, l4) = match ports {
                            None => (
                                IpProtocol::Icmpv6,
                                icmpv6_echo(Icmpv6Message::EchoRequest, 1, 2, b"payload", src, dst),
                            ),
                            Some((s, d)) => (IpProtocol::Udp, udp_datagram(src.into(), s, dst.into(), d, b"payload")),
                        };
                        let (first, upper) = if kind >= 2 {
                            let mut ext = vec![u8::from(next_header), 0];
                            ext.extend_from_slice(&hbh);
                            ext.extend_from_slice(&l4);
                            (IpProtocol::HopByHop, ext)
                        } else {
                            (next_header, l4)
                        };
                        let mut packet = ipv6_packet(src, dst, first, &upper);
                        Ipv6Packet::new_unchecked(&mut packet[..]).set_hop_limit(hop_limit);

                        let iphc_len = 2
                            + src_len
                            + dst_len
                            + usize::from(hop_limit != 1 && hop_limit != 64 && hop_limit != 255)
                            + usize::from(kind == 0);
                        let ext_len = if kind >= 2 {
                            2 + usize::from(kind == 2) + hbh.len()
                        } else {
                            0
                        };
                        let udp_len = match ports {
                            None => 0,
                            Some((0xf0b0..=0xf0bf, 0xf0b0..=0xf0bf)) => 4,
                            Some((0xf000..=0xf0ff, _)) | Some((_, 0xf000..=0xf0ff)) => 6,
                            Some(_) => 7,
                        };
                        let expected_len = iphc_len + ext_len + udp_len + packet.len()
                            - 40
                            - ext_len.min(8) * 0
                            - if kind >= 2 { 8 } else { 0 }
                            - if ports.is_some() { 8 } else { 0 };

                        for headroom in [0, 14, 64] {
                            let (compressed, header_diff) = compress(&packet, src_ll, dst_ll, headroom);
                            assert_eq!(
                                compressed.len(),
                                expected_len,
                                "{src} {dst} {hop_limit} {kind} {ports:?}"
                            );
                            assert_eq!(header_diff, packet.len() - compressed.len());
                            for headroom in [0, 14, 64] {
                                let decompressed =
                                    decompress(&compressed, src_ll, dst_ll, &[], headroom, None).unwrap();
                                assert_eq!(decompressed, packet, "{src} {dst} {hop_limit} {kind} {ports:?}");
                            }
                        }
                        cases += 1;
                    }
                }
            }
        }
        assert!(cases > 500);
    }

    /// Compression fails cleanly when the packet does not fit the buffer with
    /// the extra headroom the compressed chain needs.
    #[test]
    fn test_compress_no_room() {
        let src = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut buf = PacketBuf::try_new().unwrap();
        let len = buf.capacity();
        buf.set_len(len);
        let datagram = udp_datagram(src.into(), 1234, dst.into(), 5678, &vec![0; len - 48]);
        buf.copy_from_slice(&ipv6_packet(src, dst, IpProtocol::Udp, &datagram));
        assert!(ipv6_to_sixlowpan(&mut buf, &mac_repr(OUR_LL, PEER_LL, None)).is_err());
    }

    // The Contiki-NG vectors: a 128-byte ping in two fragments. The old tests
    // ran with checksum verification off, and the ICMPv6 and UDP checksums the
    // vectors came with do not match their contents; they are corrected here
    // (0xe071 -> 0xe865, 0xbfa0 -> 0xc794).

    const REQUEST_FIRST_PART: [u8; 98] = [
        0xc0, 0xb0, 0x00, 0x8e, 0x6a, 0x33, 0x05, 0x25, 0x2c, 0x3a, 0x80, 0x00, 0xe8, 0x65, 0x00, 0x27, 0x00, 0x02,
        0xa2, 0xc2, 0x2d, 0x63, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x5e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];

    const REQUEST_SECOND_PART: [u8; 53] = [
        0xe0, 0xb0, 0x00, 0x8e, 0x10, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
        0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
    ];

    /// Data that was generated when using `ping -s 128`.
    const PING_DATA: [u8; 128] = [
        0xa2, 0xc2, 0x2d, 0x63, 0x00, 0x00, 0x00, 0x00, 0xd9, 0x5e, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d,
        0x7e, 0x7f,
    ];

    /// A stack with the old harness's address and the vectors' address, for
    /// the Contiki-NG vectors.
    #[cfg(all(feature = "sixlowpan-fragmentation", feature = "sixlowpan-reassembly"))]
    fn vector_stack() -> (Stack<'static>, IfaceHandle, Queue, Sent, Room) {
        let (mut stack, iface, rx, tx, room) = test_stack(TWO_LL, None);
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(VECTOR_LINK_LOCAL.into(), 10))
            .unwrap();
        stack.poll(Instant::ZERO);
        tx.borrow_mut().clear();
        (stack, iface, rx, tx, room)
    }

    #[test]
    #[cfg(all(feature = "sixlowpan-fragmentation", feature = "sixlowpan-reassembly"))]
    fn test_echo_request_sixlowpan_128_bytes() {
        // The first fragment's IPHC header resolves against the frame addresses.
        {
            let frag = SixlowpanFragRepr::parse(&REQUEST_FIRST_PART).unwrap();
            let payload = &REQUEST_FIRST_PART[frag.buffer_len()..];
            let (repr, _) = SixlowpanIphcRepr::parse(payload, Some(CONTIKI_LL), Some(VECTOR_LL), &[]).unwrap();
            assert_eq!(repr.src_addr, CONTIKI_LINK_LOCAL);
            assert_eq!(repr.dst_addr, VECTOR_LINK_LOCAL);
        }

        // The compressed reply the old test expected, minus its zeroed checksum.
        let mut expected = vec![0x7a, 0x11, 0x3a];
        expected.extend_from_slice(&VECTOR_LINK_LOCAL.octets()[8..]);
        expected.extend_from_slice(&CONTIKI_LINK_LOCAL.octets()[8..]);
        expected.extend_from_slice(&[0x81, 0x00, 0x00, 0x00, 0x00, 0x27, 0x00, 0x02]);
        expected.extend_from_slice(&PING_DATA);

        for room_limit in [None, Some(1)] {
            let (mut stack, iface, rx, tx, room) = vector_stack();
            fill_neighbor(&mut stack, iface, CONTIKI_LINK_LOCAL, ZERO_LL);
            room.set(room_limit);

            inject(&mut stack, &rx, frame(CONTIKI_LL, VECTOR_LL, PAN, &REQUEST_FIRST_PART));
            assert!(tx.borrow().is_empty());
            inject(&mut stack, &rx, frame(CONTIKI_LL, VECTOR_LL, PAN, &REQUEST_SECOND_PART));

            if room_limit.is_some() {
                // The device took one fragment; the next poll sends the other.
                assert_eq!(tx.borrow().len(), 1);
                room.set(Some(1));
                stack.poll(Instant::ZERO);
            }
            assert_eq!(tx.borrow().len(), 2);

            for frame in tx.borrow().iter() {
                let (repr, _) = parse_frame(frame);
                assert_eq!(repr.dst_addr, Some(ZERO_LL));
                assert_eq!(repr.src_addr, Some(TWO_LL));
                assert_eq!(repr.dst_pan_id, Some(Ieee802154Pan(0)));
            }
            let (size, _tag, offsets, compressed) = reassemble_frames(&tx.borrow());
            assert_eq!(size, 136 + 40);
            assert_eq!(offsets, [0, 120]);
            assert_eq!(compressed.len(), expected.len());
            assert_eq!(compressed[..21], expected[..21]);
            assert_eq!(compressed[23..], expected[23..]);

            let mut packet = decompress(&compressed, TWO_LL, ZERO_LL, &[], 0, None).unwrap();
            let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
            assert_eq!(ip.src_addr(), VECTOR_LINK_LOCAL);
            assert_eq!(ip.dst_addr(), CONTIKI_LINK_LOCAL);
            assert_eq!(ip.payload_len(), 136);
            let mut payload = ip.payload().to_vec();
            let icmp = Icmpv6Packet::new_checked(&mut payload[..]).unwrap();
            assert!(icmp.verify_checksum(&VECTOR_LINK_LOCAL, &CONTIKI_LINK_LOCAL));
            assert_eq!(icmp.msg_type(), Icmpv6Message::EchoReply);
            assert_eq!(icmp.echo_ident(), 39);
            assert_eq!(icmp.echo_seq_no(), 2);
            assert_eq!(icmp.payload(), &PING_DATA);
        }
    }

    const UDP_FIRST_PART: [u8; 104] = [
        0xc0, 0xbc, 0x00, 0x92, 0x6e, 0x33, 0x07, 0xe7, 0xdc, 0xf0, 0xd3, 0xc9, 0x1b, 0x39, 0xc7, 0x94, 0x4c, 0x6f,
        0x72, 0x65, 0x6d, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6d, 0x20, 0x64, 0x6f, 0x6c, 0x6f, 0x72, 0x20, 0x73, 0x69,
        0x74, 0x20, 0x61, 0x6d, 0x65, 0x74, 0x2c, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75,
        0x72, 0x20, 0x61, 0x64, 0x69, 0x70, 0x69, 0x73, 0x63, 0x69, 0x6e, 0x67, 0x20, 0x65, 0x6c, 0x69, 0x74, 0x2e,
        0x20, 0x49, 0x6e, 0x20, 0x61, 0x74, 0x20, 0x72, 0x68, 0x6f, 0x6e, 0x63, 0x75, 0x73, 0x20, 0x74, 0x6f, 0x72,
        0x74, 0x6f, 0x72, 0x2e, 0x20, 0x43, 0x72, 0x61, 0x73, 0x20, 0x62, 0x6c, 0x61, 0x6e,
    ];

    const UDP_SECOND_PART: [u8; 57] = [
        0xe0, 0xbc, 0x00, 0x92, 0x11, 0x64, 0x69, 0x74, 0x20, 0x74, 0x65, 0x6c, 0x6c, 0x75, 0x73, 0x20, 0x64, 0x69,
        0x61, 0x6d, 0x2c, 0x20, 0x76, 0x61, 0x72, 0x69, 0x75, 0x73, 0x20, 0x76, 0x65, 0x73, 0x74, 0x69, 0x62, 0x75,
        0x6c, 0x75, 0x6d, 0x20, 0x6e, 0x69, 0x62, 0x68, 0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x64, 0x6f, 0x20, 0x6e,
        0x65, 0x63, 0x2e,
    ];

    const UDP_DATA: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
In at rhoncus tortor. Cras blandit tellus diam, varius vestibulum nibh commodo nec.";

    #[test]
    #[cfg(all(feature = "sixlowpan-fragmentation", feature = "sixlowpan-reassembly"))]
    fn test_sixlowpan_udp_with_fragmentation() {
        let (mut stack, iface, rx, tx, _room) = vector_stack();
        let udp = stack.add_udp_socket().unwrap();
        stack
            .udp_socket(udp)
            .bind((VECTOR_LINK_LOCAL, 6969), IpListenEndpoint::UNSPECIFIED)
            .unwrap();

        inject(&mut stack, &rx, frame(CONTIKI_LL, VECTOR_LL, PAN, &UDP_FIRST_PART));
        assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
        inject(&mut stack, &rx, frame(CONTIKI_LL, VECTOR_LL, PAN, &UDP_SECOND_PART));

        let remote = IpEndpoint::new(CONTIKI_LINK_LOCAL.into(), 54217);
        {
            let mut socket = stack.udp_socket(udp);
            let received = socket.recv().unwrap();
            assert_eq!(&*received, UDP_DATA);
            assert_eq!(received.meta().endpoint, remote);
            assert_eq!(received.meta().local_address, Some(VECTOR_LINK_LOCAL.into()));
        }
        assert!(tx.borrow().is_empty());

        // Echo it back: the datagram does not fit one frame.
        fill_neighbor(&mut stack, iface, CONTIKI_LINK_LOCAL, ZERO_LL);
        stack.udp_socket(udp).send_slice(UDP_DATA, remote).unwrap();
        assert_eq!(tx.borrow().len(), 2);
        let (size, _tag, offsets, compressed) = reassemble_frames(&tx.borrow());
        assert_eq!(size as usize, 40 + 8 + UDP_DATA.len());
        assert_eq!(offsets[0], 0);
        let mut packet = decompress(&compressed, TWO_LL, ZERO_LL, &[], 0, None).unwrap();
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        assert_eq!(ip.src_addr(), VECTOR_LINK_LOCAL);
        assert_eq!(ip.dst_addr(), CONTIKI_LINK_LOCAL);
        assert_eq!(ip.next_header(), IpProtocol::Udp);
        let mut payload = ip.payload().to_vec();
        let udp = UdpPacket::new_checked(&mut payload[..]).unwrap();
        assert!(udp.verify_checksum(&VECTOR_LINK_LOCAL.into(), &CONTIKI_LINK_LOCAL.into()));
        assert_eq!((udp.src_port(), udp.dst_port()), (6969, 54217));
        assert_eq!(udp.payload(), UDP_DATA);
    }

    /// A stack with a UDP socket bound to 6969 and the peer resolved, and a
    /// datagram from the peer that takes two fragments.
    #[cfg(any(feature = "sixlowpan-fragmentation", feature = "sixlowpan-reassembly"))]
    fn reassembly_stack() -> (Stack<'static>, IfaceHandle, Queue, Sent, Room, crate::udp::UdpHandle) {
        let (mut stack, iface, rx, tx, room) = test_stack(OUR_LL, Some(PAN));
        fill_neighbor(&mut stack, iface, PEER_LINK_LOCAL, PEER_LL);
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(6969, IpListenEndpoint::UNSPECIFIED).unwrap();
        (stack, iface, rx, tx, room, udp)
    }

    #[cfg(feature = "sixlowpan-reassembly")]
    fn big_datagram(tag: u16) -> Vec<Vec<u8>> {
        let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let datagram = udp_datagram(PEER_LINK_LOCAL.into(), 1234, OUR_LINK_LOCAL.into(), 6969, &payload);
        let packet = ipv6_packet(PEER_LINK_LOCAL, OUR_LINK_LOCAL, IpProtocol::Udp, &datagram);
        let frames = fragments(&packet, PEER_LL, OUR_LL, tag);
        assert_eq!(frames.len(), 4);
        frames
    }

    #[cfg(feature = "sixlowpan-reassembly")]
    fn check_received(stack: &mut Stack, udp: crate::udp::UdpHandle) {
        let mut socket = stack.udp_socket(udp);
        let received = socket.recv().unwrap();
        assert_eq!(received.len(), 300);
        assert!(received.iter().enumerate().all(|(i, &b)| b == i as u8));
        assert_eq!(received.meta().endpoint, IpEndpoint::new(PEER_LINK_LOCAL.into(), 1234));
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));
    }

    #[test]
    #[cfg(feature = "sixlowpan-reassembly")]
    fn test_reassembly_out_of_order() {
        let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
        let frames = big_datagram(1);
        for i in [2, 0, 3] {
            inject(&mut stack, &rx, frames[i].clone());
            assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
        }
        inject(&mut stack, &rx, frames[1].clone());
        check_received(&mut stack, udp);
    }

    #[test]
    #[cfg(feature = "sixlowpan-reassembly")]
    fn test_reassembly_duplicates() {
        let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
        let frames = big_datagram(1);
        for i in [0, 0, 1, 2, 1, 0] {
            inject(&mut stack, &rx, frames[i].clone());
            assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
        }
        inject(&mut stack, &rx, frames[3].clone());
        check_received(&mut stack, udp);
        // Late duplicates start a new, never completed, reassembly.
        inject(&mut stack, &rx, frames[3].clone());
        assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
    }

    /// A fragment whose datagram size disagrees belongs to another datagram,
    /// and with one reassembly slot it is dropped.
    #[test]
    #[cfg(feature = "sixlowpan-reassembly")]
    fn test_reassembly_size_mismatch() {
        let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
        let frames = big_datagram(1);
        inject(&mut stack, &rx, frames[0].clone());
        let mut wrong = frames[1].clone();
        let mac_len = mac_repr(PEER_LL, OUR_LL, Some(PAN)).buffer_len();
        wrong[mac_len + 1] += 8;
        inject(&mut stack, &rx, wrong);
        inject(&mut stack, &rx, frames[2].clone());
        inject(&mut stack, &rx, frames[3].clone());
        assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
        inject(&mut stack, &rx, frames[1].clone());
        check_received(&mut stack, udp);
    }

    #[test]
    #[cfg(feature = "sixlowpan-reassembly")]
    fn test_reassembly_timeout() {
        let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
        stack.set_reassembly_timeout(Duration::from_secs(1));
        let frames = big_datagram(1);
        inject(&mut stack, &rx, frames[0].clone());
        inject(&mut stack, &rx, frames[1].clone());
        inject(&mut stack, &rx, frames[2].clone());
        assert_eq!(stack.poll(Instant::ZERO), Instant::from_secs(1));
        // The fragments are forgotten by then: the last one alone completes nothing.
        stack.poll(Instant::from_secs(2));
        assert_eq!(stack.poll(Instant::from_secs(2)), Instant::MAX);
        inject(&mut stack, &rx, frames[3].clone());
        assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
    }

    /// With every reassembly slot in use, fragments of another datagram are dropped.
    #[test]
    #[cfg(feature = "sixlowpan-reassembly")]
    fn test_reassembly_slots_full() {
        use crate::config::REASSEMBLY_BUFFER_COUNT;
        let (mut stack, _iface, rx, _tx, _room, udp) = reassembly_stack();
        for tag in 0..REASSEMBLY_BUFFER_COUNT as u16 {
            inject(&mut stack, &rx, big_datagram(100 + tag)[0].clone());
        }
        let frames = big_datagram(1);
        for frame in &frames {
            inject(&mut stack, &rx, frame.clone());
        }
        assert_eq!(stack.udp_socket(udp).recv().err(), Some(RecvError::Exhausted));
        // Completing one of the blockers frees its slot.
        let blocker = big_datagram(100);
        for frame in &blocker[1..] {
            inject(&mut stack, &rx, frame.clone());
        }
        check_received(&mut stack, udp);
        for frame in &frames {
            inject(&mut stack, &rx, frame.clone());
        }
        check_received(&mut stack, udp);
    }

    /// While the fragments of one packet are going out, the sockets are held
    /// back; the fragments go out as the device makes room.
    #[test]
    #[cfg(feature = "sixlowpan-fragmentation")]
    fn test_fragmenter_holds_sockets_back() {
        let (mut stack, _iface, _rx, tx, room, udp) = reassembly_stack();
        let remote = IpEndpoint::new(PEER_LINK_LOCAL.into(), 1234);
        let payload = vec![0x55; 300];

        room.set(Some(1));
        assert_eq!(stack.udp_socket(udp).send_slice(&payload, remote), Ok(()));
        assert_eq!(tx.borrow().len(), 1);

        room.set(Some(10));
        assert_eq!(
            stack.udp_socket(udp).send_slice(&payload, remote),
            Err(SendError::DeviceBusy)
        );
        assert_eq!(tx.borrow().len(), 1);

        stack.poll(Instant::ZERO);
        assert_eq!(tx.borrow().len(), 4);
        let (size, _tag, offsets, compressed) = reassemble_frames(&tx.borrow());
        assert_eq!(size as usize, 48 + 300);
        assert!(offsets.windows(2).all(|w| w[0] < w[1]));
        let mut packet = decompress(&compressed, OUR_LL, PEER_LL, &[], 0, None).unwrap();
        let ip = Ipv6Packet::new_checked(&mut packet[..]).unwrap();
        let mut l4 = ip.payload().to_vec();
        let udp_packet = UdpPacket::new_checked(&mut l4[..]).unwrap();
        assert!(udp_packet.verify_checksum(&OUR_LINK_LOCAL.into(), &PEER_LINK_LOCAL.into()));
        assert_eq!(udp_packet.payload(), &payload[..]);

        assert_eq!(stack.udp_socket(udp).send_slice(&payload, remote), Ok(()));
        assert_eq!(tx.borrow().len(), 8);
    }

    /// A packet parked on a neighbor resolution is not flushed into a busy
    /// fragmenter; it goes out, fragmented, once the fragmenter is free.
    #[test]
    #[cfg(feature = "sixlowpan-fragmentation")]
    fn test_parked_packet_waits_for_fragmenter() {
        let (mut stack, _iface, rx, tx, room, udp) = reassembly_stack();
        let other_ll = Ieee802154Address::Extended([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let other = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let payload = vec![0x55; 300];

        // Park a big packet on the unresolved neighbor: only a solicitation goes out.
        assert_eq!(
            stack
                .udp_socket(udp)
                .send_slice(&payload, IpEndpoint::new(other.into(), 1)),
            Ok(())
        );
        assert_eq!(tx.borrow().len(), 1);
        tx.borrow_mut().clear();

        // Make the fragmenter busy with a packet to the resolved peer.
        room.set(Some(1));
        assert_eq!(
            stack
                .udp_socket(udp)
                .send_slice(&payload, IpEndpoint::new(PEER_LINK_LOCAL.into(), 1)),
            Ok(())
        );
        assert_eq!(tx.borrow().len(), 1);

        // The neighbor resolves: its packet stays parked.
        room.set(None);
        let na = ndisc_packet(
            Icmpv6Message::NeighborAdvert,
            other,
            OUR_LINK_LOCAL,
            other,
            NdiscOptionType::TargetLinkLayerAddr,
            other_ll,
        );
        let (compressed, _) = compress(&na, other_ll, OUR_LL, 0);
        rx.borrow_mut().push_back(frame(other_ll, OUR_LL, PAN, &compressed));
        stack.poll(Instant::ZERO);
        // The poll that processed the advertisement also drained the fragmenter.
        assert_eq!(tx.borrow().len(), 4);
        for frame in tx.borrow().iter() {
            assert_eq!(parse_frame(frame).0.dst_addr, Some(PEER_LL));
        }
        // The next poll flushes the parked packet, in fragments.
        stack.poll(Instant::ZERO);
        assert_eq!(tx.borrow().len(), 8);
        for frame in tx.borrow()[4..].iter() {
            assert_eq!(parse_frame(frame).0.dst_addr, Some(other_ll));
        }
        let (size, _tag, _offsets, compressed) = reassemble_frames(&tx.borrow()[4..]);
        assert_eq!(size as usize, 48 + 300);
        let mut packet = decompress(&compressed, OUR_LL, other_ll, &[], 0, None).unwrap();
        assert_eq!(Ipv6Packet::new_checked(&mut packet[..]).unwrap().dst_addr(), other);
    }
}
