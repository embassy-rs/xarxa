//! Fragmentation of outgoing packets: IPv4 (feature `ipv4-fragmentation`) and
//! 6LoWPAN (feature `sixlowpan-fragmentation`).
//!
//! The packet is built whole first, then kept in the interface's [`Fragmenter`]
//! while its fragments are copied out into fresh buffers, one per fragment. For
//! IPv4 the IP header is byte-copied and patched onto each; for 6LoWPAN the
//! compressed packet is cut into pieces behind fragment headers. Fragmentation
//! pays one extra copy, on purpose: it is a fallback path.

use crate::driver::PacketBuf;
use crate::iface::IfaceState;
#[cfg(feature = "ipv4-fragmentation")]
use crate::rand::Rand;
use crate::stack::StackInner;
use crate::wire::*;

pub(crate) struct Fragmenter {
    /// The packet being fragmented: the IP packet, header included, or the
    /// compressed 6LoWPAN packet. `None` when there is nothing to transmit.
    pub buffer: Option<PacketBuf>,
    /// The size of the packet.
    pub packet_len: usize,
    /// The amount of bytes that already have been transmitted.
    pub sent_bytes: usize,

    #[cfg(feature = "ipv4-fragmentation")]
    pub ipv4: Ipv4Fragmenter,
    #[cfg(feature = "sixlowpan-fragmentation")]
    pub sixlowpan: SixlowpanFragmenter,
}

#[cfg(feature = "sixlowpan-fragmentation")]
pub(crate) struct SixlowpanFragmenter {
    /// The size of the whole IPv6 datagram.
    pub datagram_size: u16,
    /// The tag every fragment of the datagram carries.
    pub datagram_tag: u16,
    /// The offset of the next fragment, in bytes of the uncompressed datagram.
    pub datagram_offset: usize,
    /// The payload size of the first fragment.
    pub frag1_size: usize,
    /// The payload size of every fragment but the first (the last may be shorter).
    pub fragn_size: usize,
    /// The bytes compression took off the header chain.
    pub header_diff: usize,
    /// The link-layer destination address.
    pub ll_dst_addr: Ieee802154Address,
    /// The link-layer source address.
    pub ll_src_addr: Ieee802154Address,
}

#[cfg(feature = "sixlowpan-fragmentation")]
impl SixlowpanFragmenter {
    const fn new() -> Self {
        Self {
            datagram_size: 0,
            datagram_tag: 0,
            datagram_offset: 0,
            frag1_size: 0,
            fragn_size: 0,
            header_diff: 0,
            ll_dst_addr: Ieee802154Address::Absent,
            ll_src_addr: Ieee802154Address::Absent,
        }
    }
}

#[cfg(feature = "ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The destination address.
    pub dst_addr: IpAddress,
    /// The next hop the packet was routed to.
    pub next_hop: IpAddress,
    /// The offset of the next fragment.
    pub frag_offset: u16,
    /// The identifier of the stream.
    pub ident: u16,
}

impl Fragmenter {
    pub(crate) fn new() -> Self {
        Self {
            buffer: None,
            packet_len: 0,
            sent_bytes: 0,

            #[cfg(feature = "ipv4-fragmentation")]
            ipv4: Ipv4Fragmenter {
                dst_addr: IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
                next_hop: IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
                frag_offset: 0,
                ident: 0,
            },
            #[cfg(feature = "sixlowpan-fragmentation")]
            sixlowpan: SixlowpanFragmenter::new(),
        }
    }

    /// Return `true` when everything is transmitted.
    #[inline]
    pub(crate) fn finished(&self) -> bool {
        self.packet_len == self.sent_bytes
    }

    /// Returns `true` when there is nothing to transmit.
    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.packet_len == 0
    }

    // Reset the buffer.
    pub(crate) fn reset(&mut self) {
        self.buffer = None;
        self.packet_len = 0;
        self.sent_bytes = 0;

        #[cfg(feature = "ipv4-fragmentation")]
        {
            self.ipv4.dst_addr = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);
            self.ipv4.next_hop = IpAddress::Ipv4(Ipv4Address::UNSPECIFIED);
            self.ipv4.frag_offset = 0;
            self.ipv4.ident = 0;
        }
        #[cfg(feature = "sixlowpan-fragmentation")]
        {
            self.sixlowpan = SixlowpanFragmenter::new();
        }
    }
}

impl StackInner {
    /// Transmit the fragments still waiting in the interface's fragmenter.
    ///
    /// An IEEE 802.15.4 interface's fragmenter holds a 6LoWPAN packet, any
    /// other's an IPv4 packet.
    pub(crate) fn fragment_egress(&mut self, iface: &mut IfaceState<'_>) {
        match iface.medium() {
            #[cfg(feature = "medium-ieee802154")]
            crate::iface::Medium::Ieee802154 => {
                #[cfg(feature = "sixlowpan-fragmentation")]
                self.sixlowpan_egress(iface);
            }
            #[allow(unreachable_patterns)]
            _ => {
                #[cfg(feature = "ipv4-fragmentation")]
                self.ipv4_egress(iface);
            }
        }
    }
}

/// The first IPv4 fragment identifier, drawn from the PRNG.
#[cfg(feature = "ipv4-fragmentation")]
pub(crate) fn initial_ipv4_id(rand: &mut Rand) -> u16 {
    loop {
        let ipv4_id = rand.rand_u16();
        if ipv4_id != 0 {
            return ipv4_id;
        }
    }
}

#[cfg(feature = "ipv4-fragmentation")]
impl StackInner {
    /// Get the next IPv4 fragment identifier.
    pub(crate) fn next_ipv4_frag_ident(&mut self) -> u16 {
        let ipv4_id = self.ipv4_id;
        self.ipv4_id = self.ipv4_id.wrapping_add(1);
        ipv4_id
    }

    /// Fragment an IPv4 packet larger than the interface's MTU, and start
    /// transmitting the fragments.
    pub(crate) fn fragment_ipv4(
        &mut self,
        iface: &mut IfaceState<'_>,
        dst_addr: IpAddress,
        next_hop: IpAddress,
        mut buf: PacketBuf,
    ) {
        debug!("start fragmentation");

        let total_ip_len = buf.len();

        let frag = &mut iface.fragmenter;
        if !frag.is_empty() {
            debug!("Fragmentation buffer is busy. Dropping");
            return;
        }

        let ipv4_id = self.next_ipv4_frag_ident();
        let ip_header_len = Ipv4Packet::new_unchecked(&mut buf).header_len() as usize;
        if iface.max_ipv4_fragment_size(ip_header_len) == 0 {
            debug!("MTU too small to fragment. Dropping");
            return;
        }

        let frag = &mut iface.fragmenter;

        // Save the routing decision for the other fragments.
        frag.ipv4.dst_addr = dst_addr;
        frag.ipv4.next_hop = next_hop;

        // Save the total packet len (with the IP header).
        frag.packet_len = total_ip_len;

        // Only the header counts as sent: the fragments carry the payload.
        frag.sent_bytes = ip_header_len;

        frag.ipv4.ident = ipv4_id;
        frag.ipv4.frag_offset = 0;

        // Save the packet for the fragments to be copied out of.
        frag.buffer = Some(buf);

        // Transmit as many fragments as the device takes now. The rest go
        // out on the next polls.
        self.ipv4_egress(iface);
    }

    /// Process fragments that still need to be sent for IPv4 packets.
    ///
    /// Fragments go out while the device has room for them and the pool has
    /// buffers. The rest wait in the fragmenter for the next poll.
    pub(crate) fn ipv4_egress(&mut self, iface: &mut IfaceState<'_>) {
        if iface.fragmenter.is_empty() {
            return;
        }

        while !iface.fragmenter.finished() {
            if !iface.can_transmit() {
                trace!("fragmenter: device has no room, fragments wait");
                return;
            }
            if !self.dispatch_ipv4_frag(iface) {
                return;
            }
        }

        // Reset the buffer when we transmitted everything.
        iface.fragmenter.reset();
    }

    /// Transmit the next fragment of the packet in the interface's fragmenter.
    ///
    /// Returns `false` if no packet buffer is free, leaving the fragmenter as it was.
    fn dispatch_ipv4_frag(&mut self, iface: &mut IfaceState<'_>) -> bool {
        // NOTE(unwrap): the fragmenter is not empty, checked by the caller.
        let ip_header_len = Ipv4Packet::new_unchecked(unwrap!(iface.fragmenter.buffer.as_mut())).header_len() as usize;
        let max_fragment_size = iface.max_ipv4_fragment_size(ip_header_len);
        let checksum_caps = iface.checksum_caps();

        let frag = &mut iface.fragmenter;
        let payload_len = (frag.packet_len - frag.sent_bytes).min(max_fragment_size);
        let ip_len = payload_len + ip_header_len;

        let more_frags = (frag.packet_len - frag.sent_bytes) != payload_len;

        let Some(mut tx_buffer) = PacketBuf::try_new() else {
            trace!("fragmenter: no packet buffer, fragments wait");
            return false;
        };
        tx_buffer.reserve(LINK_HEADER_LEN);
        tx_buffer.set_len(ip_len);

        // NOTE(unwrap): checked above.
        let buffer = unwrap!(frag.buffer.as_ref());
        // Copy the IP header and the payload.
        tx_buffer[..ip_header_len].copy_from_slice(&buffer[..ip_header_len]);
        tx_buffer[ip_header_len..]
            .copy_from_slice(&buffer[frag.ipv4.frag_offset as usize + ip_header_len..][..payload_len]);

        let mut packet = Ipv4Packet::new_unchecked(&mut tx_buffer);
        packet.set_total_len(ip_len as u16);
        packet.set_ident(frag.ipv4.ident);
        packet.set_more_frags(more_frags);
        packet.set_dont_frag(false);
        packet.set_frag_offset(frag.ipv4.frag_offset);
        if !checksum_caps.ipv4.tx {
            packet.fill_checksum();
        } else {
            packet.set_checksum(0);
        }

        frag.sent_bytes += payload_len;

        // Update the frag offset for the next fragment.
        frag.ipv4.frag_offset += payload_len as u16;

        let (dst_addr, next_hop) = (frag.ipv4.dst_addr, frag.ipv4.next_hop);
        self.dispatch_ip(iface, dst_addr, next_hop, tx_buffer, EthernetProtocol::Ipv4);
        true
    }
}

#[cfg(feature = "ipv4-fragmentation")]
impl IfaceState<'_> {
    /// The maximum IPv4 payload fragment size, aligned per spec.
    pub(crate) fn max_ipv4_fragment_size(&self, ip_header_len: usize) -> usize {
        let payload_mtu = self.ip_mtu().saturating_sub(ip_header_len);
        payload_mtu - (payload_mtu % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
    }
}
