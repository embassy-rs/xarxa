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
use crate::stack::{Blocked, StackInner};
use crate::wire::*;

/// The packet an interface is sending in fragments, if any.
pub(crate) enum Fragmenter {
    /// No packet.
    Idle,
    /// An IPv4 packet larger than the interface's IP MTU.
    #[cfg(feature = "ipv4-fragmentation")]
    Ipv4(Ipv4Fragmenter),
    /// A compressed 6LoWPAN packet larger than an IEEE 802.15.4 frame.
    #[cfg(feature = "sixlowpan-fragmentation")]
    Sixlowpan(SixlowpanFragmenter),
}

#[cfg(feature = "ipv4-fragmentation")]
pub(crate) struct Ipv4Fragmenter {
    /// The IP packet, header included.
    pub buffer: PacketBuf,
    /// Where the fragments go on the link: the resolved next hop, or nowhere
    /// on an IP medium.
    pub link_dst: HardwareAddress,
    /// The identification every fragment carries.
    pub ident: u16,
    /// The offset of the next fragment in the packet's payload.
    pub frag_offset: u16,
}

#[cfg(feature = "sixlowpan-fragmentation")]
pub(crate) struct SixlowpanFragmenter {
    /// The compressed packet, from the IPHC header on.
    pub buffer: PacketBuf,
    /// How much of it was sent.
    pub sent_bytes: usize,
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

impl Fragmenter {
    /// Whether no packet is being sent in fragments.
    #[inline]
    pub(crate) fn is_idle(&self) -> bool {
        matches!(self, Fragmenter::Idle)
    }
}

impl StackInner {
    /// Transmit the fragments still waiting in the interface's fragmenter.
    ///
    /// Fragments go out while the device has room for them and the pool has
    /// buffers. The rest wait in the fragmenter for the next poll, and the error
    /// says which of the two ran out.
    ///
    /// A packet only gets here once its next hop is resolved, so the fragments
    /// go straight to the link layer.
    pub(crate) fn fragment_egress(&mut self, iface: &mut IfaceState<'_>) -> Result<(), Blocked> {
        loop {
            // The packet's metadata rides on its first fragment.
            let first_meta = match &iface.fragmenter {
                Fragmenter::Idle => return Ok(()),
                #[cfg(feature = "ipv4-fragmentation")]
                Fragmenter::Ipv4(frag) => (frag.frag_offset == 0).then(|| frag.buffer.meta()),
                #[cfg(feature = "sixlowpan-fragmentation")]
                Fragmenter::Sixlowpan(frag) => (frag.sent_bytes == 0).then(|| frag.buffer.meta()),
            };
            if !iface.can_transmit() {
                trace!("fragmenter: device has no room, fragments wait");
                return Err(Blocked::DeviceBusy);
            }
            let Some(mut tx_buffer) = self.pool.alloc() else {
                trace!("fragmenter: no packet buffer, fragments wait");
                return Err(Blocked::NoBuffer);
            };
            if let Some(meta) = first_meta {
                tx_buffer.set_meta(meta);
            }
            match iface.fragmenter {
                Fragmenter::Idle => {}
                #[cfg(feature = "ipv4-fragmentation")]
                Fragmenter::Ipv4(_) => self.dispatch_ipv4_frag(iface, tx_buffer),
                #[cfg(feature = "sixlowpan-fragmentation")]
                Fragmenter::Sixlowpan(_) => self.dispatch_ieee802154_frag(iface, tx_buffer),
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

    /// Fragment an IPv4 packet larger than the interface's MTU, whose next hop
    /// is resolved to `link_dst`, and start transmitting the fragments.
    pub(crate) fn fragment_ipv4(&mut self, iface: &mut IfaceState<'_>, link_dst: HardwareAddress, mut buf: PacketBuf) {
        debug!("start fragmentation");

        if !iface.fragmenter.is_idle() {
            debug!("Fragmentation buffer is busy. Dropping");
            return;
        }

        let ip_header_len = Ipv4Packet::new_unchecked(&mut buf).header_len() as usize;
        if iface.max_ipv4_fragment_size(ip_header_len) == 0 {
            debug!("MTU too small to fragment. Dropping");
            return;
        }

        // Keep the packet, and where its fragments go.
        iface.fragmenter = Fragmenter::Ipv4(Ipv4Fragmenter {
            buffer: buf,
            link_dst,
            ident: self.next_ipv4_frag_ident(),
            frag_offset: 0,
        });

        // Transmit as many fragments as the device takes now. The rest go
        // out on the next polls, which also schedule the retry if the pool ran out.
        let _ = self.fragment_egress(iface);
    }

    /// Fill `tx_buffer` with the next fragment of the IPv4 packet in the
    /// interface's fragmenter, and transmit it.
    fn dispatch_ipv4_frag(&mut self, iface: &mut IfaceState<'_>, mut tx_buffer: PacketBuf) {
        let ip_mtu = iface.ip_mtu;
        let checksum_caps = iface.checksum_caps();
        tx_buffer.reserve(iface.ip_headroom);
        let Fragmenter::Ipv4(frag) = &mut iface.fragmenter else {
            return;
        };

        let ip_header_len = Ipv4Packet::new_unchecked(&mut frag.buffer).header_len() as usize;
        let remaining = frag.buffer.len() - ip_header_len - frag.frag_offset as usize;
        let payload_len = remaining.min(max_ipv4_fragment_size(ip_mtu, ip_header_len));
        let more_frags = remaining != payload_len;
        let ip_len = ip_header_len + payload_len;

        tx_buffer.set_len(ip_len);
        // Copy the IP header and the payload.
        tx_buffer[..ip_header_len].copy_from_slice(&frag.buffer[..ip_header_len]);
        tx_buffer[ip_header_len..]
            .copy_from_slice(&frag.buffer[ip_header_len + frag.frag_offset as usize..][..payload_len]);

        let mut packet = Ipv4Packet::new_unchecked(&mut tx_buffer);
        packet.set_total_len(ip_len as u16);
        packet.set_ident(frag.ident);
        packet.set_more_frags(more_frags);
        packet.set_dont_frag(false);
        packet.set_frag_offset(frag.frag_offset);
        if !checksum_caps.ipv4.tx {
            packet.fill_checksum();
        } else {
            packet.set_checksum(0);
        }

        frag.frag_offset += payload_len as u16;
        let link_dst = frag.link_dst;
        if !more_frags {
            iface.fragmenter = Fragmenter::Idle;
        }
        match link_dst {
            #[cfg(feature = "medium-ethernet")]
            HardwareAddress::Ethernet(addr) => self.transmit_ethernet(iface, addr, tx_buffer, EthernetProtocol::Ipv4),
            // An IP medium. IEEE 802.15.4 takes no IPv4.
            #[allow(unreachable_patterns)]
            _ => self.transmit_raw(iface, tx_buffer),
        }
    }
}

/// The largest IPv4 fragment payload for an interface of IP MTU `ip_mtu`, a
/// multiple of 8 as the offset field requires.
#[cfg(feature = "ipv4-fragmentation")]
fn max_ipv4_fragment_size(ip_mtu: usize, ip_header_len: usize) -> usize {
    let payload_mtu = ip_mtu.saturating_sub(ip_header_len);
    payload_mtu - (payload_mtu % IPV4_FRAGMENT_PAYLOAD_ALIGNMENT)
}

#[cfg(feature = "ipv4-fragmentation")]
impl IfaceState<'_> {
    /// The maximum IPv4 payload fragment size, aligned per spec.
    pub(crate) fn max_ipv4_fragment_size(&self, ip_header_len: usize) -> usize {
        max_ipv4_fragment_size(self.ip_mtu, ip_header_len)
    }
}
