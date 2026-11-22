//! IPv6 header compression ([RFC 6282 § 3.1]).
//!
//! [RFC 6282 § 3.1]: https://datatracker.ietf.org/doc/html/rfc6282#section-3.1

use super::{AddressContext, DISPATCH_IPHC_HEADER, Malformed, NextHeader};
use crate::wire::take;
use crate::wire::{IpProtocol, ieee802154::Address as LlAddress, ipv6};

/// The largest IPHC header: the base, a context identifier, an inline traffic
/// class and flow label, next header, hop limit, and two full addresses.
pub const MAX_HEADER_LEN: usize = 2 + 1 + 4 + 1 + 1 + 16 + 16;

const LINK_LOCAL_PREFIX: [u8; 2] = [0xfe, 0x80];
const EUI64_MIDDLE_VALUE: [u8; 2] = [0xff, 0xfe];

/// The interface identifier an elided address takes from the link-layer
/// address (RFC 6282 § 3.2.2).
fn ll_iid(ll_addr: Option<LlAddress>) -> Result<[u8; 8], Malformed> {
    match ll_addr {
        Some(LlAddress::Short(ll)) => Ok([0, 0, 0, 0xff, 0xfe, 0, ll[0], ll[1]]),
        Some(addr @ LlAddress::Extended(_)) => addr.as_eui_64().ok_or(Malformed),
        Some(LlAddress::Absent) | None => Err(Malformed),
    }
}

/// Overwrite the prefix of `bytes` with the address context `index` refers to.
fn apply_context(addr_context: &[AddressContext], index: usize, bytes: &mut [u8; 16]) -> Result<(), Malformed> {
    let context = addr_context.get(index).ok_or(Malformed)?;
    bytes[..context.0.len()].copy_from_slice(&context.0);
    Ok(())
}

/// The fields of a 6LoWPAN IPHC header.
///
/// The link-layer addresses decide how much of each IPv6 address is elided,
/// so they are part of the header's fields: [`parse`](Self::parse) restores
/// elided bits from them and [`emit`](Self::emit) elides against them.
///
/// The header always starts with the following base format (from [RFC 6282 § 3.1.1]):
/// ```txt
///    0                                       1
///    0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
///  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
///  | 0 | 1 | 1 |  TF   |NH | HLIM  |CID|SAC|  SAM  | M |DAC|  DAM  |
///  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
/// ```
/// The fields that are not fully elided follow it inline.
///
/// [RFC 6282 § 3.1.1]: https://datatracker.ietf.org/doc/html/rfc6282#section-3.1.1
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Repr {
    pub src_addr: ipv6::Address,
    pub ll_src_addr: Option<LlAddress>,
    pub dst_addr: ipv6::Address,
    pub ll_dst_addr: Option<LlAddress>,
    pub next_header: NextHeader,
    pub hop_limit: u8,
    pub ecn: Option<u8>,
    pub dscp: Option<u8>,
    pub flow_label: Option<u16>,
}

impl core::fmt::Display for Repr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "IPHC src={} dst={} nxt-hdr={} hop-limit={}",
            self.src_addr, self.dst_addr, self.next_header, self.hop_limit
        )
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Repr {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "IPHC src={} dst={} nxt-hdr={} hop-limit={}",
            self.src_addr,
            self.dst_addr,
            self.next_header,
            self.hop_limit
        );
    }
}

/// How the interface identifier of a link-local address compresses against
/// the link-layer address: the SAM/DAM bits and the bytes carried inline.
fn compress_iid(octets: &[u8; 16], ll_addr: Option<LlAddress>) -> (u8, [u8; 16], usize) {
    let mut inline = [0u8; 16];
    let is_eui_64 = ll_addr
        .map(|addr| addr.as_eui_64().map(|addr| addr[..] == octets[8..]).unwrap_or(false))
        .unwrap_or(false);
    if octets[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
        if ll_addr == Some(LlAddress::Short([octets[14], octets[15]])) {
            // The address is derived from the frame's short address: elide it.
            (0b11, inline, 0)
        } else {
            // Elide everything but the short address the IID embeds.
            inline[..2].copy_from_slice(&octets[14..]);
            (0b10, inline, 2)
        }
    } else if is_eui_64 {
        // The address is derived from the frame's extended address: elide it.
        (0b11, inline, 0)
    } else {
        // Elide the link-local prefix, carry the IID.
        inline[..8].copy_from_slice(&octets[8..]);
        (0b01, inline, 8)
    }
}

/// Whether the address is in fe80::/64, the link-local prefix IPHC elides. Only
/// that exact prefix: the rest of fe80::/10 is link-local too, but carried whole.
fn is_link_local_64(addr: &ipv6::Address) -> bool {
    addr.segments()[..4] == [0xfe80, 0, 0, 0]
}

/// How a source address compresses: the SAC bit, the SAM bits, and the bytes
/// carried inline.
fn compress_src(addr: &ipv6::Address, ll_addr: Option<LlAddress>) -> (bool, u8, [u8; 16], usize) {
    let octets = addr.octets();
    if *addr == ipv6::Address::UNSPECIFIED {
        (true, 0b00, octets, 0)
    } else if is_link_local_64(addr) {
        let (sam, inline, len) = compress_iid(&octets, ll_addr);
        (false, sam, inline, len)
    } else {
        (false, 0b00, octets, 16)
    }
}

/// How a destination address compresses: the M bit, the DAM bits, and the
/// bytes carried inline. The DAC bit is always zero: contexts are never used
/// when emitting.
fn compress_dst(addr: &ipv6::Address, ll_addr: Option<LlAddress>) -> (bool, u8, [u8; 16], usize) {
    let octets = addr.octets();
    if addr.is_multicast() {
        let mut inline = [0u8; 16];
        if octets[1] == 0x02 && octets[2..15] == [0; 13] {
            // ff02::00XX
            inline[0] = octets[15];
            (true, 0b11, inline, 1)
        } else if octets[2..13] == [0; 11] {
            // ffXX::00XX:XXXX
            inline[0] = octets[1];
            inline[1..4].copy_from_slice(&octets[13..]);
            (true, 0b10, inline, 4)
        } else if octets[2..11] == [0; 9] {
            // ffXX::00XX:XXXX:XXXX
            inline[0] = octets[1];
            inline[1..6].copy_from_slice(&octets[11..]);
            (true, 0b01, inline, 6)
        } else {
            (true, 0b00, octets, 16)
        }
    } else if is_link_local_64(addr) {
        let (dam, inline, len) = compress_iid(&octets, ll_addr);
        (false, dam, inline, len)
    } else {
        (false, 0b00, octets, 16)
    }
}

impl Repr {
    /// Parse an IPHC header from the front of `buf`.
    ///
    /// Returns the header and its length. `ll_src_addr` and `ll_dst_addr` are
    /// the link-layer addresses of the frame the header arrived in, and
    /// `addr_context` the address contexts, indexed by context identifier.
    /// Elided address bits are restored from them.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short, is not an IPHC header, an
    ///   encoding is reserved or unsupported, or an address refers to a
    ///   context or link-layer address that is not there.
    pub fn parse(
        buf: &[u8],
        ll_src_addr: Option<LlAddress>,
        ll_dst_addr: Option<LlAddress>,
        addr_context: &[AddressContext],
    ) -> Result<(Self, usize), Malformed> {
        if buf.len() < 2 {
            return Err(Malformed);
        }
        let iphc = u16::from_be_bytes([buf[0], buf[1]]);
        if iphc >> 13 != DISPATCH_IPHC_HEADER as u16 {
            return Err(Malformed);
        }
        let tf = ((iphc >> 11) & 0b11) as u8;
        let nh = (iphc >> 10) & 1 != 0;
        let hlim = ((iphc >> 8) & 0b11) as u8;
        let cid = (iphc >> 7) & 1 != 0;
        let sac = (iphc >> 6) & 1 != 0;
        let sam = ((iphc >> 4) & 0b11) as u8;
        let m = (iphc >> 3) & 1 != 0;
        let dac = (iphc >> 2) & 1 != 0;
        let dam = (iphc & 0b11) as u8;

        let mut offset = 2;

        // The context identifier extension. Without it, context 0 is used
        // (RFC 6282 § 3.1.1, CID).
        let (src_context, dst_context) = if cid {
            let b = take(buf, &mut offset, 1)?[0];
            ((b >> 4) as usize, (b & 0x0f) as usize)
        } else {
            (0, 0)
        };

        let (ecn, dscp, flow_label) = match tf {
            0b00 => {
                let b = take(buf, &mut offset, 4)?;
                (
                    Some(b[0] & 0b1100_0000),
                    Some(b[0] & 0b11_1111),
                    Some(u16::from_be_bytes([b[2], b[3]])),
                )
            }
            0b01 => {
                let b = take(buf, &mut offset, 3)?;
                (Some(b[0] & 0b1100_0000), None, Some(u16::from_be_bytes([b[1], b[2]])))
            }
            0b10 => {
                let b = take(buf, &mut offset, 1)?;
                (Some(b[0] & 0b1100_0000), Some(b[0] & 0b11_1111), None)
            }
            _ => (None, None, None),
        };

        let next_header = if nh {
            NextHeader::Compressed
        } else {
            NextHeader::Uncompressed(IpProtocol::from(take(buf, &mut offset, 1)?[0]))
        };

        let hop_limit = match hlim {
            0b00 => take(buf, &mut offset, 1)?[0],
            0b01 => 1,
            0b10 => 64,
            _ => 255,
        };

        let mut bytes = [0u8; 16];
        let src_addr = match (sac, sam) {
            // The full address is carried inline.
            (false, 0b00) => ipv6::Address::from_octets(take(buf, &mut offset, 16)?.try_into().unwrap()),
            // The link-local prefix is elided.
            (false, 0b01) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[8..].copy_from_slice(take(buf, &mut offset, 8)?);
                ipv6::Address::from_octets(bytes)
            }
            // The IID embeds a short address: fe80::ff:fe00:XXXX.
            (false, 0b10) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE);
                bytes[14..].copy_from_slice(take(buf, &mut offset, 2)?);
                ipv6::Address::from_octets(bytes)
            }
            // Fully elided: link-local, IID from the link-layer address.
            (false, 0b11) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[8..].copy_from_slice(&ll_iid(ll_src_addr)?);
                ipv6::Address::from_octets(bytes)
            }
            (true, 0b00) => ipv6::Address::UNSPECIFIED,
            // Context prefix, IID carried inline.
            (true, 0b01) => {
                bytes[8..].copy_from_slice(take(buf, &mut offset, 8)?);
                apply_context(addr_context, src_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            // Context prefix, IID from the 0000:00ff:fe00:XXXX mapping.
            (true, 0b10) => {
                bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE);
                bytes[14..].copy_from_slice(take(buf, &mut offset, 2)?);
                apply_context(addr_context, src_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            // Context prefix, IID from the link-layer address.
            (true, 0b11) => {
                bytes[8..].copy_from_slice(&ll_iid(ll_src_addr)?);
                apply_context(addr_context, src_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            _ => unreachable!(),
        };

        let mut bytes = [0u8; 16];
        let dst_addr = match (m, dac, dam) {
            // Unicast: same modes as the source address.
            (false, false, 0b00) => ipv6::Address::from_octets(take(buf, &mut offset, 16)?.try_into().unwrap()),
            (false, false, 0b01) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[8..].copy_from_slice(take(buf, &mut offset, 8)?);
                ipv6::Address::from_octets(bytes)
            }
            (false, false, 0b10) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE);
                bytes[14..].copy_from_slice(take(buf, &mut offset, 2)?);
                ipv6::Address::from_octets(bytes)
            }
            (false, false, 0b11) => {
                bytes[0..2].copy_from_slice(&LINK_LOCAL_PREFIX);
                bytes[8..].copy_from_slice(&ll_iid(ll_dst_addr)?);
                ipv6::Address::from_octets(bytes)
            }
            // Reserved.
            (false, true, 0b00) => return Err(Malformed),
            (false, true, 0b01) => {
                bytes[8..].copy_from_slice(take(buf, &mut offset, 8)?);
                apply_context(addr_context, dst_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            (false, true, 0b10) => {
                bytes[11..13].copy_from_slice(&EUI64_MIDDLE_VALUE);
                bytes[14..].copy_from_slice(take(buf, &mut offset, 2)?);
                apply_context(addr_context, dst_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            (false, true, 0b11) => {
                bytes[8..].copy_from_slice(&ll_iid(ll_dst_addr)?);
                apply_context(addr_context, dst_context, &mut bytes)?;
                ipv6::Address::from_octets(bytes)
            }
            // Multicast.
            (true, false, 0b00) => ipv6::Address::from_octets(take(buf, &mut offset, 16)?.try_into().unwrap()),
            (true, false, 0b01) => {
                // ffXX::00XX:XXXX:XXXX
                let b = take(buf, &mut offset, 6)?;
                bytes[0] = 0xff;
                bytes[1] = b[0];
                bytes[11..].copy_from_slice(&b[1..]);
                ipv6::Address::from_octets(bytes)
            }
            (true, false, 0b10) => {
                // ffXX::00XX:XXXX
                let b = take(buf, &mut offset, 4)?;
                bytes[0] = 0xff;
                bytes[1] = b[0];
                bytes[13..].copy_from_slice(&b[1..]);
                ipv6::Address::from_octets(bytes)
            }
            (true, false, 0b11) => {
                // ff02::00XX
                bytes[0] = 0xff;
                bytes[1] = 0x02;
                bytes[15] = take(buf, &mut offset, 1)?[0];
                ipv6::Address::from_octets(bytes)
            }
            // Unicast-prefix-based multicast (unsupported), and reserved.
            (true, true, _) => return Err(Malformed),
            _ => unreachable!(),
        };

        Ok((
            Self {
                src_addr,
                ll_src_addr,
                dst_addr,
                ll_dst_addr,
                next_header,
                hop_limit,
                ecn,
                dscp,
                flow_label,
            },
            offset,
        ))
    }

    /// Return the length of the header this will emit.
    pub fn buffer_len(&self) -> usize {
        let mut len = 2;
        if let NextHeader::Uncompressed(_) = self.next_header {
            len += 1;
        }
        if !matches!(self.hop_limit, 255 | 64 | 1) {
            len += 1;
        }
        len += compress_src(&self.src_addr, self.ll_src_addr).3;
        len += compress_dst(&self.dst_addr, self.ll_dst_addr).3;
        len
    }

    /// Write the header into the front of `buf`.
    ///
    /// Writes exactly [`buffer_len`](Self::buffer_len) bytes. The traffic
    /// class and flow label are always elided.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`buffer_len`](Self::buffer_len).
    pub fn emit(&self, buf: &mut [u8]) {
        let (sac, sam, src_inline, src_len) = compress_src(&self.src_addr, self.ll_src_addr);
        let (m, dam, dst_inline, dst_len) = compress_dst(&self.dst_addr, self.ll_dst_addr);

        let mut iphc = (DISPATCH_IPHC_HEADER as u16) << 13;
        // The traffic class and flow label are never carried.
        iphc |= 0b11 << 11;
        if self.next_header == NextHeader::Compressed {
            iphc |= 1 << 10;
        }
        iphc |= match self.hop_limit {
            1 => 0b01,
            64 => 0b10,
            255 => 0b11,
            _ => 0b00,
        } << 8;
        iphc |= (sac as u16) << 6 | (sam as u16) << 4 | (m as u16) << 3 | dam as u16;
        buf[0..2].copy_from_slice(&iphc.to_be_bytes());

        let mut offset = 2;
        if let NextHeader::Uncompressed(nh) = self.next_header {
            buf[offset] = nh.into();
            offset += 1;
        }
        if !matches!(self.hop_limit, 1 | 64 | 255) {
            buf[offset] = self.hop_limit;
            offset += 1;
        }
        buf[offset..offset + src_len].copy_from_slice(&src_inline[..src_len]);
        offset += src_len;
        buf[offset..offset + dst_len].copy_from_slice(&dst_inline[..dst_len]);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SRC_LL: LlAddress = LlAddress::Extended([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    const DST_LL: LlAddress = LlAddress::Extended([0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    /// Fully elided addresses resolve against the link-layer addresses.
    #[test]
    fn parse_elided() {
        let bytes = [
            0x7a, 0x33, // IPHC: TF elided, NH inline, hop limit 64, both addresses elided
            0x3a, // next header
        ];
        let (repr, len) = Repr::parse(&bytes, Some(SRC_LL), Some(DST_LL), &[]).unwrap();
        assert_eq!(len, 3);
        assert_eq!(repr.next_header, NextHeader::Uncompressed(IpProtocol::Icmpv6));
        assert_eq!(repr.hop_limit, 64);
        assert_eq!(repr.src_addr, SRC_LL.as_link_local_address().unwrap());
        assert_eq!(repr.dst_addr, DST_LL.as_link_local_address().unwrap());
        assert_eq!(repr.ecn, None);
        assert_eq!(repr.dscp, None);
        assert_eq!(repr.flow_label, None);

        // Without the link-layer addresses the elided bits cannot be restored.
        assert!(Repr::parse(&bytes, None, Some(DST_LL), &[]).is_err());
        assert!(Repr::parse(&bytes, Some(SRC_LL), None, &[]).is_err());
    }

    /// Context-compressed addresses resolve against the address contexts.
    #[test]
    fn parse_context() {
        let context = AddressContext([0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        let bytes = [
            0x7e, 0xf7, // IPHC: NH compressed, hop limit 64, both addresses elided with context
            0x00, // context identifier extension: context 0 for both
        ];
        let (repr, len) = Repr::parse(&bytes, Some(SRC_LL), Some(DST_LL), &[context]).unwrap();
        assert_eq!(len, 3);
        assert_eq!(repr.next_header, NextHeader::Compressed);
        assert_eq!(repr.hop_limit, 64);

        let expected = |ll: LlAddress| {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&context.0);
            bytes[8..].copy_from_slice(&ll.as_eui_64().unwrap());
            ipv6::Address::from_octets(bytes)
        };
        assert_eq!(repr.src_addr, expected(SRC_LL));
        assert_eq!(repr.dst_addr, expected(DST_LL));

        // Without the context the addresses cannot be resolved.
        assert!(Repr::parse(&bytes, Some(SRC_LL), Some(DST_LL), &[]).is_err());
    }

    /// A context-compressed address with a 16-bit inline part takes its IID
    /// from the 0000:00ff:fe00:XXXX mapping (RFC 6282 § 3.1.1, SAM=10).
    #[test]
    fn parse_context_16bit() {
        let context = AddressContext([0xfd, 0, 0, 0, 0, 0, 0, 0]);
        let bytes = [
            0x7e, 0x63, // IPHC: NH compressed, hop limit 64, SAC=1 SAM=10, DAM=11
            0x12, 0x34, // the 16 inline source bits
        ];
        let (repr, _) = Repr::parse(&bytes, Some(SRC_LL), Some(DST_LL), &[context]).unwrap();
        assert_eq!(
            repr.src_addr,
            ipv6::Address::new(0xfd00, 0, 0, 0, 0, 0xff, 0xfe00, 0x1234)
        );
    }

    /// Emitting a header and parsing it back round-trips, even into a buffer
    /// full of stale bytes: emit writes every byte of the header.
    #[test]
    fn emit_parse_roundtrip() {
        let repr = Repr {
            src_addr: ipv6::Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            ll_src_addr: Some(SRC_LL),
            dst_addr: DST_LL.as_link_local_address().unwrap(),
            ll_dst_addr: Some(DST_LL),
            next_header: NextHeader::Uncompressed(IpProtocol::Icmpv6),
            hop_limit: 17,
            ecn: None,
            dscp: None,
            flow_label: None,
        };
        let len = repr.buffer_len();
        // Base, next header, hop limit, full source address, elided destination.
        assert_eq!(len, 2 + 1 + 1 + 16);
        let mut buf = [0xffu8; MAX_HEADER_LEN];
        repr.emit(&mut buf[..len]);
        assert_eq!(
            Repr::parse(&buf[..len], Some(SRC_LL), Some(DST_LL), &[]),
            Ok((repr, len))
        );
    }
}
