//! Socket-internal representation of a TCP segment.
//!
//! The TCP state machine works on whole segments: it inspects most header fields
//! of every ingress segment, and dispatch decides all header fields of an egress
//! segment at transmit time. [`TcpRepr`] is that segment value, parsed from a
//! [`TcpPacket`] on ingress, and emitted into one on egress.

use core::fmt;

use crate::driver::ChecksumCapabilities;
use crate::wire::{Error, IpAddress, Result, TCP_HEADER_LEN, TcpControl, TcpOption, TcpPacket, TcpSeqNumber};

/// A high-level representation of a Transmission Control Protocol packet.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) struct TcpRepr<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub control: TcpControl,
    pub seq_number: TcpSeqNumber,
    pub ack_number: Option<TcpSeqNumber>,
    pub window_len: u16,
    pub window_scale: Option<u8>,
    pub max_seg_size: Option<u16>,
    #[cfg(feature = "tcp-sack")]
    pub sack_permitted: bool,
    #[cfg(feature = "tcp-sack")]
    pub sack_ranges: [Option<(u32, u32)>; 3],
    #[cfg(feature = "tcp-timestamps")]
    pub timestamp: Option<TcpTimestampRepr>,
    // The segment payload is two chunks, sent back to back on the wire. Egress
    // fills both when the segment straddles the tx ring buffer's wrap point, so
    // a wrapped segment can still be a full MSS. Everywhere else (ingress
    // parsing, control segments) `payload2` is empty.
    pub payload: &'a [u8],
    pub payload2: &'a [u8],
}

/// The TCP timestamp option value (RFC 7323).
#[cfg(feature = "tcp-timestamps")]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct TcpTimestampRepr {
    /// Our own clock, as milliseconds from an arbitrary point.
    pub tsval: u32,
    /// The last `tsval` received from the peer, echoed back.
    pub tsecr: u32,
}

#[cfg(feature = "tcp-timestamps")]
impl TcpTimestampRepr {
    pub fn new(tsval: u32, tsecr: u32) -> Self {
        Self { tsval, tsecr }
    }
}

impl<'a> TcpRepr<'a> {
    /// Parse a Transmission Control Protocol packet and return a high-level representation.
    ///
    /// The checksum is not verified here. The caller verifies it on the wire packet
    /// before parsing.
    pub fn parse(packet: &'a TcpPacket<'_>, src_addr: &IpAddress, dst_addr: &IpAddress) -> Result<TcpRepr<'a>> {
        packet.check_len()?;

        // Source and destination ports must be present.
        if packet.src_port() == 0 {
            return Err(Error);
        }
        if packet.dst_port() == 0 {
            return Err(Error);
        }

        let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
            (false, false, false, false) => TcpControl::None,
            (false, false, false, true) => TcpControl::Psh,
            (true, false, false, _) => TcpControl::Syn,
            (false, true, false, _) => TcpControl::Fin,
            (false, false, true, _) => TcpControl::Rst,
            _ => return Err(Error),
        };
        let ack_number = match packet.ack() {
            true => Some(packet.ack_number()),
            false => None,
        };
        // The PSH flag is ignored.
        // The URG flag and the urgent field is ignored. This behavior is standards-compliant,
        // however, most deployed systems (e.g. Linux) are *not* standards-compliant, and would
        // cut the byte at the urgent pointer from the stream.

        let mut max_seg_size = None;
        let mut window_scale = None;
        let mut options = packet.options();
        #[cfg(feature = "tcp-sack")]
        let mut sack_permitted = false;
        #[cfg(feature = "tcp-sack")]
        let mut sack_ranges = [None, None, None];
        #[cfg(feature = "tcp-timestamps")]
        let mut timestamp = None;
        while !options.is_empty() {
            let (next_options, option) = TcpOption::parse(options)?;
            match option {
                TcpOption::EndOfList => break,
                TcpOption::NoOperation => (),
                TcpOption::MaxSegmentSize(value) => max_seg_size = Some(value),
                TcpOption::WindowScale(value) => {
                    // RFC 1323: Thus, the shift count must be limited to 14 (which allows windows
                    // of 2**30 = 1 Gigabyte). If a Window Scale option is received with a shift.cnt
                    // value exceeding 14, the TCP should log the error but use 14 instead of the
                    // specified value.
                    window_scale = if value > 14 {
                        debug!(
                            "{}:{}:{}:{}: parsed window scaling factor >14, setting to 14",
                            src_addr,
                            packet.src_port(),
                            dst_addr,
                            packet.dst_port()
                        );
                        Some(14)
                    } else {
                        Some(value)
                    };
                }
                #[cfg(feature = "tcp-sack")]
                TcpOption::SackPermitted => sack_permitted = true,
                #[cfg(feature = "tcp-sack")]
                TcpOption::SackRange(slice) => sack_ranges = slice,
                #[cfg(feature = "tcp-timestamps")]
                TcpOption::TimeStamp { tsval, tsecr } => {
                    timestamp = Some(TcpTimestampRepr::new(tsval, tsecr));
                }
                _ => (),
            }
            options = next_options;
        }

        Ok(TcpRepr {
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            control,
            seq_number: packet.seq_number(),
            ack_number,
            window_len: packet.window_len(),
            window_scale,
            max_seg_size,
            #[cfg(feature = "tcp-sack")]
            sack_permitted,
            #[cfg(feature = "tcp-sack")]
            sack_ranges,
            #[cfg(feature = "tcp-timestamps")]
            timestamp,
            payload: packet.payload(),
            payload2: &[],
        })
    }

    /// Return the length of a header that will be emitted from this high-level representation.
    ///
    /// This should be used for buffer space calculations.
    /// The TCP header length is a multiple of 4.
    pub fn header_len(&self) -> usize {
        let mut length = TCP_HEADER_LEN;
        if self.max_seg_size.is_some() {
            length += 4
        }
        if self.window_scale.is_some() {
            length += 3
        }
        #[cfg(feature = "tcp-sack")]
        if self.sack_permitted {
            length += 2;
        }
        #[cfg(feature = "tcp-timestamps")]
        if self.timestamp.is_some() {
            length += 10;
        }
        #[cfg(feature = "tcp-sack")]
        {
            let sack_range_len: usize = self.sack_ranges.iter().map(|o| o.map(|_| 8).unwrap_or(0)).sum();
            if sack_range_len > 0 {
                length += sack_range_len + 2;
            }
        }
        if !length.is_multiple_of(4) {
            length += 4 - length % 4;
        }
        length
    }

    /// Return the total payload length, both chunks combined.
    pub const fn payload_len(&self) -> usize {
        self.payload.len() + self.payload2.len()
    }

    /// Return the length of a packet that will be emitted from this high-level representation.
    pub fn buffer_len(&self) -> usize {
        self.header_len() + self.payload_len()
    }

    /// Emit a high-level representation into a Transmission Control Protocol packet.
    ///
    /// The buffer wrapped by `packet` must be exactly [`buffer_len`](Self::buffer_len)
    /// octets long.
    pub fn emit(
        &self,
        packet: &mut TcpPacket<'_>,
        src_addr: &IpAddress,
        dst_addr: &IpAddress,
        checksum_caps: &ChecksumCapabilities,
    ) {
        packet.set_src_port(self.src_port);
        packet.set_dst_port(self.dst_port);
        packet.set_seq_number(self.seq_number);
        packet.set_ack_number(self.ack_number.unwrap_or(TcpSeqNumber(0)));
        packet.set_window_len(self.window_len);
        packet.set_header_len(self.header_len() as u8);
        packet.clear_flags();
        match self.control {
            TcpControl::None => (),
            TcpControl::Psh => packet.set_psh(true),
            TcpControl::Syn => packet.set_syn(true),
            TcpControl::Fin => packet.set_fin(true),
            TcpControl::Rst => packet.set_rst(true),
        }
        packet.set_ack(self.ack_number.is_some());
        {
            let mut options = packet.options_mut();
            if let Some(value) = self.max_seg_size {
                let tmp = options;
                options = TcpOption::MaxSegmentSize(value).emit(tmp);
            }
            if let Some(value) = self.window_scale {
                let tmp = options;
                options = TcpOption::WindowScale(value).emit(tmp);
            }
            #[cfg(feature = "tcp-sack")]
            if self.sack_permitted {
                let tmp = options;
                options = TcpOption::SackPermitted.emit(tmp);
            } else if self.ack_number.is_some() && self.sack_ranges.iter().any(|s| s.is_some()) {
                let tmp = options;
                options = TcpOption::SackRange(self.sack_ranges).emit(tmp);
            }
            #[cfg(feature = "tcp-timestamps")]
            if let Some(timestamp) = self.timestamp {
                let tmp = options;
                options = TcpOption::TimeStamp {
                    tsval: timestamp.tsval,
                    tsecr: timestamp.tsecr,
                }
                .emit(tmp);
            }

            if !options.is_empty() {
                TcpOption::EndOfList.emit(options);
            }
        }
        packet.set_urgent_at(0);
        let payload = packet.payload_mut();
        payload[..self.payload.len()].copy_from_slice(self.payload);
        payload[self.payload.len()..].copy_from_slice(self.payload2);
        if !checksum_caps.tcp.tx {
            packet.fill_checksum(src_addr, dst_addr)
        } else {
            packet.set_checksum(0);
        }
    }

    /// Return the length of the segment, in terms of sequence space.
    pub const fn segment_len(&self) -> usize {
        self.payload_len() + self.control.len()
    }

    /// Return whether the segment has no flags set (except PSH) and no data.
    pub const fn is_empty(&self) -> bool {
        match self.control {
            _ if self.payload_len() != 0 => false,
            TcpControl::Syn | TcpControl::Fin | TcpControl::Rst => false,
            TcpControl::None | TcpControl::Psh => true,
        }
    }
}

impl<'a> fmt::Display for TcpRepr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TCP src={} dst={}", self.src_port, self.dst_port)?;
        match self.control {
            TcpControl::Syn => write!(f, " syn")?,
            TcpControl::Fin => write!(f, " fin")?,
            TcpControl::Rst => write!(f, " rst")?,
            TcpControl::Psh => write!(f, " psh")?,
            TcpControl::None => (),
        }
        write!(f, " seq={}", self.seq_number)?;
        if let Some(ack_number) = self.ack_number {
            write!(f, " ack={ack_number}")?;
        }
        write!(f, " win={}", self.window_len)?;
        write!(f, " len={}", self.payload_len())?;
        if let Some(max_seg_size) = self.max_seg_size {
            write!(f, " mss={max_seg_size}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "ipv4"))]
mod test {
    use super::*;
    use crate::wire::Ipv4Address;

    const SRC_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 1);
    const DST_ADDR: Ipv4Address = Ipv4Address::new(192, 168, 1, 2);

    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    static SYN_PACKET_BYTES: [u8; 24] = [
        0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x01, 0x23, 0x7a, 0x8d,
        0x00, 0x00, 0xaa, 0x00, 0x00, 0xff,
    ];

    fn packet_repr() -> TcpRepr<'static> {
        TcpRepr {
            src_port: 48896,
            dst_port: 80,
            seq_number: TcpSeqNumber(0x01234567),
            ack_number: None,
            window_len: 0x0123,
            window_scale: None,
            control: TcpControl::Syn,
            max_seg_size: None,
            #[cfg(feature = "tcp-sack")]
            sack_permitted: false,
            #[cfg(feature = "tcp-sack")]
            sack_ranges: [None, None, None],
            #[cfg(feature = "tcp-timestamps")]
            timestamp: None,
            payload: &PAYLOAD_BYTES,
            payload2: &[],
        }
    }

    #[test]
    fn test_parse() {
        let mut bytes = SYN_PACKET_BYTES;
        let packet = TcpPacket::new_unchecked(&mut bytes[..]);
        assert!(packet.verify_checksum(&SRC_ADDR.into(), &DST_ADDR.into()));
        let repr = TcpRepr::parse(&packet, &SRC_ADDR.into(), &DST_ADDR.into()).unwrap();
        assert_eq!(repr, packet_repr());
    }

    #[test]
    fn test_emit() {
        let repr = packet_repr();
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = TcpPacket::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&bytes[..], &SYN_PACKET_BYTES[..]);
    }

    #[test]
    fn test_emit_split_payload() {
        // A payload split in two chunks emits the same bytes as a contiguous one.
        let mut repr = packet_repr();
        repr.payload = &PAYLOAD_BYTES[..3];
        repr.payload2 = &PAYLOAD_BYTES[3..];
        let mut bytes = vec![0xa5; repr.buffer_len()];
        let mut packet = TcpPacket::new_unchecked(&mut bytes);
        repr.emit(
            &mut packet,
            &SRC_ADDR.into(),
            &DST_ADDR.into(),
            &ChecksumCapabilities::default(),
        );
        assert_eq!(&bytes[..], &SYN_PACKET_BYTES[..]);
    }

    #[test]
    fn test_header_len_multiple_of_4() {
        let mut repr = packet_repr();
        repr.window_scale = Some(0); // This TCP Option needs 3 bytes.
        assert_eq!(repr.header_len() % 4, 0); // Should e.g. be 28 instead of 27.
    }
}
