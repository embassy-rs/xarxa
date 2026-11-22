use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::wire::ip::checksum;
use crate::wire::{IpProtocol, Ipv6Addr};

open_enum! {
    /// Internet protocol control message type.
    pub enum Message(u8) {
        /// Destination Unreachable.
        DstUnreachable  = 0x01,
        /// Packet Too Big.
        PktTooBig       = 0x02,
        /// Time Exceeded.
        TimeExceeded    = 0x03,
        /// Parameter Problem.
        ParamProblem    = 0x04,
        /// Echo Request
        EchoRequest     = 0x80,
        /// Echo Reply
        EchoReply       = 0x81,
        /// Multicast Listener Query
        MldQuery        = 0x82,
        /// Router Solicitation
        RouterSolicit   = 0x85,
        /// Router Advertisement
        RouterAdvert    = 0x86,
        /// Neighbor Solicitation
        NeighborSolicit = 0x87,
        /// Neighbor Advertisement
        NeighborAdvert  = 0x88,
        /// Redirect
        Redirect        = 0x89,
        /// Multicast Listener Report
        MldReport       = 0x8f,
        /// RPL Control Message
        RplControl      = 0x9b,
    }
}

impl Message {
    /// Per [RFC 4443 § 2.1] ICMPv6 message types with the highest order
    /// bit set are informational messages while message types without
    /// the highest order bit set are error messages.
    ///
    /// [RFC 4443 § 2.1]: https://tools.ietf.org/html/rfc4443#section-2.1
    pub fn is_error(&self) -> bool {
        (u8::from(*self) & 0x80) != 0x80
    }

    /// Return a boolean value indicating if the given message type
    /// is an [NDISC] message type.
    ///
    /// [NDISC]: https://tools.ietf.org/html/rfc4861
    pub const fn is_ndisc(&self) -> bool {
        match *self {
            Message::RouterSolicit
            | Message::RouterAdvert
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect => true,
            _ => false,
        }
    }

    /// Return a boolean value indicating if the given message type
    /// is an [MLD] message type.
    ///
    /// [MLD]: https://tools.ietf.org/html/rfc3810
    pub const fn is_mld(&self) -> bool {
        match *self {
            Message::MldQuery | Message::MldReport => true,
            _ => false,
        }
    }
}

open_enum! {
    /// Internet protocol control message subtype for type "Destination Unreachable".
    pub enum DstUnreachable(u8) {
        /// No Route to destination.
        NoRoute         = 0,
        /// Communication with destination administratively prohibited.
        AdminProhibit   = 1,
        /// Beyond scope of source address.
        BeyondScope     = 2,
        /// Address unreachable.
        AddrUnreachable = 3,
        /// Port unreachable.
        PortUnreachable = 4,
        /// Source address failed ingress/egress policy.
        FailedPolicy    = 5,
        /// Reject route to destination.
        RejectRoute     = 6
    }
}

open_enum! {
    /// Internet protocol control message subtype for the type "Parameter Problem".
    pub enum ParamProblem(u8) {
        /// Erroneous header field encountered.
        ErroneousHdrField  = 0,
        /// Unrecognized Next Header type encountered.
        UnrecognizedNxtHdr = 1,
        /// Unrecognized IPv6 option encountered.
        UnrecognizedOption = 2
    }
}

open_enum! {
    /// Internet protocol control message subtype for the type "Time Exceeded".
    pub enum TimeExceeded(u8) {
        /// Hop limit exceeded in transit.
        HopLimitExceeded    = 0,
        /// Fragment reassembly time exceeded.
        FragReassemExceeded = 1
    }
}

/// A read/write wrapper around an Internet Control Message Protocol version 6 packet buffer.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub(super) buffer: &'a mut [u8],
}

// Ranges and constants describing key boundaries in the ICMPv6 header.
pub(super) mod field {
    // Which field offsets are used depends on the enabled features (MLD needs
    // `multicast`, router advertisements need `slaac`).
    #![allow(unused)]

    use crate::wire::field::*;

    // ICMPv6: See https://tools.ietf.org/html/rfc4443
    pub const TYPE: usize = 0;
    pub const CODE: usize = 1;
    pub const CHECKSUM: Field = 2..4;

    pub const UNUSED: Field = 4..8;
    pub const MTU: Field = 4..8;
    pub const POINTER: Field = 4..8;
    pub const ECHO_IDENT: Field = 4..6;
    pub const ECHO_SEQNO: Field = 6..8;

    pub const HEADER_END: usize = 8;

    // NDISC: See https://tools.ietf.org/html/rfc4861
    // Router Advertisement message offsets
    pub const CUR_HOP_LIMIT: usize = 4;
    pub const ROUTER_FLAGS: usize = 5;
    pub const ROUTER_LT: Field = 6..8;
    pub const REACHABLE_TM: Field = 8..12;
    pub const RETRANS_TM: Field = 12..16;

    // Neighbor Solicitation message offsets
    pub const TARGET_ADDR: Field = 8..24;

    // Neighbor Advertisement message offsets
    pub const NEIGH_FLAGS: usize = 4;

    // Redirected Header message offsets
    pub const DEST_ADDR: Field = 24..40;

    // MLD:
    //   - https://tools.ietf.org/html/rfc3810
    //   - https://tools.ietf.org/html/rfc3810
    // Multicast Listener Query message
    pub const MAX_RESP_CODE: Field = 4..6;
    pub const QUERY_RESV: Field = 6..8;
    pub const QUERY_MCAST_ADDR: Field = 8..24;
    pub const SQRV: usize = 24;
    pub const QQIC: usize = 25;
    pub const QUERY_NUM_SRCS: Field = 26..28;

    // Multicast Listener Report Message
    pub const RECORD_RESV: Field = 4..6;
    pub const NR_MCAST_RCRDS: Field = 6..8;

    // Multicast Address Record Offsets
    pub const RECORD_TYPE: usize = 0;
    pub const AUX_DATA_LEN: usize = 1;
    pub const RECORD_NUM_SRCS: Field = 2..4;
    pub const RECORD_MCAST_ADDR: Field = 4..20;
}

impl<'a> Packet<'a> {
    /// Imbue a raw octet buffer with ICMPv6 packet structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>, Malformed> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// This checks lengths only, for any message type value: the buffer holds the
    /// header of its type, as [`header_len`] gives it. Every accessor for the
    /// message's type is then in bounds. Fields that only some messages of a type
    /// carry, like the MLDv2 query fields, have accessors that return `None`
    /// when they are not there. Whether the message is valid for its type is up
    /// to the consumer.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is shorter than the header of the message type.
    ///
    /// [`header_len`]: #method.header_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::CHECKSUM.end || len < self.header_len() {
            return Err(Malformed);
        }
        Ok(())
    }

    /// Return the message type field.
    #[inline]
    pub fn msg_type(&self) -> Message {
        Message::from(self.buffer[field::TYPE])
    }

    /// Return the message code field.
    #[inline]
    pub fn msg_code(&self) -> u8 {
        self.buffer[field::CODE]
    }

    /// Return the checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::CHECKSUM])
    }

    /// Return the identifier field (for echo request and reply packets).
    #[inline]
    pub fn echo_ident(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_IDENT])
    }

    /// Return the sequence number field (for echo request and reply packets).
    #[inline]
    pub fn echo_seq_no(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::ECHO_SEQNO])
    }

    /// Return the MTU field (for packet too big messages).
    #[inline]
    pub fn pkt_too_big_mtu(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::MTU])
    }

    /// Return the pointer field (for parameter problem messages).
    #[inline]
    pub fn param_problem_ptr(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::POINTER])
    }

    /// Return the header length. The result depends on the value of
    /// the message type field.
    ///
    /// Every error message (type below 128) has the 8-byte header of RFC 4443
    /// §2.1, also the types this does not know, so that the payload of an
    /// unknown error is the packet it quotes.
    pub fn header_len(&self) -> usize {
        match self.msg_type() {
            Message::DstUnreachable => field::UNUSED.end,
            Message::PktTooBig => field::MTU.end,
            Message::TimeExceeded => field::UNUSED.end,
            Message::ParamProblem => field::POINTER.end,
            Message::EchoRequest => field::ECHO_SEQNO.end,
            Message::EchoReply => field::ECHO_SEQNO.end,
            Message::RouterSolicit => field::UNUSED.end,
            Message::RouterAdvert => field::RETRANS_TM.end,
            Message::NeighborSolicit => field::TARGET_ADDR.end,
            Message::NeighborAdvert => field::TARGET_ADDR.end,
            Message::Redirect => field::DEST_ADDR.end,
            // RFC 3810 §8.1 tells the versions apart by length: an MLDv2 query
            // has 4 more bytes of header than an MLDv1 query (RFC 2710 §3).
            Message::MldQuery if self.buffer.len() >= field::QUERY_NUM_SRCS.end => field::QUERY_NUM_SRCS.end,
            Message::MldQuery => field::QUERY_MCAST_ADDR.end,
            Message::MldReport => field::NR_MCAST_RCRDS.end,
            msg_type if msg_type.is_error() => field::HEADER_END,
            // For informational messages that are not known here, do not
            // include the last 32 bits of the ICMPv6 header in
            // `header_bytes`. This must be done so that these bytes
            // can be accessed in the `payload`.
            _ => field::CHECKSUM.end,
        }
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self, src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = &*self.buffer;
        checksum::combine(&[
            checksum::pseudo_header_v6(src_addr, dst_addr, IpProtocol::Icmpv6, data.len() as u32),
            checksum::data(data),
        ]) == !0
    }

    /// Return a pointer to the type-specific data.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.header_len()..]
    }

    /// Set the message type field.
    #[inline]
    pub fn set_msg_type(&mut self, value: Message) {
        self.buffer[field::TYPE] = value.into()
    }

    /// Set the message code field.
    #[inline]
    pub fn set_msg_code(&mut self, value: u8) {
        self.buffer[field::CODE] = value
    }

    /// Clear the reserved fields of the message header.
    ///
    /// Set the message type first. Message types with no reserved fields are
    /// left unchanged.
    #[inline]
    pub fn clear_reserved(&mut self) {
        match self.msg_type() {
            Message::DstUnreachable
            | Message::TimeExceeded
            | Message::RouterSolicit
            | Message::NeighborSolicit
            | Message::NeighborAdvert
            | Message::Redirect => {
                NetworkEndian::write_u32(&mut self.buffer[field::UNUSED], 0);
            }
            Message::MldQuery => {
                NetworkEndian::write_u16(&mut self.buffer[field::QUERY_RESV], 0);
                // An MLDv1 query has no S/QRV field.
                if let Some(sqrv) = self.buffer.get_mut(field::SQRV) {
                    *sqrv &= 0xf;
                }
            }
            Message::MldReport => {
                NetworkEndian::write_u16(&mut self.buffer[field::RECORD_RESV], 0);
            }
            _ => {}
        }
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::CHECKSUM], value)
    }

    /// Set the identifier field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_ident(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_IDENT], value)
    }

    /// Set the sequence number field (for echo request and reply packets).
    ///
    /// # Panics
    /// This function may panic if this packet is not an echo request or reply packet.
    #[inline]
    pub fn set_echo_seq_no(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::ECHO_SEQNO], value)
    }

    /// Set the MTU field (for packet too big messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not an packet too big packet.
    #[inline]
    pub fn set_pkt_too_big_mtu(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::MTU], value)
    }

    /// Set the pointer field (for parameter problem messages).
    ///
    /// # Panics
    /// This function may panic if this packet is not a parameter problem message.
    #[inline]
    pub fn set_param_problem_ptr(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::POINTER], value)
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self, src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr) {
        self.set_checksum(0);
        let checksum = {
            let data = &*self.buffer;
            !checksum::combine(&[
                checksum::pseudo_header_v6(src_addr, dst_addr, IpProtocol::Icmpv6, data.len() as u32),
                checksum::data(data),
            ])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the type-specific data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len()..;
        &mut self.buffer[range]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MOCK_IP_ADDR_1: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const MOCK_IP_ADDR_2: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    static ECHO_PACKET_BYTES: [u8; 12] = [0x80, 0x00, 0x19, 0xb3, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff];

    static ECHO_PACKET_PAYLOAD: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];

    static PKT_TOO_BIG_BYTES: [u8; 60] = [
        0x02, 0x00, 0x0f, 0xc9, 0x00, 0x00, 0x05, 0xdc, 0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c,
        0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    static PKT_TOO_BIG_IP_PAYLOAD: [u8; 52] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x11, 0x40, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn test_echo_deconstruct() {
        let mut bytes = ECHO_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::EchoRequest);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x19b3);
        assert_eq!(packet.echo_ident(), 0x1234);
        assert_eq!(packet.echo_seq_no(), 0xabcd);
        assert_eq!(packet.payload(), &ECHO_PACKET_PAYLOAD[..]);
        assert!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2));
        assert!(!packet.msg_type().is_error());
    }

    #[test]
    fn test_echo_construct() {
        let mut bytes = vec![0xa5; 12];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::EchoRequest);
        packet.set_msg_code(0);
        packet.set_echo_ident(0x1234);
        packet.set_echo_seq_no(0xabcd);
        packet.payload_mut().copy_from_slice(&ECHO_PACKET_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&bytes[..], &ECHO_PACKET_BYTES[..]);
    }

    #[test]
    fn test_too_big_deconstruct() {
        let mut bytes = PKT_TOO_BIG_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::PktTooBig);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x0fc9);
        assert_eq!(packet.pkt_too_big_mtu(), 1500);
        assert_eq!(packet.payload(), &PKT_TOO_BIG_IP_PAYLOAD[..]);
        assert!(packet.verify_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2));
        assert!(packet.msg_type().is_error());
    }

    /// `check_len` checks lengths only. Every error type, known or not, has the
    /// 8-byte error header, and an unknown informational type has 4 bytes.
    #[test]
    fn test_check_len_unknown_types() {
        let mut bytes = [100, 0, 0, 0, 0, 0, 0, 0, 0xaa];
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert!(packet.msg_type().is_error());
        assert_eq!(packet.payload(), &[0xaa]);
        assert!(Packet::new_checked(&mut bytes[..7]).is_err());

        let mut bytes = [200, 0, 0, 0, 0xaa];
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.payload(), &[0xaa]);
        assert!(Packet::new_checked(&mut bytes[..3]).is_err());

        // RPL control, a known informational type with no fixed header here.
        let mut bytes = [0x9b, 0, 0, 0];
        assert!(Packet::new_checked(&mut bytes[..]).is_ok());

        // Known types still need their header.
        let mut bytes = [0x87; 23];
        assert!(Packet::new_checked(&mut bytes[..]).is_err());
    }

    #[test]
    fn test_too_big_construct() {
        let mut bytes = vec![0xa5; 60];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::PktTooBig);
        packet.set_msg_code(0);
        packet.set_pkt_too_big_mtu(1500);
        packet.payload_mut().copy_from_slice(&PKT_TOO_BIG_IP_PAYLOAD[..]);
        packet.fill_checksum(&MOCK_IP_ADDR_1, &MOCK_IP_ADDR_2);
        assert_eq!(&bytes[..], &PKT_TOO_BIG_BYTES[..]);
    }
}
