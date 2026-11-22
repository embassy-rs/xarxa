// Packet implementation for the Multicast Listener Discovery
// protocol. See [RFC 3810] and [RFC 2710].
//
// [RFC 3810]: https://tools.ietf.org/html/rfc3810
// [RFC 2710]: https://tools.ietf.org/html/rfc2710

use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::time::Duration;
use crate::wire::Ipv6Addr;
use crate::wire::icmpv6::{Packet, field};

open_enum! {
    /// MLDv2 Multicast Listener Report Record Type. See [RFC 3810 § 5.2.12] for
    /// more details.
    ///
    /// [RFC 3810 § 5.2.12]: https://tools.ietf.org/html/rfc3010#section-5.2.12
    pub enum RecordType(u8) {
        /// Interface has a filter mode of INCLUDE for the specified multicast address.
        ModeIsInclude   = 0x01,
        /// Interface has a filter mode of EXCLUDE for the specified multicast address.
        ModeIsExclude   = 0x02,
        /// Interface has changed to a filter mode of INCLUDE for the specified
        /// multicast address.
        ChangeToInclude = 0x03,
        /// Interface has changed to a filter mode of EXCLUDE for the specified
        /// multicast address.
        ChangeToExclude = 0x04,
        /// Interface wishes to listen to the sources in the specified list.
        AllowNewSources = 0x05,
        /// Interface no longer wishes to listen to the sources in the specified list.
        BlockOldSources = 0x06
    }
}

/// The length of a Multicast Address Record with no sources and no auxiliary data.
pub const ADDRESS_RECORD_LEN: usize = field::RECORD_MCAST_ADDR.end;

/// Getters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<'a> Packet<'a> {
    /// Return the maximum response code field.
    #[inline]
    pub fn max_resp_code(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::MAX_RESP_CODE])
    }

    /// Return the maximum response delay, decoded from the maximum response code field.
    ///
    /// See [RFC 3810 § 5.1.3].
    ///
    /// [RFC 3810 § 5.1.3]: https://tools.ietf.org/html/rfc3810#section-5.1.3
    #[inline]
    pub fn max_resp_delay(&self) -> Duration {
        max_resp_code_to_delay(self.max_resp_code())
    }

    /// Return the address being queried.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.buffer[field::QUERY_MCAST_ADDR].try_into().unwrap())
    }

    /// Return the Suppress Router-Side Processing flag, `None` if this is not
    /// an MLDv2 query.
    #[inline]
    pub fn s_flag(&self) -> Option<bool> {
        Some((self.mldv2_query()?[field::SQRV] & 0x08) != 0)
    }

    /// Return the Querier's Robustness Variable, `None` if this is not an MLDv2
    /// query.
    #[inline]
    pub fn qrv(&self) -> Option<u8> {
        Some(self.mldv2_query()?[field::SQRV] & 0x7)
    }

    /// Return the Querier's Query Interval Code, `None` if this is not an MLDv2
    /// query.
    #[inline]
    pub fn qqic(&self) -> Option<u8> {
        Some(self.mldv2_query()?[field::QQIC])
    }

    /// Return number of sources, `None` if this is not an MLDv2 query.
    #[inline]
    pub fn num_srcs(&self) -> Option<u16> {
        Some(NetworkEndian::read_u16(&self.mldv2_query()?[field::QUERY_NUM_SRCS]))
    }

    /// The header of an MLDv2 query, `None` if the buffer is too short for one.
    ///
    /// RFC 3810 §8.1 tells an MLDv2 query from an MLDv1 one by its length alone.
    #[inline]
    fn mldv2_query(&self) -> Option<&[u8]> {
        self.buffer.get(..field::QUERY_NUM_SRCS.end)
    }
}

/// Getters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<'a> Packet<'a> {
    /// Return the number of Multicast Address Records.
    #[inline]
    pub fn nr_mcast_addr_rcrds(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::NR_MCAST_RCRDS])
    }
}

/// Setters for the Multicast Listener Query message header.
/// See [RFC 3810 § 5.1].
///
/// [RFC 3810 § 5.1]: https://tools.ietf.org/html/rfc3010#section-5.1
impl<'a> Packet<'a> {
    /// Set the maximum response code field.
    #[inline]
    pub fn set_max_resp_code(&mut self, code: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::MAX_RESP_CODE], code);
    }

    /// Set the maximum response code field from a maximum response delay.
    ///
    /// The delay is rounded down to the nearest value the field can encode.
    /// Delays longer than 8387.584 s are clamped to that.
    #[inline]
    pub fn set_max_resp_delay(&mut self, delay: Duration) {
        self.set_max_resp_code(delay_to_max_resp_code(delay))
    }

    /// Set the address being queried.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Addr) {
        self.buffer[field::QUERY_MCAST_ADDR].copy_from_slice(&addr.octets());
    }

    /// Set the Suppress Router-Side Processing flag.
    #[inline]
    pub fn set_s_flag(&mut self) {
        let current = self.buffer[field::SQRV];
        self.buffer[field::SQRV] = 0x8 | (current & 0x7);
    }

    /// Clear the Suppress Router-Side Processing flag.
    #[inline]
    pub fn clear_s_flag(&mut self) {
        self.buffer[field::SQRV] &= 0x7;
    }

    /// Set the Querier's Robustness Variable.
    #[inline]
    pub fn set_qrv(&mut self, value: u8) {
        assert!(value < 8);
        self.buffer[field::SQRV] = (self.buffer[field::SQRV] & 0x8) | value & 0x7;
    }

    /// Set the Querier's Query Interval Code.
    #[inline]
    pub fn set_qqic(&mut self, value: u8) {
        self.buffer[field::QQIC] = value;
    }

    /// Set number of sources.
    #[inline]
    pub fn set_num_srcs(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::QUERY_NUM_SRCS], value);
    }
}

/// Setters for the Multicast Listener Report message header.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<'a> Packet<'a> {
    /// Set the number of Multicast Address Records.
    #[inline]
    pub fn set_nr_mcast_addr_rcrds(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::NR_MCAST_RCRDS], value)
    }
}

/// A read/write wrapper around an MLDv2 Listener Report Message Address Record.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct AddressRecord<'a> {
    buffer: &'a mut [u8],
}

impl<'a> AddressRecord<'a> {
    /// Imbue a raw octet buffer with a Address Record structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> Self {
        Self { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<Self, Malformed> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// # Errors
    /// - `Malformed`: if the buffer is too short.
    pub fn check_len(&self) -> Result<(), Malformed> {
        let len = self.buffer.len();
        if len < field::RECORD_MCAST_ADDR.end {
            Err(Malformed)
        } else {
            Ok(())
        }
    }
}

/// Getters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<'a> AddressRecord<'a> {
    /// Return the record type for the given sources.
    #[inline]
    pub fn record_type(&self) -> RecordType {
        RecordType::from(self.buffer[field::RECORD_TYPE])
    }

    /// Return the length of the auxiliary data.
    #[inline]
    pub fn aux_data_len(&self) -> u8 {
        self.buffer[field::AUX_DATA_LEN]
    }

    /// Return the number of sources field.
    #[inline]
    pub fn num_srcs(&self) -> u16 {
        NetworkEndian::read_u16(&self.buffer[field::RECORD_NUM_SRCS])
    }

    /// Return the multicast address field.
    #[inline]
    pub fn mcast_addr(&self) -> Ipv6Addr {
        Ipv6Addr::from_octets(self.buffer[field::RECORD_MCAST_ADDR].try_into().unwrap())
    }

    /// Return a pointer to the address records.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buffer[field::RECORD_MCAST_ADDR.end..]
    }
}

/// Setters for a MLDv2 Listener Report Message Address Record.
/// See [RFC 3810 § 5.2].
///
/// [RFC 3810 § 5.2]: https://tools.ietf.org/html/rfc3010#section-5.2
impl<'a> AddressRecord<'a> {
    /// Set the record type for the given sources.
    #[inline]
    pub fn set_record_type(&mut self, rty: RecordType) {
        self.buffer[field::RECORD_TYPE] = rty.into();
    }

    /// Set the length of the auxiliary data.
    #[inline]
    pub fn set_aux_data_len(&mut self, len: u8) {
        self.buffer[field::AUX_DATA_LEN] = len;
    }

    /// Set the number of sources field.
    #[inline]
    pub fn set_num_srcs(&mut self, num_srcs: u16) {
        NetworkEndian::write_u16(&mut self.buffer[field::RECORD_NUM_SRCS], num_srcs);
    }

    /// Set the multicast address field.
    ///
    /// # Panics
    /// This function panics if the given address is not a multicast address.
    #[inline]
    pub fn set_mcast_addr(&mut self, addr: Ipv6Addr) {
        assert!(addr.is_multicast());
        self.buffer[field::RECORD_MCAST_ADDR].copy_from_slice(&addr.octets());
    }

    /// Return a mutable pointer to the address records.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[field::RECORD_MCAST_ADDR.end..]
    }
}

/// The longest maximum response delay the code field can encode, in milliseconds.
const MAX_RESP_DELAY_MAX_MILLIS: u32 = 0x1FFF << 10;

// RFC 3810 §5.1.3: a code below 32768 is the delay in milliseconds, a code of
// 32768 or more is a floating point value, `(mant | 0x1000) << (exp + 3)`, with
// a 3-bit exponent and a 12-bit mantissa.
const fn max_resp_code_to_delay(code: u16) -> Duration {
    let code = code as u32;
    let millis = if code < 0x8000 {
        code
    } else {
        let mant = code & 0xFFF;
        let exp = (code >> 12) & 0x7;
        (mant | 0x1000) << (exp + 3)
    };
    Duration::from_millis(millis)
}

const fn delay_to_max_resp_code(delay: Duration) -> u16 {
    let millis = delay.as_millis();
    if millis < 0x8000 {
        millis as u16
    } else if millis >= MAX_RESP_DELAY_MAX_MILLIS {
        0xFFFF
    } else {
        let mut mant = millis >> 3;
        let mut exp = 0u16;
        while mant > 0x1FFF {
            mant >>= 1;
            exp += 1;
        }
        0x8000 | (exp << 12) | (mant as u16 & 0xFFF)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wire::icmpv6::Message;
    use crate::wire::{IPV6_LINK_LOCAL_ALL_NODES, IPV6_LINK_LOCAL_ALL_ROUTERS};

    static QUERY_PACKET_BYTES: [u8; 44] = [
        0x82, 0x00, 0x73, 0x74, 0x04, 0x00, 0x00, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x12, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    static REPORT_PACKET_BYTES: [u8; 44] = [
        0x8f, 0x00, 0x73, 0x85, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ];

    #[test]
    fn test_query_deconstruct() {
        let mut bytes = QUERY_PACKET_BYTES;
        let packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::MldQuery);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x7374);
        assert_eq!(packet.max_resp_code(), 0x0400);
        assert_eq!(packet.max_resp_delay(), Duration::from_millis(0x0400));
        assert_eq!(packet.mcast_addr(), IPV6_LINK_LOCAL_ALL_NODES);
        assert_eq!(packet.s_flag(), Some(true));
        assert_eq!(packet.qrv(), Some(0x02));
        assert_eq!(packet.qqic(), Some(0x12));
        assert_eq!(packet.num_srcs(), Some(0x01));
        assert_eq!(
            Ipv6Addr::from_octets(packet.payload().try_into().unwrap()),
            IPV6_LINK_LOCAL_ALL_ROUTERS
        );
        assert!(packet.verify_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS));
    }

    /// An MLDv1 query (24 bytes) passes `check_len`, and the MLDv2 query fields
    /// it does not have read as `None`.
    #[test]
    fn test_check_len_mldv1_query() {
        let mut bytes = [0u8; 24];
        bytes[0] = 0x82;
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.header_len(), 24);
        assert!(packet.payload().is_empty());
        assert_eq!(packet.num_srcs(), None);
        assert_eq!(packet.qrv(), None);
        assert!(Packet::new_checked(&mut bytes[..23]).is_err());

        // Too short for MLDv2, too long for MLDv1: the consumer ignores it.
        let mut bytes = [0u8; 26];
        bytes[0] = 0x82;
        let packet = Packet::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(packet.payload().len(), 2);
        assert_eq!(packet.s_flag(), None);
    }

    #[test]
    fn test_query_construct() {
        let mut bytes = [0xff; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::MldQuery);
        packet.set_msg_code(0);
        packet.set_max_resp_code(0x0400);
        packet.set_mcast_addr(IPV6_LINK_LOCAL_ALL_NODES);
        packet.set_s_flag();
        packet.set_qrv(0x02);
        packet.set_qqic(0x12);
        packet.set_num_srcs(0x01);
        packet
            .payload_mut()
            .copy_from_slice(&IPV6_LINK_LOCAL_ALL_ROUTERS.octets());
        packet.clear_reserved();
        packet.fill_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(&bytes[..], &QUERY_PACKET_BYTES[..]);
    }

    #[test]
    fn test_record_deconstruct() {
        let mut bytes = REPORT_PACKET_BYTES;
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        assert_eq!(packet.msg_type(), Message::MldReport);
        assert_eq!(packet.msg_code(), 0);
        assert_eq!(packet.checksum(), 0x7385);
        assert_eq!(packet.nr_mcast_addr_rcrds(), 0x01);
        assert!(packet.verify_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS));
        let addr_rcrd = AddressRecord::new_checked(packet.payload_mut()).unwrap();
        assert_eq!(addr_rcrd.record_type(), RecordType::ModeIsInclude);
        assert_eq!(addr_rcrd.aux_data_len(), 0x00);
        assert_eq!(addr_rcrd.num_srcs(), 0x01);
        assert_eq!(addr_rcrd.mcast_addr(), IPV6_LINK_LOCAL_ALL_NODES);
        assert_eq!(
            Ipv6Addr::from_octets(addr_rcrd.payload().try_into().unwrap()),
            IPV6_LINK_LOCAL_ALL_ROUTERS
        );
    }

    #[test]
    fn test_record_construct() {
        let mut bytes = [0xff; 44];
        let mut packet = Packet::new_unchecked(&mut bytes[..]);
        packet.set_msg_type(Message::MldReport);
        packet.set_msg_code(0);
        packet.clear_reserved();
        packet.set_nr_mcast_addr_rcrds(1);
        {
            let mut addr_rcrd = AddressRecord::new_unchecked(packet.payload_mut());
            addr_rcrd.set_record_type(RecordType::ModeIsInclude);
            addr_rcrd.set_aux_data_len(0);
            addr_rcrd.set_num_srcs(1);
            addr_rcrd.set_mcast_addr(IPV6_LINK_LOCAL_ALL_NODES);
            addr_rcrd
                .payload_mut()
                .copy_from_slice(&IPV6_LINK_LOCAL_ALL_ROUTERS.octets());
        }
        packet.fill_checksum(&IPV6_LINK_LOCAL_ALL_NODES, &IPV6_LINK_LOCAL_ALL_ROUTERS);
        assert_eq!(&bytes[..], &REPORT_PACKET_BYTES[..]);
    }

    #[test]
    fn test_record_too_short() {
        let mut bytes = [0; ADDRESS_RECORD_LEN - 1];
        assert_eq!(AddressRecord::new_checked(&mut bytes[..]).err(), Some(Malformed));
    }

    #[test]
    fn test_max_resp_code_decode() {
        // RFC 3810 §5.1.3: linear below 32768, floating point from there.
        assert_eq!(max_resp_code_to_delay(0), Duration::ZERO);
        assert_eq!(max_resp_code_to_delay(1000), Duration::from_millis(1000));
        assert_eq!(max_resp_code_to_delay(0x7FFF), Duration::from_millis(32767));
        assert_eq!(max_resp_code_to_delay(0x8000), Duration::from_millis(32768));
        assert_eq!(max_resp_code_to_delay(0x8001), Duration::from_millis(32776));
        assert_eq!(max_resp_code_to_delay(0x9000), Duration::from_millis(65536));
        assert_eq!(max_resp_code_to_delay(0xFFFF), Duration::from_millis(8_387_584));
    }

    #[test]
    fn test_max_resp_code_round_trip() {
        for code in 0..=u16::MAX {
            assert_eq!(delay_to_max_resp_code(max_resp_code_to_delay(code)), code);
        }
    }

    #[test]
    fn test_max_resp_delay_encode_rounding() {
        // In the floating point range the delay is rounded down to a multiple
        // of the exponent's step, 8 ms for exponent 0.
        assert_eq!(delay_to_max_resp_code(Duration::from_millis(40_000)), 0x8388);
        assert_eq!(delay_to_max_resp_code(Duration::from_millis(40_007)), 0x8388);
        assert_eq!(max_resp_code_to_delay(0x8388), Duration::from_millis(40_000));
        // Anything past the largest encodable delay is clamped to it.
        for millis in [8_387_584, 8_387_585, 10_000_000] {
            assert_eq!(delay_to_max_resp_code(Duration::from_millis(millis)), 0xFFFF);
        }
    }

    #[test]
    fn test_set_max_resp_delay() {
        let mut bytes = vec![0; 28];
        let mut packet = Packet::new_unchecked(&mut bytes);
        packet.set_msg_type(Message::MldQuery);
        packet.set_max_resp_delay(Duration::from_millis(65_536));
        assert_eq!(packet.max_resp_code(), 0x9000);
        assert_eq!(packet.max_resp_delay(), Duration::from_millis(65_536));
    }
}
