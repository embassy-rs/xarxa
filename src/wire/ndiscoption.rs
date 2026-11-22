use bitflags::bitflags;
use byteorder::{ByteOrder, NetworkEndian};

use crate::error::Malformed;
use crate::time::Duration;
use crate::wire::{Ipv6Addr, MAX_HARDWARE_ADDRESS_LEN};

use crate::wire::RawHardwareAddress;

open_enum! {
    /// NDISC Option Type
    pub enum Type(u8) {
        /// Source Link-layer Address
        SourceLinkLayerAddr = 0x1,
        /// Target Link-layer Address
        TargetLinkLayerAddr = 0x2,
        /// Prefix Information
        PrefixInformation   = 0x3,
        /// Redirected Header
        RedirectedHeader    = 0x4,
        /// MTU
        Mtu                 = 0x5
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PrefixInfoFlags: u8 {
        const ON_LINK  = 0b10000000;
        const ADDRCONF = 0b01000000;
    }
}

/// A read/write wrapper around an [NDISC Option].
///
/// [NDISC Option]: https://tools.ietf.org/html/rfc4861#section-4.6
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq)]
pub struct NdiscOption<'a> {
    buffer: &'a mut [u8],
}

// Format of an NDISC Option
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |              ...              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// ~                              ...                              ~
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// See https://tools.ietf.org/html/rfc4861#section-4.6 for details.
mod field {
    #![allow(non_snake_case)]

    use crate::wire::field::*;

    // 8-bit identifier of the type of option.
    pub const TYPE: usize = 0;
    // 8-bit unsigned integer. Length of the option, in units of 8 octets.
    pub const LENGTH: usize = 1;
    // Variable-length field. Option-Type-specific data.
    pub const fn DATA(length: u8) -> Field {
        2..length as usize * 8
    }

    // Source/Target Link-layer Option fields.
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix Information Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Valid Lifetime                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                       Preferred Lifetime                      |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved2                           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +                            Prefix                             +
    //  |                                                               |
    //  +                                                               +
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Prefix length.
    pub const PREFIX_LEN: usize = 2;
    // Flags field of prefix header.
    pub const FLAGS: usize = 3;
    // Valid lifetime.
    pub const VALID_LT: Field = 4..8;
    // Preferred lifetime.
    pub const PREF_LT: Field = 8..12;
    // Reserved bits
    pub const PREF_RESERVED: Field = 12..16;
    // Prefix
    pub const PREFIX: Field = 16..32;

    // Redirected Header Option fields.
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |            Reserved           |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                           Reserved                            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                                                               |
    //  ~                       IP header + data                        ~
    //  |                                                               |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // Reserved bits.
    pub const REDIRECTED_RESERVED: Field = 2..8;

    // MTU Option fields
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |     Type      |    Length     |           Reserved            |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                              MTU                              |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    //  MTU
    pub const MTU_RESERVED: Field = 2..4;
    pub const MTU: Field = 4..8;
}

/// Core getter methods relevant to any type of NDISC option.
impl<'a> NdiscOption<'a> {
    /// Create a raw octet buffer with an NDISC Option structure.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> NdiscOption<'a> {
        NdiscOption { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<NdiscOption<'a>, Malformed> {
        let opt = Self::new_unchecked(buffer);
        opt.check_len()?;
        Ok(opt)
    }

    /// Ensure that no accessor method will panic if called.
    ///
    /// This checks the framing only, for any option type value: the Length field
    /// is not zero (RFC 4861 §4.6), and the buffer holds that many bytes. The
    /// accessors of a type that needs more than the 8 bytes every option has, like
    /// [prefix_information], return `None` for an option too short for it.
    /// Whether the option is valid for its type is up to the consumer.
    ///
    /// The result of this check is invalidated by calling [set_data_len].
    ///
    /// # Errors
    /// - `Malformed`: if the Length field is zero, or the buffer is too short.
    ///
    /// [prefix_information]: #method.prefix_information
    /// [set_data_len]: #method.set_data_len
    pub fn check_len(&self) -> Result<(), Malformed> {
        match option_len(self.buffer) {
            Some(_) => Ok(()),
            None => Err(Malformed),
        }
    }

    /// Return the option type.
    #[inline]
    pub fn option_type(&self) -> Type {
        Type::from(self.buffer[field::TYPE])
    }

    /// Return the length of the data.
    #[inline]
    pub fn data_len(&self) -> u8 {
        self.buffer[field::LENGTH]
    }
}

/// Getter methods only relevant for Source/Target Link-layer Address options.
impl<'a> NdiscOption<'a> {
    /// Return the Source/Target Link-layer Address.
    #[inline]
    pub fn link_layer_addr(&self) -> RawHardwareAddress {
        let len = MAX_HARDWARE_ADDRESS_LEN.min(self.data_len() as usize * 8 - 2);
        RawHardwareAddress::from_bytes(&self.buffer[2..len + 2])
    }
}

/// Getter methods only relevant for the MTU option.
impl<'a> NdiscOption<'a> {
    /// Return the MTU value.
    #[inline]
    pub fn mtu(&self) -> u32 {
        NetworkEndian::read_u32(&self.buffer[field::MTU])
    }
}

/// The fields of a Prefix Information option.
///
/// See [RFC 4861 § 4.6.2].
///
/// [RFC 4861 § 4.6.2]: https://tools.ietf.org/html/rfc4861#section-4.6.2
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformation {
    /// The number of leading bits of `prefix` that are valid.
    pub prefix_len: u8,
    /// The on-link and autonomous address-configuration flags.
    pub flags: PrefixInfoFlags,
    /// How long the prefix is valid for on-link determination.
    pub valid_lifetime: Duration,
    /// How long addresses formed from the prefix stay preferred.
    pub preferred_lifetime: Duration,
    /// The prefix. Bits past `prefix_len` are not meaningful.
    pub prefix: Ipv6Addr,
}

/// Getter methods only relevant for the Prefix Information option.
impl<'a> NdiscOption<'a> {
    /// Return the fields of a Prefix Information option, or `None` if the
    /// option is too short to hold them.
    ///
    /// This does not look at the option type.
    #[inline]
    pub fn prefix_information(&self) -> Option<PrefixInformation> {
        if field::DATA(self.data_len()).end < field::PREFIX.end {
            return None;
        }
        Some(PrefixInformation {
            prefix_len: self.buffer[field::PREFIX_LEN],
            flags: PrefixInfoFlags::from_bits_truncate(self.buffer[field::FLAGS]),
            valid_lifetime: Duration::from_secs(NetworkEndian::read_u32(&self.buffer[field::VALID_LT])),
            preferred_lifetime: Duration::from_secs(NetworkEndian::read_u32(&self.buffer[field::PREF_LT])),
            prefix: Ipv6Addr::from_octets(self.buffer[field::PREFIX].try_into().unwrap()),
        })
    }
}

impl<'a> NdiscOption<'a> {
    /// Return the option data.
    #[inline]
    pub fn data(&self) -> &[u8] {
        let len = self.data_len();
        &self.buffer[field::DATA(len)]
    }
}

/// Core setter methods relevant to any type of NDISC option.
impl<'a> NdiscOption<'a> {
    /// Set the option type.
    #[inline]
    pub fn set_option_type(&mut self, value: Type) {
        self.buffer[field::TYPE] = value.into();
    }

    /// Set the option data length.
    #[inline]
    pub fn set_data_len(&mut self, value: u8) {
        self.buffer[field::LENGTH] = value;
    }
}

/// Setter methods only relevant for Source/Target Link-layer Address options.
impl<'a> NdiscOption<'a> {
    /// Set the Source/Target Link-layer Address.
    #[inline]
    pub fn set_link_layer_addr(&mut self, addr: RawHardwareAddress) {
        self.buffer[2..2 + addr.len()].copy_from_slice(addr.as_bytes())
    }
}

/// Setter methods only relevant for the MTU option.
impl<'a> NdiscOption<'a> {
    /// Clear the reserved area of the MTU option.
    #[inline]
    pub fn clear_mtu_reserved(&mut self) {
        NetworkEndian::write_u16(&mut self.buffer[field::MTU_RESERVED], 0);
    }

    /// Set the MTU value.
    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buffer[field::MTU], value);
    }
}

/// Setter methods only relevant for the Prefix Information option.
impl<'a> NdiscOption<'a> {
    /// Set the prefix length.
    #[inline]
    pub fn set_prefix_len(&mut self, value: u8) {
        self.buffer[field::PREFIX_LEN] = value;
    }

    /// Set the prefix information flags.
    #[inline]
    pub fn set_prefix_flags(&mut self, flags: PrefixInfoFlags) {
        self.buffer[field::FLAGS] = flags.bits();
    }

    /// Set the valid lifetime of the prefix.
    #[inline]
    pub fn set_valid_lifetime(&mut self, time: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::VALID_LT], time.as_secs());
    }

    /// Set the preferred lifetime of the prefix.
    #[inline]
    pub fn set_preferred_lifetime(&mut self, time: Duration) {
        NetworkEndian::write_u32(&mut self.buffer[field::PREF_LT], time.as_secs());
    }

    /// Clear the reserved bits.
    #[inline]
    pub fn clear_prefix_reserved(&mut self) {
        NetworkEndian::write_u32(&mut self.buffer[field::PREF_RESERVED], 0);
    }

    /// Set the prefix.
    #[inline]
    pub fn set_prefix(&mut self, addr: Ipv6Addr) {
        self.buffer[field::PREFIX].copy_from_slice(&addr.octets());
    }
}

/// Setter methods only relevant for the Redirected Header option.
impl<'a> NdiscOption<'a> {
    /// Clear the reserved bits.
    #[inline]
    pub fn clear_redirected_reserved(&mut self) {
        self.buffer[field::REDIRECTED_RESERVED].fill_with(|| 0);
    }
}

impl<'a> NdiscOption<'a> {
    /// Return a mutable pointer to the option data.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        &mut self.buffer[field::DATA(len)]
    }
}

/// The length of the option at the start of `buffer`, from its Length field, or
/// `None` if the Length field is zero or the buffer is too short for it.
fn option_len(buffer: &[u8]) -> Option<usize> {
    // An option is a whole number of 8-byte units, and at least one. The
    // accessors that need no more than one unit read within it.
    let len = *buffer.get(field::LENGTH)? as usize * 8;
    if len == 0 || len > buffer.len() {
        return None;
    }
    Some(len)
}

/// An iterator over the options of an NDISC message.
///
/// Each option is yielded as an [`NdiscOption`] whose buffer is that option
/// alone, so it passes [`NdiscOption::check_len`]. Every option is yielded,
/// whatever its type or contents: options the message does not use, and options
/// that do not parse as their type, are for the consumer to skip (RFC 4861
/// §6.1.2, §7.1.1, §7.1.2).
#[derive(Debug)]
pub struct NdiscOptions<'a> {
    buffer: &'a mut [u8],
}

impl<'a> NdiscOptions<'a> {
    /// Iterate over the options in `buffer`, the options area of an NDISC
    /// message, without checking their framing first.
    ///
    /// The iteration stops at the first option whose framing is broken.
    pub const fn new_unchecked(buffer: &'a mut [u8]) -> NdiscOptions<'a> {
        NdiscOptions { buffer }
    }

    /// Iterate over the options in `buffer`, the options area of an NDISC
    /// message, after checking the framing of them all.
    ///
    /// # Errors
    /// - `Malformed`: if an option has a Length of zero or runs past the end of
    ///   the buffer. RFC 4861 discards the whole message then.
    pub fn new_checked(buffer: &'a mut [u8]) -> Result<NdiscOptions<'a>, Malformed> {
        let mut rest = &buffer[..];
        while !rest.is_empty() {
            let len = option_len(rest).ok_or(Malformed)?;
            rest = &rest[len..];
        }
        Ok(Self::new_unchecked(buffer))
    }
}

impl<'a> Iterator for NdiscOptions<'a> {
    type Item = NdiscOption<'a>;

    fn next(&mut self) -> Option<NdiscOption<'a>> {
        let len = option_len(self.buffer)?;
        let (opt, rest) = core::mem::take(&mut self.buffer).split_at_mut(len);
        self.buffer = rest;
        Some(NdiscOption::new_unchecked(opt))
    }
}

#[cfg(test)]
mod test {
    use super::Malformed;
    use super::{NdiscOption, NdiscOptions, PrefixInfoFlags, PrefixInformation, Type};
    use crate::time::Duration;
    use crate::wire::Ipv6Addr;

    static PREFIX_OPT_BYTES: [u8; 32] = [
        0x03, 0x04, 0x40, 0xc0, 0x00, 0x00, 0x03, 0x84, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn test_deconstruct() {
        let mut bytes = PREFIX_OPT_BYTES;
        let opt = NdiscOption::new_unchecked(&mut bytes[..]);
        assert_eq!(opt.option_type(), Type::PrefixInformation);
        assert_eq!(opt.data_len(), 4);
        assert_eq!(
            opt.prefix_information(),
            Some(PrefixInformation {
                prefix_len: 64,
                flags: PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF,
                valid_lifetime: Duration::from_secs(900),
                preferred_lifetime: Duration::from_secs(1000),
                prefix: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            })
        );
    }

    #[test]
    fn test_construct() {
        // Into a buffer full of stale bytes: every byte of the option is written.
        let mut bytes = [0x2a; 32];
        let mut opt = NdiscOption::new_unchecked(&mut bytes[..]);
        opt.set_option_type(Type::PrefixInformation);
        opt.set_data_len(4);
        opt.set_prefix_len(64);
        opt.set_prefix_flags(PrefixInfoFlags::ON_LINK | PrefixInfoFlags::ADDRCONF);
        opt.set_valid_lifetime(Duration::from_secs(900));
        opt.set_preferred_lifetime(Duration::from_secs(1000));
        opt.clear_prefix_reserved();
        opt.set_prefix(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(&bytes[..], &PREFIX_OPT_BYTES[..]);
    }

    #[test]
    fn test_mtu() {
        let mut bytes = [0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc];
        let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(opt.option_type(), Type::Mtu);
        assert_eq!(opt.data_len(), 1);
        assert_eq!(opt.mtu(), 1500);

        let mut built = [0x2a; 8];
        let mut opt = NdiscOption::new_unchecked(&mut built[..]);
        opt.set_option_type(Type::Mtu);
        opt.set_data_len(1);
        opt.clear_mtu_reserved();
        opt.set_mtu(1500);
        assert_eq!(built, bytes);
    }

    /// An 8-byte link-layer address option (data length 1) carries an Ethernet
    /// address, as a source or a target option alike.
    #[test]
    #[cfg(feature = "medium-ethernet")]
    fn test_link_layer_addr_ethernet() {
        use crate::iface::Medium;
        use crate::wire::{EthernetAddress, HardwareAddress};
        let mut bytes = [0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34];
        let addr = HardwareAddress::Ethernet(EthernetAddress([0x54, 0x52, 0x00, 0x12, 0x23, 0x34]));
        {
            let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(opt.option_type(), Type::SourceLinkLayerAddr);
            assert_eq!(opt.data_len(), 1);
            assert_eq!(opt.link_layer_addr().parse(Medium::Ethernet), Ok(addr));
            #[cfg(feature = "medium-ieee802154")]
            assert!(opt.link_layer_addr().parse(Medium::Ieee802154).is_err());
        }
        bytes[0] = 0x02;
        {
            let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
            assert_eq!(opt.option_type(), Type::TargetLinkLayerAddr);
            assert_eq!(opt.link_layer_addr().parse(Medium::Ethernet), Ok(addr));
        }

        // The same option, built with the setters.
        let mut built = [0x2a; 8];
        let mut opt = NdiscOption::new_unchecked(&mut built[..]);
        opt.set_option_type(Type::TargetLinkLayerAddr);
        opt.set_data_len(1);
        opt.set_link_layer_addr(addr.into());
        assert_eq!(built, bytes);
    }

    /// A 16-byte link-layer address option (data length 2) carries an
    /// extended 802.15.4 address, padded with zeros.
    #[test]
    #[cfg(feature = "medium-ieee802154")]
    fn test_link_layer_addr_ieee802154() {
        use crate::iface::Medium;
        use crate::wire::{HardwareAddress, Ieee802154Address};
        let mut bytes = [
            0x01, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let opt = NdiscOption::new_checked(&mut bytes[..]).unwrap();
        assert_eq!(opt.option_type(), Type::SourceLinkLayerAddr);
        assert_eq!(opt.data_len(), 2);
        let addr = Ieee802154Address::Extended([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(
            opt.link_layer_addr().parse(Medium::Ieee802154),
            Ok(HardwareAddress::Ieee802154(addr))
        );
        #[cfg(feature = "medium-ethernet")]
        assert!(opt.link_layer_addr().parse(Medium::Ethernet).is_err());
    }

    #[test]
    fn test_short_packet() {
        assert_eq!(NdiscOption::new_checked(&mut [0x00, 0x00]), Err(Malformed));
        assert_eq!(
            NdiscOption::new_checked(&mut [0x01, 0x02, 0, 0, 0, 0, 0, 0]),
            Err(Malformed)
        );
    }

    /// Length 0 fails `check_len`, not only `new_checked`, so that no accessor
    /// can panic after `check_len` passed.
    #[test]
    fn test_zero_length() {
        let mut bytes = [0x01, 0x00, 0, 0, 0, 0, 0, 0];
        assert_eq!(NdiscOption::new_unchecked(&mut bytes).check_len(), Err(Malformed));
        assert_eq!(NdiscOption::new_checked(&mut bytes), Err(Malformed));
    }

    /// A Prefix Information or Redirected Header option shorter than its type
    /// needs is well framed. Only the accessor that needs the bytes says so.
    #[test]
    fn test_short_typed_option() {
        let mut bytes = [0x03, 0x01, 0, 0, 0, 0, 0, 0];
        let opt = NdiscOption::new_checked(&mut bytes).unwrap();
        assert_eq!(opt.prefix_information(), None);
        let mut bytes = [0x04, 0x01, 0, 0, 0, 0, 0, 0];
        assert!(NdiscOption::new_checked(&mut bytes).is_ok());

        // The bytes of the next option do not count toward a short one.
        let mut bytes = [0u8; 32];
        bytes[..2].copy_from_slice(&[0x03, 0x01]);
        bytes[8..10].copy_from_slice(&[0xc8, 0x03]);
        let mut opts = NdiscOptions::new_checked(&mut bytes).unwrap();
        assert_eq!(opts.next().unwrap().prefix_information(), None);
        assert_eq!(opts.next().unwrap().option_type(), Type::from(0xc8));
        assert!(opts.next().is_none());
    }

    #[test]
    fn test_options_iter() {
        let mut bytes = [0u8; 8 + 32 + 8];
        bytes[..8].copy_from_slice(&[0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34]);
        bytes[8..40].copy_from_slice(&PREFIX_OPT_BYTES);
        bytes[40..].copy_from_slice(&[0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xdc]);
        let types: Vec<_> = NdiscOptions::new_checked(&mut bytes)
            .unwrap()
            .map(|opt| (opt.option_type(), opt.data().len()))
            .collect();
        assert_eq!(
            types,
            [
                (Type::SourceLinkLayerAddr, 6),
                (Type::PrefixInformation, 30),
                (Type::Mtu, 6)
            ]
        );

        assert!(NdiscOptions::new_checked(&mut []).unwrap().next().is_none());
    }

    /// A broken framing anywhere fails the whole walk, as RFC 4861 discards the
    /// message. Unchecked, the walk stops there.
    #[test]
    fn test_options_framing() {
        // Length 0 after a good option.
        let mut bytes = [0x05, 0x01, 0, 0, 0, 0, 0x05, 0xdc, 0xc8, 0x00, 0, 0, 0, 0, 0, 0];
        assert!(NdiscOptions::new_checked(&mut bytes).is_err());
        let mut opts = NdiscOptions::new_unchecked(&mut bytes);
        assert_eq!(opts.next().unwrap().option_type(), Type::Mtu);
        assert!(opts.next().is_none());

        // An option running past the end.
        let mut bytes = [0x05, 0x01, 0, 0, 0, 0, 0x05, 0xdc, 0xc8, 0x02, 0, 0, 0, 0, 0, 0];
        assert!(NdiscOptions::new_checked(&mut bytes).is_err());

        // Trailing bytes too short for an option.
        let mut bytes = [0x05, 0x01, 0, 0, 0, 0, 0x05, 0xdc, 0xc8];
        assert!(NdiscOptions::new_checked(&mut bytes).is_err());
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PrefixInfoFlags {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "PrefixInfoFlags({=u8:#010b})", self.bits());
    }
}
