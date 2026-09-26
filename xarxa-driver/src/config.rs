//! Compile-time configuration.
//!
//! The sizes of the packet pool and of the buffers in it are set at compile
//! time. They can be set in two ways:
//!
//! - With a cargo feature named `<name>-<value>`, lowercase and with dashes
//!   instead of underscores. For example `packet-buf-count-32`. Only the values
//!   listed in `Cargo.toml` can be set this way.
//! - With an environment variable named `XARXA_<NAME>` at build time. For
//!   example `XARXA_PACKET_BUF_COUNT=32 cargo build`. They can also be set in
//!   the `[env]` section of `.cargo/config.toml`. Any value can be set this way.
//!
//! Environment variables win over cargo features. Enabling two cargo features
//! for the same setting with different values fails the build.
//!
//! The `xarxa` crate forwards the features of the same name to this crate, and
//! has its own knobs in `xarxa::config`.

mod raw {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

/// Number of buffers in the packet pool.
///
/// Every packet in flight takes one buffer: in a driver's receive ring, in a
/// socket's queue, being reassembled, or parked waiting for a neighbor. When
/// they are all in use, [`PacketBuf::try_new`](crate::PacketBuf::try_new) fails
/// and packets are dropped.
///
/// Default: 16.
pub const PACKET_BUF_COUNT: usize = raw::PACKET_BUF_COUNT;

/// Alignment of the buffer in a [`PacketBuf`](crate::PacketBuf), in bytes.
///
/// DMA engines often require the buffers they write to be aligned. Raising this
/// also rounds [`PACKET_BUF_SIZE`] up to a multiple of it, since such engines
/// write whole bus words past the end of the frame.
///
/// Can only be set with cargo features, not with an environment variable. If
/// several are enabled, the highest wins.
///
/// Supported values: 1, 2, 4, 8, 16, 32.
///
/// Default: 1.
pub const PACKET_BUF_ALIGN: usize = cfg_select! {
    feature = "packet-buf-align-32" => 32,
    feature = "packet-buf-align-16" => 16,
    feature = "packet-buf-align-8" => 8,
    feature = "packet-buf-align-4" => 4,
    feature = "packet-buf-align-2" => 2,
    _ => 1,
};

const fn packet_buf_driver_headroom(cfg_head: usize) -> usize {
    if cfg_head == 0 {
        0
    } else if PACKET_BUF_ALIGN > cfg_head {
        PACKET_BUF_ALIGN
    } else {
        cfg_head
    }
}

/// Default headroom of the buffer in a [`PacketBuf`](crate::PacketBuf), in bytes.
pub const PACKET_BUF_DRIVER_HEADROOM: usize = packet_buf_driver_headroom(cfg_select! {
    feature = "packet-buf-driver-headroom-64" => 64,
    feature = "packet-buf-driver-headroom-32" => 32,
    feature = "packet-buf-driver-headroom-16" => 16,
    feature = "packet-buf-driver-headroom-8" => 8,
    feature = "packet-buf-driver-headroom-4" => 4,
    feature = "packet-buf-driver-headroom-2" => 2,
    _ => 0,
});

/// Size of the buffer in a [`PacketBuf`](crate::PacketBuf), in bytes.
///
/// This is the largest frame that can be sent or received, headers included.
/// It also caps the MTU of every interface.
///
/// The configured value is rounded up to a multiple of [`PACKET_BUF_ALIGN`].
///
/// Pick it for the largest frame your links carry:
/// - 1514 for Ethernet. 1518 or 1522 with one or two VLAN tags.
/// - 9018 or so for Ethernet with jumbo frames.
/// - 128 or 256 for IEEE 802.15.4 without 6LoWPAN fragmentation. 256 leaves
///   room for the headers to grow when they are decompressed.
///
/// Going below the protocol minimums works, but breaks interoperability:
/// - IPv6 needs 1280 bytes plus the link header (RFC 8200).
/// - IPv4 hosts must accept 576 bytes plus the link header (RFC 791).
///
/// Must be between 128 and 65535.
///
/// Default: 1514.
pub const PACKET_BUF_SIZE: usize = raw::PACKET_BUF_SIZE.next_multiple_of(PACKET_BUF_ALIGN) + PACKET_BUF_DRIVER_HEADROOM;

// `headroom` and `len` are `u16`.
const _: () = assert!(
    PACKET_BUF_SIZE <= u16::MAX as usize,
    "PACKET_BUF_SIZE must be at most 65535"
);
// Room for the largest headers the stack writes in front of a payload.
const _: () = assert!(PACKET_BUF_SIZE >= 128, "PACKET_BUF_SIZE must be at least 128");
