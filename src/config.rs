//! Compile-time configuration.
//!
//! The sizes of the stack's tables, queues and buffers are set at compile time.
//! They can be set in two ways:
//!
//! - With a cargo feature named `<name>-<value>`, lowercase and with dashes
//!   instead of underscores. For example `udp-socket-count-8`. Only the values
//!   listed in `Cargo.toml` can be set this way.
//! - With an environment variable named `XARXA_<NAME>` at build time. For
//!   example `XARXA_UDP_SOCKET_COUNT=8 cargo build`. They can also be set in the
//!   `[env]` section of `.cargo/config.toml`. Any value can be set this way.
//!
//! Environment variables take priority over cargo features. Enabling two cargo features
//! for the same setting with different values fails the build.
//!
//! Some data structures are statically or dynamically allocated depending on the `alloc` feature,
//! so some limits apply only with `alloc` disabled.

mod raw {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

// Index types for the handles of the slabs sized by the knobs below. Which ones
// are used depends on the enabled features.
#[allow(unused_imports)]
pub(crate) use raw::{dns_query_index, iface_index, raw_index, tcp_index, tcp_listener_index, udp_index};

// ======== Packet buffers

/// Headroom the stack leaves in front of every packet it hands to a driver, in bytes.
///
/// For drivers that add headers of their own.
///
/// Can only be set with cargo features, not with an environment variable. If
/// several are enabled, the highest wins.
///
/// Supported values: 0, 2, 4, 8, 16, 32, 64.
///
/// Default: 0.
pub const PACKET_BUF_DRIVER_HEADROOM: usize = cfg_select! {
    feature = "packet-buf-driver-headroom-64" => 64,
    feature = "packet-buf-driver-headroom-32" => 32,
    feature = "packet-buf-driver-headroom-16" => 16,
    feature = "packet-buf-driver-headroom-8" => 8,
    feature = "packet-buf-driver-headroom-4" => 4,
    feature = "packet-buf-driver-headroom-2" => 2,
    _ => 0,
};

// ======== Interfaces and their tables

/// Max interfaces a [`Stack`](crate::Stack) can hold.
///
/// Ignored with `alloc`. Default: 2.
pub const IFACE_COUNT: usize = raw::IFACE_COUNT;

/// Max IP addresses an interface can hold.
///
/// This counts addresses from all sources: set by the application, learned from
/// DHCP or from SLAAC.
///
/// Ignored with `alloc`. Default: 4.
pub const IFACE_ADDR_COUNT: usize = raw::IFACE_ADDR_COUNT;

/// Max routes the routing table can hold.
///
/// This counts routes from all sources: added by the application, learned from
/// DHCP or from router advertisements.
///
/// Ignored with `alloc`. Default: 4.
pub const ROUTE_COUNT: usize = raw::ROUTE_COUNT;

/// Max multicast groups a [`Stack`](crate::Stack) can be joined to.
///
/// Ignored with `alloc`. Default: 8.
pub const MULTICAST_GROUP_COUNT: usize = raw::MULTICAST_GROUP_COUNT;

/// Max advertised prefixes SLAAC tracks per interface.
///
/// Ignored with `alloc`. Default: 2.
pub const SLAAC_PREFIX_COUNT: usize = raw::SLAAC_PREFIX_COUNT;

/// Max default routers SLAAC tracks per interface.
///
/// Ignored with `alloc`. Default: 2.
pub const SLAAC_ROUTER_COUNT: usize = raw::SLAAC_ROUTER_COUNT;

/// Max 6LoWPAN address contexts an interface can hold.
///
/// Ignored with `alloc`. Default: 4.
pub const SIXLOWPAN_ADDRESS_CONTEXT_COUNT: usize = raw::SIXLOWPAN_ADDRESS_CONTEXT_COUNT;

// ======== Neighbors

/// Max neighbors the stack remembers, across all interfaces.
///
/// The cache holds the hardware address of each neighbor, learned from ARP or
/// NDISC. When it is full, learning a neighbor evicts another one.
///
/// This is a limit with and without `alloc`. Default: 8.
pub const NEIGHBOR_CACHE_COUNT: usize = raw::NEIGHBOR_CACHE_COUNT;

/// Max packets in the "pending neighbor" queue.
///
/// When sending packets to an unresolved neighbor, they get parked in
/// this queue temporarily while ARP or NDISC resolves.
///
/// This is a limit with and without `alloc`. Default: 16.
pub const PENDING_QUEUE_COUNT: usize = raw::PENDING_QUEUE_COUNT;

/// TX timestamps queued per stack with `packetmeta-timestamp`.
///
/// Full queues drop incoming timestamps. Always bounded, including with `alloc`.
/// Default: 4.
pub const TX_TIMESTAMP_QUEUE_COUNT: usize = raw::TX_TIMESTAMP_QUEUE_COUNT;

// ======== Sockets

/// Max UDP sockets a [`Stack`](crate::Stack) can hold.
///
/// Ignored with `alloc`. Default: 4.
pub const UDP_SOCKET_COUNT: usize = raw::UDP_SOCKET_COUNT;

/// Max raw sockets a [`Stack`](crate::Stack) can hold.
///
/// Ignored with `alloc`. Default: 2.
pub const RAW_SOCKET_COUNT: usize = raw::RAW_SOCKET_COUNT;

/// Max TCP sockets a [`Stack`](crate::Stack) can hold.
///
/// Ignored with `alloc`. Default: 4.
pub const TCP_SOCKET_COUNT: usize = raw::TCP_SOCKET_COUNT;

/// Max TCP listeners a [`Stack`](crate::Stack) can hold.
///
/// Ignored with `alloc`. Default: 2.
pub const TCP_LISTENER_COUNT: usize = raw::TCP_LISTENER_COUNT;

/// Max datagrams a UDP socket queues for receiving.
///
/// Datagrams arriving on a full queue are dropped.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const UDP_RX_QUEUE_COUNT: usize = raw::UDP_RX_QUEUE_COUNT;

/// Max packets a raw socket queues for receiving.
///
/// Packets arriving on a full queue are dropped.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const RAW_RX_QUEUE_COUNT: usize = raw::RAW_RX_QUEUE_COUNT;

/// Max connections a TCP listener queues for accepting: the SYN backlog.
///
/// SYNs arriving on a full queue are dropped, so the peer retries. A queued SYN
/// costs no buffers: the connection's buffers are created when it is accepted.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const TCP_LISTENER_BACKLOG: usize = raw::TCP_LISTENER_BACKLOG;

// ======== Reassembly

/// Max contiguous data ranges tracked while reassembling.
///
/// This is used both for TCP receive and for IP or 6LoWPAN reassembly.
/// When the assembler is full, data that would need tracking one more range is dropped and has to be retransmitted.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const ASSEMBLER_MAX_SEGMENT_COUNT: usize = raw::ASSEMBLER_MAX_SEGMENT_COUNT;

/// Max datagrams reassembled, IPv4 and 6LoWPAN together.
///
/// Each one holds a packet buffer until it is complete or its reassembly
/// timeout expires. Fragments of further datagrams are dropped.
///
/// This is a limit with and without `alloc`. Default: 1.
pub const REASSEMBLY_BUFFER_COUNT: usize = raw::REASSEMBLY_BUFFER_COUNT;

// ======== DNS and DHCP

/// Max DNS queries in flight.
///
/// Ignored with `alloc`. Default: 4.
pub const DNS_MAX_QUERY_COUNT: usize = raw::DNS_MAX_QUERY_COUNT;

/// Max addresses one DNS query returns.
///
/// Further addresses in the answer are ignored.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const DNS_MAX_RESULT_COUNT: usize = raw::DNS_MAX_RESULT_COUNT;

/// Max DNS servers a `DnsClient` can be given.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const DNS_MAX_SERVER_COUNT: usize = raw::DNS_MAX_SERVER_COUNT;

/// Longest DNS name that can be queried, in wire format, in bytes.
///
/// The wire format is one length byte per label plus the label itself, so a name
/// takes one byte more than its dotted form. 255 is the most the DNS protocol
/// allows.
///
/// This is a limit with and without `alloc`. Default: 255.
pub const DNS_MAX_NAME_SIZE: usize = raw::DNS_MAX_NAME_SIZE;

/// Max DNS servers kept from a DHCP lease.
///
/// This is a limit with and without `alloc`. Default: 3.
pub const DHCP_MAX_DNS_SERVER_COUNT: usize = raw::DHCP_MAX_DNS_SERVER_COUNT;

/// Size of the raw options buffer in a DHCP lease, in bytes.
///
/// Only used with the `dhcpv4-options` feature.
///
/// This is a limit with and without `alloc`. Default: 128.
pub const DHCP_OPTIONS_BUF_SIZE: usize = raw::DHCP_OPTIONS_BUF_SIZE;

/// Max leases the DHCP server keeps per interface.
///
/// Only used with the `dhcpv4-server` feature. This bounds how many clients can
/// hold an address. Expired and released leases stay in the table as
/// records until a new client needs their slot.
///
/// This is a limit with and without `alloc`. Default: 8.
pub const DHCP_SERVER_LEASE_COUNT: usize = raw::DHCP_SERVER_LEASE_COUNT;

/// Longest DHCP client identifier a server lease can store, in bytes.
///
/// Only used with the `dhcpv4-server` feature. A client sending a longer
/// identifier is identified by its hardware address instead.
///
/// This is a limit with and without `alloc`. Default: 24.
pub const DHCP_SERVER_CLIENT_ID_SIZE: usize = raw::DHCP_SERVER_CLIENT_ID_SIZE;
