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
//! Some settings are limits only without the `alloc` feature: with it, the table
//! they size grows on the heap instead, and the setting is ignored.
//!
//! The packet pool size is configurable in [`xarxa_driver::config`](crate::driver::config).

mod raw {
    #![allow(unused)]
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

// Index types for the handles of the slabs sized by the knobs below. Which ones
// are used depends on the enabled features.
#[allow(unused_imports)]
pub(crate) use raw::{dns_query_index, iface_index, raw_index, tcp_index, tcp_listener_index, udp_index};

// ======== Interfaces and their tables

/// Max interfaces a [`Stack`](crate::Stack) can hold at once.
///
/// Adding one past this many fails with [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 2.
pub const IFACE_COUNT: usize = raw::IFACE_COUNT;

/// Max IP addresses an interface can hold at once.
///
/// This counts addresses from all sources: set by the application, learned from
/// DHCP, formed by SLAAC. Adding one past this many fails with
/// [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 4.
pub const IFACE_ADDR_COUNT: usize = raw::IFACE_ADDR_COUNT;

/// Max routes the routing table can hold at once.
///
/// This counts routes from all sources: added by the application, learned from
/// DHCP or from router advertisements. Adding one past this many fails with
/// [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 4.
pub const ROUTE_COUNT: usize = raw::ROUTE_COUNT;

/// Max multicast groups a [`Stack`](crate::Stack) can be joined to at once.
///
/// Joining one past this many fails with `TooManyGroups`.
///
/// Ignored with `alloc`. Default: 8.
pub const MULTICAST_GROUP_COUNT: usize = raw::MULTICAST_GROUP_COUNT;

/// Max advertised prefixes SLAAC tracks per interface.
///
/// A router advertisement carrying more is processed up to this many; the rest
/// are ignored, so no address is formed for them.
///
/// Ignored with `alloc`. Default: 2.
pub const SLAAC_PREFIX_COUNT: usize = raw::SLAAC_PREFIX_COUNT;

/// Max default routers SLAAC tracks per interface.
///
/// Advertisements from further routers are ignored once this many are known.
///
/// Ignored with `alloc`. Default: 2.
pub const SLAAC_ROUTER_COUNT: usize = raw::SLAAC_ROUTER_COUNT;

/// Max 6LoWPAN address contexts an interface can hold at once.
///
/// Contexts are used to decompress addresses of incoming packets. Setting more
/// than this many fails with [`Full`](crate::Full). A packet can only name 16 of
/// them, since the context identifier is 4 bits wide.
///
/// Ignored with `alloc`. Default: 4.
pub const SIXLOWPAN_ADDRESS_CONTEXT_COUNT: usize = raw::SIXLOWPAN_ADDRESS_CONTEXT_COUNT;

// ======== Neighbors

/// Max neighbors the stack remembers at once, across all interfaces.
///
/// The cache holds the hardware address of each neighbor, learned from ARP or
/// NDISC. When it is full, learning a neighbor evicts another one, preferring
/// entries whose resolution has already finished.
///
/// This is a limit with and without `alloc`. Default: 8.
pub const NEIGHBOR_CACHE_COUNT: usize = raw::NEIGHBOR_CACHE_COUNT;

/// Max packets parked at once waiting for neighbor resolution.
///
/// A packet whose next hop is not in the neighbor cache is parked here while
/// ARP or NDISC resolves it. Parking one on a full queue drops the oldest.
///
/// This is a limit with and without `alloc`. Default: 16.
pub const PENDING_QUEUE_COUNT: usize = raw::PENDING_QUEUE_COUNT;

// ======== Sockets

/// Max UDP sockets a [`Stack`](crate::Stack) can hold at once.
///
/// Adding one past this many fails with [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 4.
pub const UDP_SOCKET_COUNT: usize = raw::UDP_SOCKET_COUNT;

/// Max raw sockets a [`Stack`](crate::Stack) can hold at once.
///
/// Adding one past this many fails with [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 2.
pub const RAW_SOCKET_COUNT: usize = raw::RAW_SOCKET_COUNT;

/// Max TCP sockets a [`Stack`](crate::Stack) can hold at once.
///
/// Adding one past this many fails with [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 4.
pub const TCP_SOCKET_COUNT: usize = raw::TCP_SOCKET_COUNT;

/// Max TCP listeners a [`Stack`](crate::Stack) can hold at once.
///
/// Adding one past this many fails with [`Full`](crate::Full).
///
/// Ignored with `alloc`. Default: 2.
pub const TCP_LISTENER_COUNT: usize = raw::TCP_LISTENER_COUNT;

/// Max datagrams a UDP socket queues for receiving.
///
/// Datagrams arriving on a full queue are dropped. Each queued datagram holds a
/// packet buffer until the application receives it.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const UDP_RX_QUEUE_COUNT: usize = raw::UDP_RX_QUEUE_COUNT;

/// Max packets a raw socket queues for receiving.
///
/// Packets arriving on a full queue are dropped. Each queued packet holds a
/// packet buffer until the application receives it.
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

/// Max contiguous data ranges tracked at once while reassembling.
///
/// This bounds how scattered the data a TCP socket has received out of order may
/// be, and how many holes an IP or 6LoWPAN datagram being reassembled may have.
/// Data that would need one more range is dropped and has to be retransmitted.
///
/// This is a limit with and without `alloc`. Default: 4.
pub const ASSEMBLER_MAX_SEGMENT_COUNT: usize = raw::ASSEMBLER_MAX_SEGMENT_COUNT;

/// Max datagrams reassembled at once, IPv4 and 6LoWPAN together.
///
/// Each one holds a packet buffer until it is complete or its reassembly
/// timeout expires. Fragments of further datagrams are dropped.
///
/// This is a limit with and without `alloc`. Default: 1.
pub const REASSEMBLY_BUFFER_COUNT: usize = raw::REASSEMBLY_BUFFER_COUNT;

// ======== DNS and DHCP

/// Max DNS queries in flight at once.
///
/// Starting one past this many fails with `StartQueryError::NoFreeSlot`.
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
/// Servers past this many are dropped from the lease.
///
/// This is a limit with and without `alloc`. Default: 3.
pub const DHCP_MAX_DNS_SERVER_COUNT: usize = raw::DHCP_MAX_DNS_SERVER_COUNT;

/// Size of the raw options buffer in a DHCP lease, in bytes.
///
/// Only used with the `dhcpv4-options` feature, which keeps the options of a
/// lease that the client itself does not parse. Options past this many bytes are
/// dropped.
///
/// This is a limit with and without `alloc`. Default: 128.
pub const DHCP_OPTIONS_BUF_SIZE: usize = raw::DHCP_OPTIONS_BUF_SIZE;

/// Max leases the DHCP server keeps per interface.
///
/// Only used with the `dhcpv4-server` feature. This bounds how many clients can
/// hold an address at once. Expired and released leases stay in the table as
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
