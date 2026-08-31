# xarxa

[![docs.rs](https://docs.rs/xarxa/badge.svg)](https://docs.rs/xarxa)
[![crates.io](https://img.shields.io/crates/v/xarxa.svg)](https://crates.io/crates/xarxa)
[![crates.io](https://img.shields.io/matrix/xarxa:matrix.org)](https://matrix.to/#/#xarxa:matrix.org)

> *Xarxa (pronounced "sharsha"): "Network" in Catalan*

_xarxa_ is a standalone network stack designed for embedded, real-time systems.

It can work without `std` and without `alloc`.

The design goals are the following, in order of decreasing priority:

- No `unsafe`. _xarxa_ is exposed to the network and does complex packet parsing and manipulation. We want the guarantee that there is no memory safety vulnerabilities.
- Well suited for small embedded systems. This means low RAM usage, small code size.
- High performance
- Scales up to larger systems with faster links, more sockets, larger buffers.

## _xarxa_ vs _smoltcp_

_xarxa_ is a rewrite/refactor of _smoltcp_ aiming to address some design shortcomings that I felt were holding _smoltcp_ back. (where "I" is Dario Nieuwenhuis ([@dirbaio](https://github.com/Dirbaio)), _smoltcp_ maintainer since 2020 until starting this project). 

_xarxa_ is basically a "port" of _smoltcp_ to the new design. Many parts are not affected and are ported mostly unmodified (e.g TCP, wire), others look more different (e.g. the main Stack) but are a 1:1 port of the original logic wherever possible.

There's two main design decisions where _xarxa_ differs:

### Memory management

_smoltcp_ manages buffers in the following way:

- The device implementation owns a buffer pool where it stores Ethernet frames that are being received/sent.
- The device hands out *borrows* of them to the network stack via the `TxToken`/`RxToken` traits.
- All socket kinds (TCP, UDP, ICMP, raw) own one RX and one TX ring buffer.
- The network stack copies between the device buffers and the socket buffers.

This has a few implications:
- Zero-copy is impossible. You *must* do one copy between device and socket buffers.
- Multi-interface is very hard to implement. (_smoltcp_ is currently single-interface).
  - `TxToken`/`RxToken` make the `Device` trait not `dyn`-compatible.
  - The "receive gives you a `TxToken` to send the reply" trick doesn't work anymore because the reply to a packet may need to go out *another* interface.
- It's very memory-inefficient.
  - You need to pay at least 2x MTU (1500*2 = 3kb) of RAM for each UDP/raw socket you create. This is why _smoltcp_ implements DNS and DHCP sockets as dedicated `DnsSocket` and `DhcpSocket` types instead of building them on top of UDP and raw sockets. This is not very elegant.
  - For multi-interface you need dedicated pools per interface.

Instead, _xarxa_ has a single global packet pool. It passes owned handles around, so any part of the stack (device, sockets, everything else) can easily own packets. This unlocks many improvements:
- Multi-interface becomes trivial.
- Zero-copy is now possible. An interface writes a received packet into a buffer, which then goes through dispatch, gets queued in a socket, and then gets handed to the user. Same for egress.
- It allows fixing "structurally unfixable" bugs like the [tx queue clog](https://github.com/smoltcp-rs/smoltcp/issues/594) when sending to multiple IPs from a single socket.

### "Repr" structs

_smoltcp_ defines plain old Rust structs such as `IpRepr`, `UdpRepr`. At ingress, it reads the packet wire bytes and deserializes it into reprs. At egress, the reprs are serialized to bytes. The entire core works with these repr structs.

_xarxa_ makes the core work with the packet bytes directly instead. Why?

- It's faster. Serializing and deserializing is work that doesn't add value. It just loads from RAM in one format and writes in another format. The compiler is not good at optimizing it out.
- Smaller code size, for the same reason.
- Allows for actually-raw raw sockets. _smoltcp_ raw sockets [drop fields from the IP header](https://github.com/smoltcp-rs/smoltcp/issues/1095) because packets get deserialized and reserialized. The repr structs are intentionally incomplete, they don't contain fields that the stack doesn't look at. Adding them would hurt code size and perf. I've attempted refactors to avoid this reserialization in the past but they ended up too invasive and ugly since you basically need to add a way to thread raw bytes through the whole stack.

## Benchmarks

_xarxa_ is faster and smaller than _smoltcp_, and roughly matches lwIP.
![throughput](https://raw.githubusercontent.com/embassy-rs/xarxa-bench/refs/heads/main/bench-throughput.svg)
![codesize](https://raw.githubusercontent.com/embassy-rs/xarxa-bench/refs/heads/main/bench-codesize.svg)

Benchmark source code is available [here](https://github.com/embassy-rs/xarxa-bench).

## Features

- Multiple interface support
  - Add/remove interfaces dynamically to the network stack.
  - Each interface has its own configuration (like IP addresses)
  - A route table chooses which interface to use on egress.
  - Mixing mediums in is supported.
  - The driver reports its hardware address and link state to the stack.
- Ethernet interface medium (feature `medium-ethernet`)
  - Does IPv4 ARP, IPv6 NDISC.
  - Neighbor cache with expiry, renewal on use.
  - The network stack buffers egress packets pending network resolution. Unreachable neighbors don't [clog sockets](https://github.com/smoltcp-rs/smoltcp/issues/594).
- Pure IP interface medium (feature `medium-ip`)
- IEEE 802.15.4 interface medium (feature `medium-ieee802154`)
  - 6LoWPAN header compression: IPHC for the IPv6 header, NHC for UDP and extension headers, done in place in the packet buffer.
  - Address contexts for decompression.
  - NDISC over 802.15.4, link-local address from the extended address.
  - 6LoWPAN fragmentation (feature `sixlowpan-fragmentation`) 
  - 6LoWPAN reassembly (feature `sixlowpan-reassembly`)
- IPv4 (feature `ipv4`)
  - DHCP client (feature `dhcpv4`)
    - Raw access to all lease options by option number. (feature `dhcpv4-options`)
    - Sends the stack's hostname to the server, if set. (feature `hostname`)
  - DHCP server (feature `dhcpv4-server`)
    - Turned on per interface, hands out leases from a configured pool with gateway and DNS options.
    - API to inspect and remove leases.
  - Fragmentation (feature `ipv4-fragmentation`)
  - Reassembly (feature `ipv4-reassembly`)
- IPv6 (feature `ipv6`)
  - Link-local address automatically derived from the MAC address (EUI-64).
  - SLAAC: addresses and default routes from router advertisements, with lifetimes. (feature `slaac`)
- ICMP
  - Automatically replies to pings. (feature `icmp-ping-reply`)
  - Incoming ICMP errors are routed to the socket that caused them. (feature `icmp-errors`)
- UDP sockets (feature `udp`)
  - **zero-copy** on both TX and RX
  - Supports all binding modes Linux supports, including unconnected (receives from any IP) and connected sockets (receives from one fixed remote IP+port).
- Raw sockets
  - **zero-copy** on both TX and RX
  - Ethernet-layer raw sockets transmit/receive raw Ethernet frames. No routing. (feature `raw-ethernet`)
  - IP-layer raw sockets transmit/receive raw IP packets. The stack handles routing same as other socket types. (feature `raw-ip`)
  - IP headers are byte-copied instead of parsed+re-emitted, so all fields and options are kept, even those unsupported by _xarxa_.
- TCP sockets (feature `tcp`)
  - Full TCP implementation
  - TCP listeners implement an accept queue. Buffers are not allocated until you `accept()` a connection. (feature `tcp-listener`)
  - Window scaling
  - Configurable keepalive.
  - RTT estimation automatically tunes retransmission timeout
  - Compile time selection of CUBIC, Reno or no congestion control.
  - Nagle's algorithm (defaults to enabled, can be turned off)
  - Delayed ACK (defaults to enabled, can be turned off)
  - Zero-window probes
  - TCP Timestamps (feature `tcp-timestamps`)
  - TCP SACK, sending ranges only (feature `tcp-sack`)
- DNS client (feature `dns`)
  - Multiple servers, retransmission with backoff.
  - Multicast DNS for `.local` names (feature `mdns`)
- IP multicast (feature `multicast`)
  - Join and leave multicast groups per interface.
  - IGMPv1/IGMPv2 (IPv4) and MLDv2 (IPv6): membership is reported on join and leave, and in response to router queries.
  - The IPv6 solicited-node groups of the interface's addresses are joined automatically.
- Bind sockets to an interface, like Linux's `SO_BINDTODEVICE`. (feature `iface-bind`)
- Packet metadata
  - Support for hardware timestamping on both RX and TX. Allows implementing protocols like PTP, NTP. (feature `packetmeta-timestamp`)
  - Opaque ID for correlating packets through the stack. (feature `packetmeta-id`)
- Checksum offload: interfaces report which checksums they can validate/calculate and the stack skips them.

## Not yet implemented

All of the below is planned. Please open an issue or reach out on [the Matrix chat](https://matrix.to/#/#xarxa:matrix.org) if you want to work on one of these so we don't duplicate work.

- Acting on link state: skipping down interfaces on egress routing, restarting DHCP/SLAAC on link-up.
- IPv6 DAD (duplicate address detection)
- IPv6 RDNSS (DNS servers from router advertisements)
- an equivalent to smoltcp's `any_ip`
- IPv6 fragmentation and reassembly
- TCP segmentation offload
- TCP SACK, acting on ranges received from the peer.
- Store sockets on a hashmap so packet dispatch is O(1) instead of O(n). (would be optional with a Cargo feature, it's only worth if you have thousands of sockets, i.e. not on embedded)
- Maybe multithreading. Would require per-socket mutexes etc. (again, optional, would require std)

## License

_xarxa_ is distributed under the terms of 0-clause BSD license.

See [LICENSE-0BSD](LICENSE-0BSD.txt) for details.
