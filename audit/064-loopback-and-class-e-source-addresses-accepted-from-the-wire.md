# 064. Loopback and Class E IPv4 source addresses are accepted from the wire and answered

| | |
|---|---|
| Severity | medium |
| Category | security |
| Location | [src/stack.rs:1388](../src/stack.rs#L1388), [src/iface/mod.rs:902](../src/iface/mod.rs#L902), [src/wire/ipv4.rs:64](../src/wire/ipv4.rs#L64), [src/stack.rs:2063](../src/stack.rs#L2063), [src/stack.rs:1580](../src/stack.rs#L1580), [src/stack.rs:1980](../src/stack.rs#L1980) |
| Features | default |
| Verification | reproduced with a test |

## Summary

The IPv4 source check only drops broadcast, multicast and subnet-broadcast sources. Packets from 127.0.0.0/8 and 240.0.0.0/4 are delivered to UDP sockets, and TCP listeners record their SYNs. The stack also answers them with ICMP errors and echo replies, routed out the default gateway.

## Details

src/stack.rs:1388:

```rust
if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
```

src/iface/mod.rs:902:

```rust
address.x_is_unicast() && !self.is_broadcast_v4(address)
```

src/wire/ipv4.rs:64:

```rust
fn x_is_unicast(&self) -> bool {
    !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
}
```

The same `is_unicast_v4` predicate is the "single host" check in `transmit_icmpv4_error` (src/stack.rs:2063), the echo reply path (src/stack.rs:1580) and `deliver_neighbor_failure_error` (src/stack.rs:1980).

The same predicate also lets through 0.x.y.z sources with a non-zero host part, and a source equal to one of our own addresses. Those two were not tested but follow from the code.

## Failure scenario

An on-link attacker sends datagrams with source 127.0.0.1. An application that trusts localhost peers, for example a debug service that filters on remote 127.0.0.1, accepts them. The stack sends ICMP errors and echo replies addressed to 127.0.0.1 or 240.x out its default gateway. TCP listeners queue SYNs from loopback.

## RFC reference

RFC 1122 §3.2.1.3 (g):

> { 127, <any> } Internal host loopback address. Addresses of this form MUST NOT appear outside a host.

RFC 1122 §3.2.1.3:

> A host MUST silently discard an incoming datagram containing an IP source address that is invalid by the rules of this section.

RFC 1122 §3.2.2:

> An ICMP error message MUST NOT be sent as the result of receiving: ... a datagram whose source address does not define a single host -- e.g., a zero address, a loopback address, a broadcast address, a multicast address, or a Class E address.

RFC 9293 §3.9.2.3:

> An incoming SYN with an invalid source address MUST be ignored either by TCP or by the IP layer [(MUST-63)]

## Reproduction

Scratch test in the `stack.rs` test module, default features. Sketch as run by the verifier:

```rust
let (mut stack, rx, tx) = test_stack(Medium::Ip);
stack.routes_mut().add_default_ipv4_route(Ipv4Addr::new(192,168,1,254), IfaceHandle::new(0)).unwrap();
let udp = stack.add_udp_socket().unwrap();
stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
let lo = Ipv4Addr::new(127,0,0,1);
inject(... ipv4_packet(lo, OUR_V4, Udp, udp_datagram(lo, 4000, OUR_V4, 5555)));
// then: UDP to a closed port from 127.0.0.1 and from 240.0.0.1,
// an echo request from 127.0.0.1, and a SYN from 127.0.0.1 to a listener on 1234
```

`cargo test --lib zz_martian_src -- --nocapture`:

```
udp from 127.0.0.1 delivered: true
sent 192.168.1.1 -> 127.0.0.1 proto Icmp icmp type 3
sent 192.168.1.1 -> 240.0.0.1 proto Icmp icmp type 3
echo: sent 192.168.1.1 -> 127.0.0.1 icmp type 0
listener can_accept after SYN from 127.0.0.1: true
```

## Suggested fix

In `process_ipv4`, drop packets whose source is in 127.0.0.0/8 or 240.0.0.0/4. Consider also 0.0.0.0/8 with a non-zero host part and our own addresses. Use the same check in `transmit_icmpv4_error` and the echo reply path, or build it into the predicate they share.
