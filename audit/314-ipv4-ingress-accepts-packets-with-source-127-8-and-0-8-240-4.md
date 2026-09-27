# 314. IPv4 ingress accepts packets with source 127/8 (and 0/8, 240/4) from the wire

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/ipv4.rs:64](../src/wire/ipv4.rs#L64), [src/iface/mod.rs:902](../src/iface/mod.rs#L902), [src/stack.rs:1388](../src/stack.rs#L1388) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`x_is_unicast` counts 127/8, 0/8 (other than 0.0.0.0) and 240/4 as unicast. `IfaceState::is_unicast_v4` builds on it and is the only source check in `process_ipv4`. So packets from the wire with these sources are processed, and replies to them go out with a 127/8 destination. RFC 1122 requires silently discarding them.

## Details
src/wire/ipv4.rs:64:
```rust
fn x_is_unicast(&self) -> bool {
    !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
}
```
src/iface/mod.rs:902:
```rust
pub(crate) fn is_unicast_v4(&self, address: Ipv4Addr) -> bool {
    address.x_is_unicast() && !self.is_broadcast_v4(address)
}
```
src/stack.rs:1388:
```rust
if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
```

## Failure scenario
A LAN peer sends an ICMP echo request from 127.0.0.1 to one of our addresses. The stack answers with an echo reply to 127.0.0.1, routed through the default gateway. UDP datagrams from 127.0.0.1 are delivered to sockets, so an application that trusts 127.0.0.1 as local can be fooled.

## RFC reference
RFC 1122 §3.2.1.3 (g): "{ 127, <any> } Internal host loopback address. Addresses of this form MUST NOT appear outside a host."

RFC 1122 §3.2.1.3: "A host MUST silently discard an incoming datagram containing an IP source address that is invalid by the rules of this section."

(b) covers { 0, <Host-number> }: "MUST NOT be sent, except as a source address as part of an initialization procedure".

## Reproduction
Added to the test module of src/stack.rs:
```rust
#[test]
fn zz_loopback_src_echo() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    stack.routes_mut().add(crate::route::Route::new_ipv4_gateway(Ipv4Addr::new(192, 168, 1, 254), IfaceHandle::new(0))).unwrap();
    let lo = Ipv4Addr::new(127, 0, 0, 1);
    let request = icmpv4_echo(Icmpv4Message::EchoRequest, 0x1234, 7, b"hi");
    inject(&mut stack, &rx, ipv4_packet(lo, OUR_V4, IpProtocol::Icmp, &request));
    let tx = tx.borrow();
    assert_eq!(tx.len(), 1);
    let (msg_type, _, _) = parse_icmpv4_reply(&tx[0], OUR_V4, lo);
    assert_eq!(msg_type, Icmpv4Message::EchoReply);
}
```
`cargo test --lib zz_` passes: the echo reply to 127.0.0.1 is transmitted.

Related, not part of this finding: src/stack.rs accepts IPv6 packets from the wire with destination ::1 (`&& !dst_addr.is_loopback()`).

## Suggested fix
Reject 127/8 sources in the `process_ipv4` source check, and optionally 0/8 (other than 0.0.0.0) and 240/4. Use a dedicated helper rather than changing `x_is_unicast`, which `add_ip_addr` also relies on.
