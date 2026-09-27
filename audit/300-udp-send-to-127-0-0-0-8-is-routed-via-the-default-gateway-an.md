# 300. UDP send to 127.0.0.0/8 goes out via the default gateway, and 127/8 sources are accepted on ingress

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/udp.rs:876](../src/udp.rs#L876), [src/wire/ipv4.rs:64](../src/wire/ipv4.rs#L64), [src/stack.rs:1388](../src/stack.rs#L1388) |
| Features | default |
| Verification | reproduced with a test |

## Summary
IPv4 loopback counts as unicast, so egress routes 127.0.0.1 through the default route and puts it on the wire with our real source address. The send returns `Ok`. On ingress, `process_ipv4` accepts a 127/8 source for every IPv4 protocol and delivers it. Both break RFC 1122 §3.2.1.3.

## Details
src/wire/ipv4.rs:64: `x_is_unicast` is `!(broadcast || multicast || unspecified)`, so 127.0.0.1 is unicast. `TxContext::route` finds no on-link interface and falls through to the default route. src/udp.rs:873-876 has no loopback check:
```rust
.ok_or(SendError::Unaddressable)?;
```
src/stack.rs:1388:
```rust
if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
```
Nothing rejects 127/8. TCP egress probably leaks the same way through `TxContext::route` (not tested). IPv6 `::1` fails only because the fallback source `::1` isn't assigned.

## Failure scenario
Code ported from a hosted system sends to 127.0.0.1:514. The datagram goes to the default gateway and the app sees success.

## RFC reference
RFC 1122 §3.2.1.3 (g): "{ 127, <any> } Internal host loopback address.  Addresses of this form MUST NOT appear outside a host."

RFC 1122 §3.2.1.3: "A host MUST silently discard an incoming datagram containing an IP source address that is invalid by the rules of this section."

## Reproduction
`udp.rs` test harness, scratch copy:
```rust
#[test] fn vfy_udp5_loopback_dst() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    stack.routes_mut().add(crate::route::Route::new_ipv4_gateway(Ipv4Addr::new(192,168,1,254), IfaceHandle::new(0))).unwrap();
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(1000, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(h).send_slice(b"hi", SocketAddr::new(Ipv4Addr::new(127,0,0,1).into(), 53));
    println!("send to 127.0.0.1: {:?}, frames {}", r, tx.borrow().len());
    // parse frame, print src/dst
    let lo = Ipv4Addr::new(127,0,0,1);
    let d = udp_datagram(lo.into(), 53, OUR_V4.into(), 1000, b"x");
    inject(&mut stack, &rx, ipv4_packet(lo, OUR_V4, IpProtocol::Udp, &d));
    println!("ingress 127 src delivered: {}", stack.udp_socket(h).can_recv());
}
```
Output:
```
send to 127.0.0.1: Ok(()), frames 1
src 192.168.1.1 dst 127.0.0.1
ingress 127 src delivered: true
```

## Suggested fix
Return `None` from `TxContext::route` for loopback destinations. Drop IPv4 ingress with a 127/8 source or destination in `process_ipv4`.
