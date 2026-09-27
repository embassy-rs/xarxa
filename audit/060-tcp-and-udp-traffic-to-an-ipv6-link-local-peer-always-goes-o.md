# 060. TCP and UDP traffic to an IPv6 link-local peer always goes out the first interface

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/stack.rs:364](../src/stack.rs#L364), [src/stack.rs:398](../src/stack.rs#L398), [src/tcp/listener.rs:209](../src/tcp/listener.rs#L209), [src/tcp/mod.rs:1888](../src/tcp/mod.rs#L1888), [src/udp.rs:43](../src/udp.rs#L43), [src/udp.rs:875](../src/udp.rs#L875), [src/raw.rs:601](../src/raw.rs#L601) |
| Features | default (ipv6; only multi-interface stacks) |
| Verification | reproduced with a test |

## Summary

`TxContext::route` picks the first interface with an on-link prefix for the destination. Every Ethernet and 802.15.4 interface gets an fe80::/64 address at `add_iface`, so any unbound socket sending to fe80::x uses the first interface. `route_reply` handles this for stack-generated replies, but socket egress does not. An accepted TCP connection or a UDP reply to a link-local peer on another interface leaves on the wrong link, and fails.

## Details

src/stack.rs:364:

```rust
if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
```

`in_same_network` (src/iface/mod.rs:811) is a plain prefix match. `add_iface_inner` (src/stack.rs:660-664) gives every link-layer interface its `link_local_addr`, so the first interface in slab order always matches.

`route_reply` (src/stack.rs:398-414) already treats the arrival interface as the zone for ICMP replies and RSTs:

```rust
if let IpAddr::V6(dst) = dst_addr
    && dst.is_link_local()
{
    return Some(EgressRoute {
        iface: arrival,
        ...
```

Socket paths have no arrival interface to use:

- `AcceptToken` (src/tcp/listener.rs:209-212) holds the SYN and the listener's `IfaceBinding`. For an unbound listener that is `Any`. The accepted socket routes its SYN|ACK with `cx.route(self.binding, &tuple.remote.addr)` (src/tcp/mod.rs:1888).
- `UdpMetadata` (src/udp.rs:43-57) has no interface field. `send_slice(reply, meta.remote_addr)` routes with `self.tx.route(binding, ...)` (src/udp.rs:875).
- Raw IP-mode sends route the same way (src/raw.rs:601).

DESIGN.md §6 and §11 list only broadcast and multicast as going out the first interface. Link-local unicast is not mentioned.

With `iface-bind`, one socket per interface works around it. Without that feature there is no workaround. The same applies to 169.254/16 only if the user assigns such addresses on several interfaces, since the stack does not auto-assign them.

## Failure scenario

A border router has iface0 = Ethernet and iface1 = 802.15.4, with an unbound TCP listener on port 80 and a UDP server on 5683. A node on iface1 connects to our fe80:: address, or sends a CoAP request from fe80::abcd.

- The SYN is recorded and accepted. The SYN|ACK is routed out iface0.
- The UDP reply sent with `meta.remote_addr` is routed out iface0.

On Ethernet an NS for fe80::abcd goes out the wrong link and is not answered. After about 3 s resolution fails and a local ICMP unreachable aborts the SYN-RECEIVED connection, or lands on the UDP socket as `HostUnreachable`. On IP medium the packet is simply delivered on the wrong link. Either way the peer never gets an answer.

## RFC reference

RFC 4007 §7:

> When an upper-layer protocol sends a packet to a non-global destination address, it must have a means of identifying the intended zone to the IPv6 layer for cases in which the node is attached to more than one zone of the destination address's scope.

RFC 4007 §8:

> the zone to which that address pertains can be determined from the arrival interface ... it is recommended that the IP layer convey to the upper layer the correct zone indices for the arriving source and destination addresses, in addition to the arrival interface identifier.

## Reproduction

Test in the `stack.rs` `mod test` harness, default features, using `test_stack_two_ifaces()` (two IP-medium interfaces, both owning fe80::1/64):

```rust
#[test]
fn vv_link_local_multi_iface() {
    let (mut stack, rx, tx) = test_stack_two_ifaces();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5683u16, 0u16).unwrap();
    let d = udp_datagram(LINK_LOCAL_REMOTE_V6.into(), 1000, LINK_LOCAL_V6.into(), 5683, b"req");
    inject(&mut stack, &rx[1], ipv6_packet(LINK_LOCAL_REMOTE_V6, LINK_LOCAL_V6, IpProtocol::Udp, &d));
    tx[0].borrow_mut().clear(); tx[1].borrow_mut().clear();
    let meta = stack.udp_socket(udp).recv().unwrap().meta();
    let r = stack.udp_socket(udp).send_slice(b"reply", meta.remote_addr);
    println!("udp reply {:?}: tx0={} tx1={}", r, tx[0].borrow().len(), tx[1].borrow().len());
    tx[0].borrow_mut().clear(); tx[1].borrow_mut().clear();
    let listener = stack.add_tcp_listener().unwrap();
    stack.tcp_listener(listener).listen(80).unwrap();
    let seg = tcp_segment(LINK_LOCAL_REMOTE_V6.into(), 40000, LINK_LOCAL_V6.into(), 80, true);
    inject(&mut stack, &rx[1], ipv6_packet(LINK_LOCAL_REMOTE_V6, LINK_LOCAL_V6, IpProtocol::Tcp, &seg));
    let tok = stack.tcp_listener(listener).accept().unwrap();
    let t = stack.add_tcp_socket(1024, 1024).unwrap();
    stack.tcp_socket(t).accept(tok).unwrap();
    stack.poll(Instant::ZERO);
    println!("synack: tx0={} tx1={}", tx[0].borrow().len(), tx[1].borrow().len());
}
```

Output:

```
udp reply Ok(()): tx0=1 tx1=0
synack: tx0=1 tx1=0
```

## Suggested fix

- Record the arrival interface in `PendingSyn`/`AcceptToken`. When the accepted connection's remote address is link-local, use it as the socket's egress interface.
- Add the arrival interface to `UdpMetadata` for incoming datagrams, and honor it on send when the destination is link-local, as `route_reply` does.
- At minimum, document that link-local peers on a non-first interface need `bind_to_iface`.
