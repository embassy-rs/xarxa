# 069. IPv6 ingress accepts ::1 as destination and source from any link, and replies from ::1 on the wire; IPv4 accepts 127/8 sources

| | |
|---|---|
| Severity | medium |
| Category | security |
| Location | [src/stack.rs:1699](../src/stack.rs#L1699), [src/stack.rs:1689](../src/stack.rs#L1689), [src/stack.rs:1388](../src/stack.rs#L1388), [src/stack.rs:1829](../src/stack.rs#L1829), [src/stack.rs:2109](../src/stack.rs#L2109), [src/iface/mod.rs:1063](../src/iface/mod.rs#L1063) |
| Features | default |
| Verification | reproduced with a test |

## Summary

The IPv6 destination check explicitly accepts `::1` on every interface, and the source check accepts `::1` as a source. xarxa has no loopback medium, so every such packet came off a link. The stack delivers them to sockets and answers them with source `::1` on the wire. On IPv4, a 127.0.0.1 destination is rejected, but a 127/8 source is accepted and delivered. Applications that trust "localhost" traffic can be fooled by any on-link host.

## Details

src/stack.rs:1697-1703:
```rust
if !iface.has_ip_addr(dst_addr.into())
    && !iface.has_multicast_group(dst_addr.into())
    && !dst_addr.is_loopback()
{
    trace!("Rejecting IPv6 packet; not for us");
    return;
}
```

src/stack.rs:1689. `x_is_unicast` is `!(multicast || unspecified)`, so `::1` passes:
```rust
if !src_addr.x_is_unicast() {
```

Replies use `::1` as source:
- src/stack.rs:1829, echo reply: `let reply_src = if dst_addr.x_is_unicast() { dst_addr } else { ... }`.
- src/stack.rs:2109, `transmit_icmpv6_error`, same pattern.
- src/iface/mod.rs:1063, `get_source_address_ipv6` returns `Ipv6Addr::LOCALHOST` for a loopback destination.

Nothing on egress checks the source.

src/stack.rs:1388, IPv4. `is_unicast_v4` does not exclude 127/8:
```rust
if !iface.is_unicast_v4(src_addr) && !src_addr.is_unspecified() {
```

If a user assigns `::1` to an interface (the code special-cases `LOCALHOST` in iface/mod.rs), a socket bound to `[::1]:port` is also reachable from the network, and its replies pass the weak-host source check.

## Failure scenario

- An on-link attacker sends UDP src `::1`, dst our address, port 7. A wildcard socket receives it with `remote_addr [::1]:4000`.
- UDP to `[::1]:7` from the link is delivered with `local_addr ::1`.
- An echo request to `::1` gets a reply with source `::1` transmitted on the interface.
- UDP from 127.0.0.1 to our IPv4 address is delivered with `remote_addr 127.0.0.1:4000`.

## RFC reference

RFC 4291 §2.5.3 (lowercase "must", but unambiguous):
> The loopback address must not be used as the source address in IPv6 packets that are sent outside of a single node. An IPv6 packet with a destination address of loopback must never be sent outside of a single node and must never be forwarded by an IPv6 router. A packet received on an interface with a destination address of loopback must be dropped.

RFC 1122 §3.2.1.3:
> (g) { 127, <any> } Internal host loopback address. Addresses of this form MUST NOT appear outside a host.

> A host MUST silently discard an incoming datagram containing an IP source address that is invalid by the rules of this section.

## Reproduction

Test in the `src/stack.rs` test module of a scratch copy:

```rust
#[test]
fn vv_loopback_v6() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let lo = Ipv6Addr::LOCALHOST;
    let req = icmpv6_echo(Icmpv6Message::EchoRequest, 1, 1, b"hi", REMOTE_V6, lo);
    inject(&mut stack, &rx, ipv6_packet(REMOTE_V6, lo, IpProtocol::Icmpv6, &req));
    assert_eq!(tx.borrow().len(), 1);
    { let mut b = tx.borrow()[0].clone(); let ip = Ipv6Packet::new_checked(&mut b[..]).unwrap();
      std::println!("echo reply src={} dst={}", ip.src_addr(), ip.dst_addr()); assert_eq!(ip.src_addr(), lo); }
    let handle = stack.add_udp_socket().unwrap();
    stack.udp_socket(handle).bind(7, ListenSocketAddr::UNSPECIFIED).unwrap();
    inject(&mut stack, &rx, ipv6_packet(lo, OUR_V6, IpProtocol::Udp, &udp_datagram(lo.into(), 4000, OUR_V6.into(), 7, b"a")));
    let mut buf = [0u8; 16];
    let (_, meta) = stack.udp_socket(handle).recv_slice(&mut buf).unwrap();
    std::println!("udp from ::1 delivered: {:?}", meta);
    inject(&mut stack, &rx, ipv6_packet(REMOTE_V6, lo, IpProtocol::Udp, &udp_datagram(REMOTE_V6.into(), 4000, lo.into(), 7, b"b")));
    let (_, meta) = stack.udp_socket(handle).recv_slice(&mut buf).unwrap();
    std::println!("udp to ::1 delivered: {:?}", meta);
    let l4 = Ipv4Addr::new(127, 0, 0, 1);
    inject(&mut stack, &rx, ipv4_packet(l4, OUR_V4, IpProtocol::Udp, &udp_datagram(l4.into(), 4000, OUR_V4.into(), 7, b"c")));
    std::println!("udp from 127.0.0.1: {:?}", stack.udp_socket(handle).recv_slice(&mut buf));
    inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, l4, IpProtocol::Udp, &udp_datagram(REMOTE_V4.into(), 4000, l4.into(), 7, b"d")));
    std::println!("udp to 127.0.0.1: {:?}", stack.udp_socket(handle).recv_slice(&mut buf));
}
```

Output:
```
echo reply src=::1 dst=fdaa::2
udp from ::1 delivered: UdpMetadata { remote_addr: SocketAddr { addr: V6(::1), port: 4000 }, local_addr: Some(V6(fdaa::1)), .. }
udp to ::1 delivered: UdpMetadata { remote_addr: SocketAddr { addr: V6(fdaa::2), port: 4000 }, local_addr: Some(V6(::1)), .. }
udp from 127.0.0.1: Ok((1, UdpMetadata { remote_addr: SocketAddr { addr: V4(127.0.0.1), port: 4000 }, local_addr: Some(V4(192.168.1.1)), .. }))
udp to 127.0.0.1: Err(Exhausted)
```

One report also claims that `send_slice` to 127.0.0.1 with a default route goes out to the gateway. That was not verified.

## Suggested fix

- Remove the `!dst_addr.is_loopback()` exception at src/stack.rs:1699.
- Drop IPv6 packets with source `::1` at src/stack.rs:1689.
- Drop IPv4 packets with a 127/8 source at src/stack.rs:1388.
