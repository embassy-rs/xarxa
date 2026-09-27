# 037. IPv6 source selection falls back to ::1 when the interface has no IPv6 address

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/mod.rs:1067](../src/iface/mod.rs#L1067), [src/iface/mod.rs:866](../src/iface/mod.rs#L866), [src/tcp/mod.rs:2570](../src/tcp/mod.rs#L2570), [src/tcp/mod.rs:1887](../src/tcp/mod.rs#L1887), [src/udp.rs:555](../src/udp.rs#L555), [src/stack.rs:1829](../src/stack.rs#L1829), [src/stack.rs:2109](../src/stack.rs#L2109), [src/stack.rs:2559](../src/stack.rs#L2559) |
| Features | default (`ipv6`) |
| Verification | reproduced with a test |

## Summary

`get_source_address_ipv6` returns `Ipv6Addr::LOCALHOST` when the interface has no IPv6 address, and `get_source_address` wraps it in `Some`. So TCP `connect` returns `Ok` with local address `::1` instead of the documented `Unaddressable`, and the socket then sits in SYN-SENT forever without sending anything. Echo replies to multicast, ICMPv6 errors about non-unicast destinations, and neighbor solicitations can go on the wire with source `::1`.

## Details

src/iface/mod.rs:1063:

```rust
if dst_addr.is_loopback() {
    return Ipv6Addr::LOCALHOST;
}
let Some((mut candidate, mut candidate_cidr)) = self.ip_addrs.iter().find_map(ipv6_candidate) else {
    return Ipv6Addr::LOCALHOST;
};
```

src/iface/mod.rs:866, no caller can tell there was no candidate:

```rust
IpAddr::V6(addr) => Some(IpAddr::V6(self.get_source_address_ipv6(addr, now))),
```

The IPv4 path returns `None` in the same situation.

Callers:
- `TcpSocket::connect` (src/tcp/mod.rs:2570) takes `::1` as the local address. Its doc lists `Unaddressable` for "the interface the route goes out of has no address to send from". Every `dispatch` then fails `cx.has_ip_addr(tuple.local.addr)` (src/tcp/mod.rs:1887) and drops the segment. The default timeout is `None`, so the socket never errors.
- `UdpSocket::bind` with a concrete remote (src/udp.rs:555) stores `::1` as the local address and returns `Ok`. Later sends fail with `Unaddressable` at the `has_ip_addr` check (src/udp.rs:895), so UDP fails loudly at send time.
- Echo reply to a non-unicast destination (src/stack.rs:1829) and ICMPv6 errors about a non-unicast destination (src/stack.rs:2109) use the value as the source.
- `transmit_ndisc_solicit` (src/stack.rs:2559) uses it as the NS source. Reachable on an Ethernet or 802.15.4 interface with no IPv6 address (link-local removed with `set_ip_addrs`, or 802.15.4 with a short address) that still gets IPv6 egress through a manual route, a raw-IP send or a reply.

Minor: the first candidate is not passed through `is_candidate_source_address`, so an interface with only a global address answers a link-local destination from the global address.

## Failure scenario

Dual-stack build. An IP-medium uplink has only 192.168.1.1/24. The user adds a default IPv6 route via fe80::1 on it. `tcp.connect([2001:db8::2]:80)` returns `Ok` with local `[::1]:61620`. No SYN is ever sent and the application waits forever.

On the same interface, a peer pings ff02::1 from fe80::2. The reply goes out from `::1`.

## RFC reference

RFC 4291 §2.5.3:

> The loopback address must not be used as the source address in IPv6 packets that are sent outside of a single node.

## Reproduction

Tests in the src/stack.rs test harness, scratch copy of HEAD:

```rust
#[test]
fn vfy_f4_tcp_connect_localhost() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let iface = IfaceHandle::new(0);
    stack.iface(iface).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    stack.routes_mut().add_default_ipv6_route(Ipv6Addr::new(0xfe80,0,0,0,0,0,0,1), iface).unwrap();
    tx.borrow_mut().clear();
    let h = stack.add_tcp_socket(1024, 1024).unwrap();
    let r = stack.tcp_socket(h).connect((Ipv6Addr::new(0x2001,0xdb8,0,0,0,0,0,2), 80), 0);
    println!("F4 connect = {:?} local={:?}", r, stack.tcp_socket(h).local_addr());
    for s in 0..10 { stack.poll(Instant::from_secs(s)); }
    println!("F4 sent {}", tx.borrow().len());
    assert!(r.is_err());
}

#[test]
fn vfy_f4_echo_multicast_src() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    stack.iface(IfaceHandle::new(0)).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    tx.borrow_mut().clear();
    let src = Ipv6Addr::new(0xfe80,0,0,0,0,0,0,2); let dst = Ipv6Addr::new(0xff02,0,0,0,0,0,0,1);
    let echo = icmpv6_echo(Icmpv6Message::EchoRequest, 1, 1, b"x", src, dst);
    inject(&mut stack, &rx, ipv6_packet(src, dst, IpProtocol::Icmpv6, &echo));
    for p in tx.borrow().iter() { let mut pc = p.clone(); let ip = Ipv6Packet::new_unchecked(&mut pc[..]); assert_ne!(ip.src_addr(), Ipv6Addr::LOCALHOST); }
}
```

Output:

```
F4 connect = Ok(()) local=Some(SocketAddr { addr: V6(::1), port: 61620 })
F4 sent 0
F4 echo out: ::1 -> fe80::2 (assertion left != right failed: ::1)
```

## Suggested fix

Make `get_source_address_ipv6` return `Option<Ipv6Addr>`, with `None` when there is no candidate (keep `::1` for a loopback destination). Callers then return `Unaddressable` from `connect`/`bind`, drop the reply or error, and skip the NS.
