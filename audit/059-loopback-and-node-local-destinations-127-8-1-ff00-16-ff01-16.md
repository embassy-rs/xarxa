# 059. Loopback and node-local destinations (127/8, ::1, ff00::/16, ff01::/16) are sent onto the wire

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:346](../src/stack.rs#L346), [src/udp.rs:875](../src/udp.rs#L875), [src/tcp/mod.rs:2552](../src/tcp/mod.rs#L2552), [src/raw.rs:596](../src/raw.rs#L596) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`TxContext::route` has no check for destinations that must never leave the host. 127.0.0.1 is unicast, so with a default route, UDP datagrams and TCP SYNs to it go to the gateway. Interface-local (ff01::/16) and reserved scope 0 (ff00::/16) multicast go out the first interface. Raw IPv6 packets to ::1 are routed out too.

## Details

src/stack.rs:350-373:

```rust
if !dst_addr.is_unicast() {
    ...
    return candidates.next().map(|(_, iface)| EgressRoute { ... });
}

if let Some((_, iface)) = candidates.find(|(_, iface)| iface.in_same_network(dst_addr)) {
    ...
}

let route = self.inner.routes.lookup(binding, dst_addr, self.inner.now)?;
```

A default route 0.0.0.0/0 or ::/0 matches 127.0.0.1 and ::1. Multicast of any scope takes the first branch.

The callers check nothing either:

- UDP (src/udp.rs:875) routes, picks a source such as 192.168.1.1, passes the weak-host check, and transmits.
- TCP `connect` (src/tcp/mod.rs:2552) only rejects port 0 and the unspecified address.
- Raw IP (src/raw.rs:596) only rejects the unspecified address.

UDP to ::1 happens to fail with `Unaddressable`, because the source selected is ::1, which is not assigned. Raw sockets are documented to send any packet verbatim, so the raw case is arguably the user's choice. The UDP and TCP 127/8 cases and the UDP multicast cases are the substantive ones.

## Failure scenario

Firmware ported from desktop code sends syslog to 127.0.0.1:514 while a DHCP default route exists. Every datagram goes to the LAN gateway with destination 127.0.0.1, and the send returns `Ok` instead of an error.

## RFC reference

RFC 1122 §3.2.1.3 (g):

> { 127, <any> } Internal host loopback address. Addresses of this form MUST NOT appear outside a host.

RFC 4291 §2.5.3:

> An IPv6 packet with a destination address of loopback must never be sent outside of a single node

RFC 4291 §2.7:

> Nodes must not originate a packet to a multicast address whose scop field contains the reserved value 0

> Interface-Local scope spans only a single interface on a node and is useful only for loopback transmission of multicast.

## Reproduction

Test in the `stack.rs` `mod test` harness, default features:

```rust
#[test]
fn vv_loopback_to_wire() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let h = stack.ifaces().next().map(|(h, _)| h).unwrap();
    stack.routes_mut().add_default_ipv4_route(Ipv4Addr::new(192, 168, 1, 254), h).unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(0u16, 0u16).ok();
    let r = stack.udp_socket(udp).send_slice(b"x", SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 53));
    println!("udp send to 127.0.0.1 -> {:?}, tx={}", r, tx.borrow().len());
    for f in tx.borrow().iter() { println!("frame {:02x?}", &f[..20]); }
    tx.borrow_mut().clear();
    let r = stack.udp_socket(udp).send_slice(b"x", SocketAddr::new(Ipv6Addr::new(0xff01,0,0,0,0,0,0,1).into(), 53));
    println!("udp send to ff01::1 -> {:?}, tx={}", r, tx.borrow().len());
    tx.borrow_mut().clear();
    let r = stack.udp_socket(udp).send_slice(b"x", SocketAddr::new(Ipv6Addr::new(0xff00,0,0,0,0,0,0,1).into(), 53));
    println!("udp send to ff00::1 -> {:?}, tx={}", r, tx.borrow().len());
    tx.borrow_mut().clear();
    let t = stack.add_tcp_socket(1024, 1024).unwrap();
    let r = stack.tcp_socket(t).connect(SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80), 0u16);
    stack.poll(Instant::ZERO);
    println!("tcp connect 127.0.0.1 -> {:?}, tx={}", r, tx.borrow().len());
    for f in tx.borrow().iter() { println!("frame {:02x?}", &f[..20]); }
    tx.borrow_mut().clear();
    let raw = stack.add_raw_socket().unwrap();
    stack.raw_socket(raw).bind(RawMode::Ip { version: None, protocol: None }).unwrap();
    stack.routes_mut().add_default_ipv6_route(Ipv6Addr::new(0xfdaa,0,0,0,0,0,0,0xfe), h).unwrap();
    let p = ipv6_packet(OUR_V6, Ipv6Addr::LOCALHOST, IpProtocol(99), b"abcd");
    let r = stack.raw_socket(raw).send_slice(&p);
    println!("raw send to ::1 -> {:?}, tx={}", r, tx.borrow().len());
}
```

`cargo test --lib vv_ -- --nocapture --test-threads=1`:

```
udp send to 127.0.0.1 -> Ok(()), tx=1
frame [45, 00, 00, 1d, 00, 00, 40, 00, 40, 11, fa, 25, c0, a8, 01, 01, 7f, 00, 00, 01]
udp send to ff01::1 -> Ok(()), tx=1
udp send to ff00::1 -> Ok(()), tx=1
tcp connect 127.0.0.1 -> Ok(()), tx=1
frame [45, 00, 00, 3c, 00, 00, 40, 00, 40, 06, fa, 11, c0, a8, 01, 01, 7f, 00, 00, 01]
raw send to ::1 -> Ok(()), tx=1
```

## Suggested fix

In `route()`, return `None` (so callers report `Unaddressable`) for 127.0.0.0/8, ::1, and multicast of scope 0 or 1, as long as there is no loopback delivery.
