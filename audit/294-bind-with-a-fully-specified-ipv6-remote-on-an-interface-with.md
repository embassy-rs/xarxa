# 294. bind() with a fully specified IPv6 remote and no IPv6 address binds the local address to ::1

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/udp.rs:555](../src/udp.rs#L555), [src/iface/mod.rs:866](../src/iface/mod.rs#L866), [src/iface/mod.rs:1066](../src/iface/mod.rs#L1066) |
| Features | `ipv6`, `udp` (default) |
| Verification | reproduced with a test |

## Summary
`get_source_address_ipv6` falls back to `::1` when the interface has no IPv6 address, so `Iface::get_source_address` always returns `Some` for IPv6. `bind()` stores `::1` as the connected socket's local address instead of returning `Unaddressable`. Every later send fails with `Unaddressable`, even after the interface gets an IPv6 address, until the application rebinds. IPv4 returns `None` and fails the bind correctly.

## Details
src/udp.rs:555:
```rust
self.tx
    .get_source_address(binding, &remote_addr)
    .ok_or(BindError::Unaddressable)?,
```
src/iface/mod.rs:866:
```rust
IpAddr::V6(addr) => Some(IpAddr::V6(self.get_source_address_ipv6(addr, now))),
```
src/iface/mod.rs:1066:
```rust
let Some((mut candidate, mut candidate_cidr)) = self.ip_addrs.iter().find_map(ipv6_candidate) else {
    return Ipv6Addr::LOCALHOST;
};
```
`prepare_datagram` then rejects `::1` with `if !self.tx.has_ip_addr(src_addr)` (src/udp.rs:895). Multicast destinations always route (first interface), so this is easy to hit. TCP connect picks its source the same way and may be affected too. That was not verified.

## Failure scenario
At boot, before SLAAC assigns an address, an app connects a UDP socket to ff02::fb:5353. `bind` succeeds. Every send fails with `Unaddressable` forever.

## Reproduction
Added to `src/stack.rs` `mod test`, run with `cargo test --lib vfy_ -- --nocapture`:
```rust
#[test]
fn vfy_udp6_bind_loopback_source() {
    let (mut stack, _rx, _tx) = test_stack(Medium::Ip);
    let ifh = IfaceHandle::new(0);
    stack.iface(ifh).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    let h = stack.add_udp_socket().unwrap();
    let grp = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
    let r = stack.udp_socket(h).bind(5353, SocketAddr::new(grp.into(), 5353));
    println!("bind: {:?} local {:?}", r, stack.udp_socket(h).local_addr());
    stack.iface(ifh).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24), IpCidr::new(OUR_V6.into(), 64)]).unwrap();
    println!("send after v6 addr: {:?}", stack.udp_socket(h).send_slice(b"hi", SocketAddr::UNSPECIFIED));
}
```
Output:
```
bind: Ok(()) local ListenSocketAddr { addr: Some(V6(::1)), port: 5353 }
send after v6 addr: Err(Unaddressable)
```

## Suggested fix
Make `get_source_address_ipv6` return `Option`, with `None` when there is no candidate, so `bind` returns `Unaddressable`.
