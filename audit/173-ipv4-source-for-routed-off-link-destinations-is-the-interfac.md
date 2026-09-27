# 173. IPv4 source for routed (off-link) destinations is the interface's first IPv4 address, not the one on the gateway's subnet

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/mod.rs:840](../src/iface/mod.rs#L840), [src/stack.rs:299](../src/stack.rs#L299), [src/stack.rs:309](../src/stack.rs#L309) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`get_source_address_ipv4(dst)` returns the address whose subnet contains `dst`, else the first IPv4 address. The route's next hop is never considered. So off-link destinations always get the first address, even when the gateway is on another subnet of the same interface. Replies can't come back. Both UDP and TCP are affected.

## Details
src/stack.rs:299-304 (and `get_source_address_routed` at 309-313):
```rust
let route = self.route(binding, dst_addr)?;
self.ifaces
    .get(route.iface.index())
    .get_source_address(dst_addr, self.inner.now)
```
`route.next_hop` is ignored. `get_source_address_ipv4` (src/iface/mod.rs:840) falls back to `first_ipv4`. Linux picks the address on the gateway's subnet (`inet_select_addr(dev, gw, scope)`).

## Failure scenario
The interface has 169.254.10.20/16 (added first) and 192.168.1.50/24 with a default route via 192.168.1.1. UDP to 8.8.8.8 goes out via 192.168.1.1 with source 169.254.10.20. Whether a DHCP lease hits this depends on the order the addresses were added.

## Reproduction
`stack` module test harness, scratch copy:
```rust
#[test]
fn vfy_f1_offlink_source() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let iface = IfaceHandle::new(0);
    stack.iface(iface).set_ip_addrs([
        IpCidr::new(Ipv4Addr::new(169, 254, 10, 20).into(), 16),
        IpCidr::new(Ipv4Addr::new(192, 168, 1, 50).into(), 24),
    ]).unwrap();
    stack.routes_mut().add_default_ipv4_route(Ipv4Addr::new(192, 168, 1, 1), iface).unwrap();
    tx.borrow_mut().clear();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp).send_slice(b"hi", (Ipv4Addr::new(8, 8, 8, 8), 53)).unwrap();
    let t = tx.borrow();
    let mut last = t[t.len() - 1].clone();
    let ip = Ipv4Packet::new_unchecked(&mut last[..]);
    assert_eq!(ip.src_addr(), Ipv4Addr::new(192, 168, 1, 50));
}
```
Output: `assertion 'left == right' failed left: 169.254.10.20 right: 192.168.1.50`

## Suggested fix
For off-link IPv4 destinations (next_hop != dst), select the source with `get_source_address_ipv4(&next_hop)`.
