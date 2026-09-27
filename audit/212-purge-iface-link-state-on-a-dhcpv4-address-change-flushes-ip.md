# 212. purge_iface_link_state on an IPv4 address change flushes IPv6 neighbors and parked packets

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:143](../src/stack.rs#L143), [src/iface/dhcpv4.rs:853](../src/iface/dhcpv4.rs#L853), [src/iface/mod.rs:457](../src/iface/mod.rs#L457), [src/iface/slaac.rs:608](../src/iface/slaac.rs#L608) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`purge_iface_link_state` clears every neighbor entry and every parked packet of an interface, with no address-family filter. It runs on any address change, including the first DHCPv4 bind (None to Some). Parked IPv6 packets are dropped with no ICMP error, after their send returned Ok.

## Details
src/stack.rs:148
```rust
self.neighbor_cache.clear_iface(handle);
self.pending.purge_iface(handle);
```
Callers: `dhcpv4_apply` when `old_addr != new_addr` (src/iface/dhcpv4.rs:853-865), SLAAC reset (src/iface/slaac.rs:608), and the `Iface` address setters through `invalidate()` (src/iface/mod.rs:457). smoltcp also flushes on address changes, so this looks inherited.

## Failure scenario
A dual-stack device boots. An IPv6 UDP datagram to a link-local peer is parked on NDISC. The DHCPv4 ACK arrives in the same second. The datagram is discarded and the IPv6 neighbor cache is wiped, though nothing changed for IPv6.

## Reproduction
Test in the `stack` module test harness. It uses `set_ip_addrs` for an IPv4-only change, the same purge path as `dhcpv4_apply`. The DHCP first-bind case was confirmed by reading the code.
```rust
#[test]
fn vtest_f1_dhcp_style_purge_drops_v6_parked() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    let u = stack.add_udp_socket().unwrap();
    stack.udp_socket(u).bind(5000, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(u).send_slice(b"x", (REMOTE_V6, 5000)).unwrap();
    println!("F1 parked before: {}", stack.inner.pending.next_on(IfaceHandle::new(0), 0).is_some());
    stack.iface(IfaceHandle::new(0)).set_ip_addrs([IpCidr::new(Ipv4Addr::new(192,168,1,7).into(), 24), IpCidr::new(OUR_V6.into(), 64)]).unwrap();
    println!("F1 parked after: {}", stack.inner.pending.next_on(IfaceHandle::new(0), 0).is_some());
}
```
Output: `F1 parked before: true`, `F1 parked after: false`.

## Suggested fix
Purge only the affected address family, or only entries whose source address was removed. Or purge only on real network changes (a removed address, a hardware address change).
