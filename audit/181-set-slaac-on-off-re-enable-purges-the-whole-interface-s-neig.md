# 181. set_slaac purges the whole interface's neighbor cache and parked packets, IPv4 included

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/slaac.rs:609](../src/iface/slaac.rs#L609), [src/stack.rs:143](../src/stack.rs#L143) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`slaac_reset` calls `purge_iface_link_state` whenever it removed a SLAAC address. That clears every neighbor entry and parked packet on the interface, IPv4 ARP included. `set_slaac` always calls `slaac_reset` first, so re-enabling SLAAC (documented as "restarts it") silently drops UDP datagrams whose send already returned `Ok`. This contradicts DESIGN §7.

## Details
src/iface/slaac.rs:604-609:
```rust
pub(crate) fn slaac_reset(&mut self, inner: &mut StackInner) {
    if self.slaac.take().is_none() { return; }
    if self.remove_ip_addrs(AddrOrigin::Slaac) {
        inner.purge_iface_link_state(self.handle);
    }
```
`purge_iface_link_state` runs `neighbor_cache.clear_iface` and `pending.purge_iface`, which drops every packet on the interface whatever its IP version. The prefix-expiry path in `sync_slaac_state` (line 467) removes SLAAC addresses with no purge at all, so the two paths disagree. The same whole-interface purge is used by `set_ip_addrs` and the DHCP address-change path (src/iface/dhcpv4.rs:865). This finding is one instance of that pattern. No ICMP error reaches the socket.

## Failure scenario
The app re-applies its config with `set_slaac(Some(default))` while an IPv4 UDP datagram is parked on ARP. The datagram is dropped. Every neighbor has to be re-resolved.

## Reproduction
In the `src/stack.rs` test module of a scratch copy:
```rust
#[test]
#[cfg(feature = "slaac")]
fn vv_set_slaac_purges_ipv4_pending() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    let router_ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
    let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    stack.poll(Instant::from_secs(1));
    rx.borrow_mut().push_back(router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix, Duration::from_secs(7200), Duration::from_secs(3600)));
    stack.poll(Instant::from_secs(2));
    assert!(stack.iface(iface).ip_addrs().iter().any(|a| a.origin == AddrOrigin::Slaac));
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
    assert!(stack.inner.pending.next_on(iface, 0).is_some(), "parked before");
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    assert!(stack.inner.pending.next_on(iface, 0).is_some(), "IPv4 datagram parked on ARP was dropped by set_slaac");
}
```
Output of `cargo test --lib vv_`: `panicked at src/stack.rs:3273:9: IPv4 datagram parked on ARP was dropped by set_slaac`.

## Suggested fix
Purge only parked packets whose source is a removed SLAAC address, or don't purge, like the expiry path. Document on `set_slaac` what re-enabling does.
