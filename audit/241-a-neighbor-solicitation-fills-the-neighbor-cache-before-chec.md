# 241. A neighbor solicitation fills the neighbor cache before checking that its target is ours

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/stack.rs:2259](../src/stack.rs#L2259), [src/stack.rs:2270](../src/stack.rs#L2270) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`process_ndisc_solicit` creates or overwrites the cache entry for the NS source from its SLLA option before it checks that the target is assigned to us. RFC 4861 §7.2.3 says such an NS MUST be silently discarded. One multicast NS to ff02::1, with any target and a spoofed source, poisons every xarxa host on the link. Many such NSes can fill the cache and evict good entries.

## Details
src/stack.rs:2259:
```rust
if let Some(lladdr) = lladdr {
    let lladdr = check!(lladdr.parse(iface.medium()));
    if !lladdr.is_unicast() || !target_addr.x_is_unicast() {
        return;
    }
    self.fill_neighbor(iface, IpAddr::V6(src_addr), lladdr);
}
```
The target check only guards the reply, src/stack.rs:2270:
```rust
if (iface.has_solicited_node(dst_addr) || iface.has_ip_addr(dst_addr.into()))
    && iface.has_ip_addr(target_addr.into())
```
`process_ipv6` accepts ff02::1, our unicast addresses, and any solicited-node group that shares the low 24 bits with one of ours. So the NS does not have to be about us. `fill_neighbor` replaces the hardware address of an existing entry and makes it Reachable for 60 s. The RFC says a new entry from an NS SHOULD be STALE, which is a second deviation.

Also, a valid NS for our address sent to ff02::1 is not answered, because of the destination check at line 2270. That case is rare.

Hop limit 255 is enforced, so the attacker must be on-link. ND is unauthenticated anyway, so the added exposure is the multicast reach and the foreign-target case.

## Failure scenario
The attacker sends one frame to 33:33:00:00:00:01 with NS src=fe80::77 (a victim, e.g. the router), dst=ff02::1, target=fdaa::99 (not ours), SLLA=attacker MAC. Every xarxa host on the link now maps fe80::77 to the attacker's MAC. Repeating with random sources fills the 8-entry cache and evicts the router, so egress keeps parking and re-resolving.

## RFC reference
RFC 4861 §7.2.3: "A valid Neighbor Solicitation that does not meet any of the following requirements MUST be silently discarded: - The Target Address is a "valid" unicast or anycast address assigned to the receiving interface [ADDRCONF], - The Target Address is a unicast or anycast address for which the node is offering proxy service, or - The Target Address is a "tentative" address on which Duplicate Address Detection is being performed [ADDRCONF]."

## Reproduction
Test in `src/stack.rs` `mod test`, scratch copy of HEAD:
```rust
#[test]
#[cfg(all(feature = "ipv6", feature = "medium-ethernet"))]
fn lo4_ns_foreign_target_fills_cache() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let victim = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x77);
    let good = EthernetAddress([0x02, 0, 0, 0, 0, 0x77]);
    let attacker = EthernetAddress([0x02, 0, 0, 0, 0, 0x66]);
    stack.neighbor_cache_mut().insert(IfaceHandle::new(0), victim.into(), HardwareAddress::Ethernet(good), Instant::from_secs(100)).unwrap();
    let foreign_target = Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 0x99);
    inject(&mut stack, &rx, neighbor_solicit(attacker, victim, Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), foreign_target));
    stack.poll(Instant::ZERO);
    assert_eq!(cached_lladdr(&stack, victim), Some(attacker));
    assert!(tx.borrow().is_empty());
}
```
`cargo test --lib lo4_ -- --nocapture`:
```
after multicast NS: Some(Address([2, 0, 0, 0, 0, 102]))
test stack::test::lo4_ns_foreign_target_fills_cache ... ok
```

## Suggested fix
Check `iface.has_ip_addr(target_addr)` first and return if it fails. Only then parse the SLLA, fill the cache and reply. Consider dropping the destination restriction at line 2270, since `process_ipv6` already filtered the destination.
