# 035. `Iface::set_hardware_addr` leaves SLAAC addresses formed from the old MAC assigned forever

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/iface/mod.rs:345](../src/iface/mod.rs#L345), [src/iface/slaac.rs:457](../src/iface/slaac.rs#L457) |
| Features | `slaac` (default) |
| Verification | reproduced with a test |

## Summary
`set_hardware_addr` regenerates the link-local address but leaves SLAAC addresses alone. `sync_slaac_state` finds its addresses only by recomputing them from the current hardware address. So after a MAC change, the old-MAC address is never refreshed and never removed when its prefix expires or is withdrawn. Only `set_slaac(None)` removes it. Its `preferred_until` stays behind and breaks the DESIGN.md §4 "Time" invariant.

## Details
src/iface/mod.rs:349:
```rust
self.state_mut().hardware_addr = addr;
#[cfg(all(any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
{
    let had = self.state_mut().remove_ip_addrs(AddrOrigin::LinkLocal);
    if let Some(ll) = link_local_addr(addr) {
```

Nothing touches `AddrOrigin::Slaac` addresses.

src/iface/slaac.rs:456:
```rust
for (prefix, prefixinfo) in slaac.prefix.iter() {
    let Some(address) = from_link_prefix(prefix, hardware_addr) else {
        continue;
    };
    let existing = self.ip_addrs.iter().position(|a| a.cidr == IpCidr::V6(address));
```

The old address never matches again. When the prefix goes, only the new-MAC address is removed.

src/iface/mod.rs:229:
```rust
pub fn is_preferred(&self, now: Instant) -> bool {
    self.preferred_until.is_none_or(|until| until > now)
}
```

The stale `preferred_until` uses the wrapping comparison, so after 2^31 ms it compares as future again.

Effects of the orphaned address:
- It and its implied /64 on-link route stay after the prefix is withdrawn or the device moves networks.
- It is still accepted as a destination and keeps its solicited-node group.
- It can be chosen as a source. After about 24.8 days it counts as preferred again.
- Without `alloc` it takes one of the `IFACE_ADDR_COUNT` slots, which can stop the new-MAC address from being assigned ("address table full").

## Failure scenario
SLAAC is on and has formed 2001:db8::<old-EUI64>. The app then calls `set_hardware_addr` with a MAC read from EEPROM (the documented override), or for MAC randomization. The old address stays for the life of the stack, even after the router withdraws the prefix. Weeks later it is picked as a source for new connections, and replies never arrive because nobody answers NDISC for it at the new MAC.

## Reproduction
Added to `mod test` in src/stack.rs, in a scratch copy of HEAD:
```rust
#[test]
#[cfg(feature = "slaac")]
fn vfy_slaac_mac_change_leaves_old_addr() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ethernet);
    let iface = IfaceHandle::new(0);
    let router_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    let router_ll = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x2);
    let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    let old_addr: IpAddr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0xff, 0xfe00, 0x1).into();
    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    stack.poll(Instant::from_secs(1));
    rx.borrow_mut().push_back(router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix, Duration::from_secs(7200), Duration::from_secs(3600)));
    stack.poll(Instant::from_secs(2));
    assert!(stack.iface(iface).has_ip_addr(old_addr));
    stack.iface(iface).set_hardware_addr(HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x09]))).unwrap();
    rx.borrow_mut().push_back(router_advert(router_hw, router_ll, Duration::from_secs(1800), prefix, Duration::from_secs(7200), Duration::from_secs(3600)));
    stack.poll(Instant::from_secs(3));
    rx.borrow_mut().push_back(router_advert(router_hw, router_ll, Duration::ZERO, prefix, Duration::ZERO, Duration::ZERO));
    stack.poll(Instant::from_secs(4));
    let mut t = Instant::from_secs(4);
    for _ in 0..30 { t = t + Duration::from_secs(86400); stack.poll(t); }
    let a = *stack.iface(iface).ip_addrs().iter().find(|a| a.cidr.address() == old_addr).expect("old addr still there");
    std::println!("after 30 days: {:?} preferred={}", a, a.is_preferred(t));
    assert!(!stack.iface(iface).has_ip_addr(old_addr), "old SLAAC address still assigned");
}
```

`cargo test --lib vfy_ -- --nocapture`. After the withdrawal, the new 2001:db8::ff:fe00:9 is gone and the old one remains:
```
after 30 days: IfaceAddr { cidr: 2001:db8::ff:fe00:1/64, origin: Slaac, preferred_until: Some(Instant { millis: 3602000 }) } preferred=true
panicked: old SLAAC address still assigned
```

## Suggested fix
In `set_hardware_addr`, also remove `AddrOrigin::Slaac` addresses and mark SLAAC for resync so the next poll re-forms them from the new MAC. Alternatively, have `sync_slaac_state` remove any Slaac-origin address that no current prefix forms.
