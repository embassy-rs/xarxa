# 166. add_ip_addr with a new prefix silently changes an autoconfigured address into a manual one

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/iface/mod.rs:397](../src/iface/mod.rs#L397), [src/iface/mod.rs:442](../src/iface/mod.rs#L442) |
| Features | default |
| Verification | reproduced with a test |

## Summary
When the address exists with a different prefix, the entry is replaced with `IfaceAddr::manual(cidr)`, losing its origin (LinkLocal, Dhcpv4, Slaac) and `preferred_until`. With an identical CIDR the call returns `Ok(Some)` and keeps the old origin. Neither is documented.

## Details
src/iface/mod.rs:396:
```rust
Some(index) if ip_addrs[index].cidr == cidr => Ok(Some(cidr)),
Some(index) => {
    let old = core::mem::replace(&mut ip_addrs[index], IfaceAddr::manual(cidr));
```
Consequences:
- A link-local address turned Manual is dropped by a later `set_ip_addrs`, which only keeps `LinkLocal` entries. SLAAC then never solicits and MLD has no source.
- `set_hardware_addr` no longer replaces it.
- A deprecated SLAAC address becomes preferred forever.
- Re-adding a DHCP address with the same CIDR to "pin" it does nothing. DHCP removes it at lease end.

## Reproduction
Test in `src/stack.rs` `mod test` (scratch copy):
```rust
let ll = stack.iface(h).ip_addrs().iter().find(|a| a.origin == AddrOrigin::LinkLocal).copied().unwrap();
let r = stack.iface(h).add_ip_addr(IpCidr::new(ll.cidr.address(), 10));
std::println!("ll change {:?} -> {:?}", r, stack.iface(h).ip_addrs());
stack.iface(h).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
std::println!("after set: {:?}", stack.iface(h).ip_addrs());
```
Output:
```
ll change Ok(Some(V6(Cidr { address: fe80::ff:fe00:1, prefix_len: 64 }))) -> [..., IfaceAddr { cidr: V6(Cidr { address: fe80::ff:fe00:1, prefix_len: 10 }), origin: Manual, preferred_until: None }]
after set: [IfaceAddr { cidr: V4(Cidr { address: 192.168.1.1, prefix_len: 24 }), origin: Manual, preferred_until: None }]
```

## Suggested fix
Keep origin and `preferred_until` when only the prefix changes, or document the conversion. Document that a same-CIDR call leaves the origin unchanged.
