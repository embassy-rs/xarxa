# 167. set_ip_addrs accepts duplicate addresses, and remove_ip_addr then leaves the address assigned

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/iface/mod.rs:434](../src/iface/mod.rs#L434), [src/iface/mod.rs:411](../src/iface/mod.rs#L411) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`set_ip_addrs` pushes each CIDR without deduplicating by address, although it is documented as "Equivalent to removing every address and adding the given ones", and `add_ip_addr` merges by address. `remove_ip_addr` removes only the first copy and returns `Some`, so the address stays assigned. The duplicate also takes an `IFACE_ADDR_COUNT` slot.

## Details
src/iface/mod.rs:434:
```rust
for cidr in new_addrs {
    if !cidr.address().is_unicast() {
        return Err(AddrError::NotUnicast);
    }
    addrs.push(IfaceAddr::manual(cidr)).map_err(|_| AddrError::Full)?;
}
```
src/iface/mod.rs:411:
```rust
let index = ip_addrs.iter().position(|a| a.cidr.address() == addr)?;
```

## Reproduction
Test in `src/stack.rs` `mod test` (scratch copy):
```rust
stack.iface(h).set_ip_addrs([IpCidr::new(Ipv4Addr::new(192,168,1,1).into(), 24), IpCidr::new(Ipv4Addr::new(192,168,1,1).into(), 16)]).unwrap();
std::println!("addrs: {:?}", stack.iface(h).ip_addrs());
let removed = stack.iface(h).remove_ip_addr(Ipv4Addr::new(192,168,1,1));
std::println!("removed {:?} still has {}", removed, stack.iface(h).has_ip_addr(Ipv4Addr::new(192,168,1,1)));
```
Output:
```
addrs: [.. 192.168.1.1/24 Manual .., .. 192.168.1.1/16 Manual .., fe80::ff:fe00:1/64 LinkLocal]
removed Some(V4(Cidr { address: 192.168.1.1, prefix_len: 24 })) still has true
```

## Suggested fix
In `set_ip_addrs`, replace an existing entry with the same address instead of pushing, or return an error for duplicates.
