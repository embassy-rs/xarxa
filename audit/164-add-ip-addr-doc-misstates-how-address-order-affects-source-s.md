# 164. add_ip_addr doc misstates how address order affects source selection

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:376](../src/iface/mod.rs#L376), [src/iface/mod.rs:840](../src/iface/mod.rs#L840), [src/iface/mod.rs:1004](../src/iface/mod.rs#L1004) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The doc says ordering only matters between addresses of the same subnet. For IPv4, the first IPv4 address is the source for every off-link destination, so order across subnets matters. For IPv6, selection follows RFC 6724 and order only breaks ties.

## Details
src/iface/mod.rs:378:
```rust
/// returned. Source address selection prefers the first address matching the
/// destination's subnet, so ordering only matters between addresses of the same
/// subnet.
```
src/iface/mod.rs:846:
```rust
if cidr.contains_addr(dst_addr) {
    return Some(cidr.address());
}
if first_ipv4.is_none() {
    first_ipv4 = Some(cidr.address());
}
```
`get_source_address_ipv6` (line 1004) applies scope, deprecation and longest common prefix before order.

## Failure scenario
The user adds 10.0.0.5/24, then 192.168.1.5/24 with the default gateway on 192.168.1.0/24. All off-link traffic goes out with source 10.0.0.5.

## Suggested fix
IPv4: first address in the destination's subnet, else the first IPv4 address. IPv6: RFC 6724 selection, with order breaking ties.
