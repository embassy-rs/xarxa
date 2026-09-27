# 205. A default route with host bits set (e.g. 10.0.0.0/0) is not recognized by the default-route helpers

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/route.rs:96](../src/route.rs#L96), [src/route.rs:102](../src/route.rs#L102), [src/route.rs:154](../src/route.rs#L154) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`is_ipv4_gateway` and `is_ipv6_gateway` compare the whole CIDR, address included, with `0.0.0.0/0` or `::/0`. A route with cidr `10.0.0.0/0` matches every destination in `lookup`, but the default-route helpers ignore it. Two default routes can then coexist.

## Details
src/route.rs:96-98
```rust
pub fn is_ipv4_gateway(&self) -> bool {
    self.cidr == IPV4_DEFAULT
}
```
`Cidr` derives `PartialEq` over (address, prefix_len), and `Cidr::new`/`try_new` do not clear host bits. `contains_addr` masks both sides, so lookup treats `x/0` as a default. `Routes::add` (line 154) does not normalize.

## Failure scenario
The app adds `Route { cidr: IpCidr::new(gw.into(), 0), .. }` with `Routes::add`. Later `add_default_ipv4_route(new_gw, iface)` returns `Ok(None)` and leaves the old route. `lookup` picks the last /0, and `remove_default_ipv4_route` never removes the first one.

## Suggested fix
Compare only the family and `prefix_len == 0`, or normalize the CIDR in `Routes::add`.
