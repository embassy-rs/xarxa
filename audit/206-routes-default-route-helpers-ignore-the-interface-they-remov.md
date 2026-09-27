# 206. Default-route helpers ignore the interface and remove another interface's DHCP route

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/route.rs:261](../src/route.rs#L261), [src/route.rs:209](../src/route.rs#L209), [src/route.rs:249](../src/route.rs#L249), [src/route.rs:304](../src/route.rs#L304), [src/iface/dhcpv4.rs:870](../src/iface/dhcpv4.rs#L870) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`add_default_ipv4_route`/`add_default_ipv6_route` remove the first default route of the family, whatever its interface or origin. `default_ipv4_route` reports the first one, but `lookup` uses the last one. On a multi-interface stack a manual add can delete another interface's DHCP route, which DHCP does not reinstall while the router stays the same.

## Details
`add_default_ipv4_route` (line 209) calls `remove_default_ipv4_route`:

src/route.rs:261-264
```rust
let index = self.storage.iter().position(|r| r.is_ipv4_gateway())?;
```
`default_ipv4_route` (line 249) uses `.find(...)`, the first match. `lookup` uses `.max_by_key(|route| route.cidr.prefix_len())` (line 304), which returns the last of equal maxima.

DHCP only re-adds its route on a router change:

src/iface/dhcpv4.rs:870
```rust
if old_router != new_router {
```

## Failure scenario
iface1 runs DHCP and has a DHCP default route. The app calls `routes_mut().add_default_ipv4_route(gw0, iface0)`. iface1's route is deleted and stays gone until the lease's router changes. Code that calls `default_ipv4_route()` to learn the gateway sees a different route than the one sockets use.

## Suggested fix
Scope the helpers to the given interface, possibly only Manual-origin routes. Document which route `lookup` prefers among equal prefixes, or make `default_ipv4_route` return that one.
