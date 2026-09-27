# 114. With `alloc`, routes, SLAAC routers/prefixes and addresses learned from RAs are unbounded

| | |
|---|---|
| Severity | low |
| Category | resource-leak |
| Location | [src/config.rs:52](../src/config.rs#L52), [src/storage/vec.rs:26](../src/storage/vec.rs#L26), [src/iface/slaac.rs:202](../src/iface/slaac.rs#L202), [src/iface/slaac.rs:226](../src/iface/slaac.rs#L226), [src/iface/slaac.rs:446](../src/iface/slaac.rs#L446), [src/route.rs:139](../src/route.rs#L139) |
| Features | default (`alloc`, `slaac`) |
| Verification | confirmed against the code |

## Summary
`ROUTE_COUNT`, `SLAAC_ROUTER_COUNT`, `SLAAC_PREFIX_COUNT` and `IFACE_ADDR_COUNT` are documented as "Ignored with `alloc`". So an on-link sender of router advertisements can grow the SLAAC lists, the address table and the routing table without limit. Memory grows until allocation fails, and the linear route lookup and SLAAC sync slow down with every entry. The ignored limits are documented. This DoS consequence is not.

## Details
src/storage/vec.rs:26-31, with `alloc`:
```rust
    pub fn push(&mut self, item: T) -> Result<(), T> {
        #[cfg(feature = "alloc")]
        {
            self.inner.push(item);
            Ok(())
        }
```
src/iface/slaac.rs:157-159:
```rust
    prefix: Vec<(Ipv6Cidr, PrefixInfo), SLAAC_PREFIX_COUNT>,
    routes: Vec<Route, SLAAC_ROUTER_COUNT>,
```
`add_prefix` (slaac.rs:202) and `add_route` (slaac.rs:226) dedup only by cidr and by (cidr, router), then push. Their "full" warning branches are unreachable with `alloc`. `sync_slaac_state` (slaac.rs:446) copies entries into `inner.routes` (route.rs:139, `Vec<Route, ROUTE_COUNT>`) and the address table, with linear searches. Lifetimes are capped only at `Duration::MAX`, about 12 days.

RAs must come from a link-local source with hop limit 255, so the attacker is on-link. Each RA adds as many prefixes as fit in one packet, and the attacker can send any number of RAs.

## Failure scenario
An attacker on the LAN sends RAs from many distinct `fe80::` sources, each with distinct /64 prefixes. The heap grows by megabytes, every packet pays a long route scan, and an embedded heap eventually runs out.

## Suggested fix
Keep network-learned tables bounded with `alloc` too: use a fixed cap (for example the `SLAAC_*` limits, via `BoundedVec`) for what SLAAC learns.
