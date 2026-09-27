# 115. config docs: MULTICAST_GROUP_COUNT is per interface and shared with solicited-node groups; IFACE_ADDR_COUNT omits the link-local slot

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/config.rs:54](../src/config.rs#L54), [src/config.rs:38](../src/config.rs#L38), [src/multicast.rs:60](../src/multicast.rs#L60), [src/multicast.rs:255](../src/multicast.rs#L255), [src/multicast.rs:150](../src/multicast.rs#L150), [src/iface/mod.rs:440](../src/iface/mod.rs#L440) |
| Features | no `alloc` (both limits are ignored with `alloc`) |
| Verification | confirmed against the code |

## Summary
`MULTICAST_GROUP_COUNT` says "Max multicast groups a `Stack` can be joined to". The table lives in each interface's `multicast::State`, so the limit is per interface. The same table also holds the automatic solicited-node groups, and a full table skips those joins silently. `Iface::join_multicast_group` documents only `Unaddressable` but can return `TooManyGroups`. `IFACE_ADDR_COUNT` lists application, DHCP and SLAAC addresses, but the automatic IPv6 link-local address takes a slot too.

## Details
src/multicast.rs:59-60, one per `IfaceState`:
```rust
pub(crate) struct State {
    groups: Vec<(IpAddr, GroupState), MULTICAST_GROUP_COUNT>,
```
src/multicast.rs:255, error ignored, no log:
```rust
                let _ = self.join_multicast_group(cidr.address().solicited_node().into());
```
src/iface/mod.rs:441-445, `set_ip_addrs` keeps the link-local address in the same table:
```rust
        for a in self.state().ip_addrs.iter() {
            if a.origin == AddrOrigin::LinkLocal && !addrs.iter().any(|n| n.cidr.address() == a.cidr.address()) {
                addrs.push(*a).map_err(|_| AddrError::Full)?;
            }
        }
```

## Failure scenario
- No-alloc dual-stack Ethernet with `iface-addr-count-1`. `set_ip_addrs([10.0.0.1/24])` returns `Full`. A DHCP lease is only warned about and never installed, so IPv4 does not work.
- The app joins 8 groups, then SLAAC adds an address. Its solicited-node group is not joined and never reported, so an MLD-snooping switch may not forward NS for it.
- With 3 interfaces a user budgets 8 groups total and pays for 24.

## Suggested fix
Say "per interface" and mention solicited-node groups in `MULTICAST_GROUP_COUNT`. Mention the link-local address in `IFACE_ADDR_COUNT`. Add `TooManyGroups` to the `join_multicast_group` errors. Log the failed solicited-node join.
