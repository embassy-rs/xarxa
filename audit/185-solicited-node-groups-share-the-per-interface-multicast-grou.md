# 185. Solicited-node groups share the fixed multicast group table: when full, a new address gets no MLD report

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/multicast.rs:255](../src/multicast.rs#L255), [src/multicast.rs:60](../src/multicast.rs#L60), [src/config.rs:54](../src/config.rs#L54) |
| Features | `ipv6`, `multicast`, without `alloc` |
| Verification | confirmed against the code |

## Summary
Without `alloc`, solicited-node groups live in the same `Vec<_, MULTICAST_GROUP_COUNT>` as user groups. `update_solicited_node_groups` ignores `TooManyGroups`. If the table is full, a new address's solicited-node group is never added and never reported with MLD. In the other direction, solicited-node groups use up slots, so user joins fail earlier than `MULTICAST_GROUP_COUNT` suggests.

## Details
src/multicast.rs:252-256:
```rust
if let IpCidr::V6(cidr) = self.ip_addrs[i].cidr {
    let _ = self.join_multicast_group(cidr.address().solicited_node().into());
}
```
Local reception still works: ingress accepts the group through `has_solicited_node`, and the filter sync derives solicited-node MACs from the addresses. Only the MLD report is missing. The failed join is not retried when a slot frees up, only at the next `config_changed`. Addresses sharing an IID share one slot.

src/config.rs:54 says only "Max multicast groups a `Stack` can be joined to", with no mention of solicited-node groups.

## Failure scenario
No-alloc build, default 8 groups. The app joins 7 groups, plus the link-local's solicited-node group. SLAAC then forms 2001:db8::x. Its solicited-node join fails silently. Behind an MLD-snooping switch, other hosts' NS for 2001:db8::x never reach us, and inbound IPv6 to that address fails.

## Suggested fix
Size the table as `MULTICAST_GROUP_COUNT + IFACE_ADDR_COUNT`, or track solicited-node groups separately. At least log the failure and document the shared limit.
