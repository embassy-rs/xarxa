# 191. Reports are sent for ff02::1, 224.0.0.1 and interface/reserved-scope groups

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/multicast.rs:584](../src/multicast.rs#L584), [src/multicast.rs:478](../src/multicast.rs#L478), [src/multicast.rs:192](../src/multicast.rs#L192), [src/iface/mod.rs:926](../src/iface/mod.rs#L926) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
Specific-query matching uses `IfaceState::has_multicast_group`, which is true for 224.0.0.1 and ff02::1. A specific query for them gets a report. `join_multicast_group` also accepts 224.0.0.1, ff02::1 and scope 0/1 IPv6 groups, and the stack then sends joins, leaves and general-query records for them. Both RFCs forbid this.

## Details
src/multicast.rs:478 and 584:
```rust
if self.has_multicast_group(group_addr.into()) && dst_addr == group_addr {
if self.has_multicast_group(mcast_addr.into()) && dst_addr == mcast_addr {
```
src/iface/mod.rs:934-936:
```rust
IpAddr::V4(key) => key == IPV4_MULTICAST_ALL_SYSTEMS,
IpAddr::V6(key) => key == IPV6_LINK_LOCAL_ALL_NODES || self.has_solicited_node(key),
```
src/multicast.rs:192-193 only checks `if !addr.is_multicast()`.

The finder observed it: a query for ff02::1 produced `[(ModeIsExclude, ff02::1)]` to ff02::16. An IGMP specific query for 224.0.0.1 produced a v2 report for 224.0.0.1. Solicited-node groups are rightly reported.

## Failure scenario
- A host sends an address-specific query for ff02::1 or 224.0.0.1. Every xarxa host answers with a report.
- An app joins ff01::x. The stack sends MLD reports for an interface-local group onto the link.

## RFC reference
RFC 3810 §6: "No MLD messages are ever sent regarding neither the link-scope all-nodes multicast address, nor any multicast address of scope 0 (reserved) or 1 (node-local)."

RFC 2236 §6: "The all-systems group (address 224.0.0.1) is handled as a special case. The host starts in Idle Member state for that group on every interface, never transitions to another state, and never sends a report for that group."

## Suggested fix
Use the table-only `State::has_multicast_group` for query matching. Never send IGMP/MLD for 224.0.0.1, ff02::1 or IPv6 scope 0/1, either by rejecting them in `join_multicast_group` or by skipping them when reporting.
