# 186. IGMP general-query spreading indexes the group table by position, so a removal during the spread skips a group

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/multicast.rs:346](../src/multicast.rs#L346), [src/multicast.rs:310](../src/multicast.rs#L310), [src/multicast.rs:118](../src/multicast.rs#L118) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`IgmpReportState::ToGeneralQuery` keeps `next_index`, a position in the IPv4-filtered group list. Groups are removed with `swap_remove`, which moves the last group into the freed slot. A removal between two spread reports reorders the list, so one group can be skipped and another reported twice.

## Details
src/multicast.rs:340-346:
```rust
.keys()
.filter_map(|addr| match addr { IpAddr::V4(addr) => Some(*addr), _ => None })
.nth(next_index);
```
src/multicast.rs:309-310, which runs earlier in the same `multicast_egress` call:
```rust
// The last group moves into this slot, and is looked at next.
self.multicast.groups.swap_remove(i);
```
`State::remove` (line 118) also uses `swap_remove`, for leaving a Joining group.

IPv6 removals reorder the IPv4 groups too when the last entry is IPv4. That includes solicited-node groups dropped by `update_solicited_node_groups` when an address goes away (e.g. SLAAC expiry). So the app does not need to touch IPv4 groups.

## Failure scenario
- IPv4 groups [A, B, C]. A general query arrives. A is reported, `next_index = 1`. The app leaves A. The leave goes out and `swap_remove(0)` gives [C, B]. The spread reports B, then `nth(2)` is `None` and ends. C is not reported this round.
- [A(v4), X(v6), B(v4), C(v4)], A and B reported, `next_index = 2`. X is removed, giving [A, C, B]. B is reported twice, C is skipped.

The next general query covers it, unless it happens again.

## Suggested fix
Use per-group "report pending" flags or deadlines instead of a positional index. Or remove groups with the order-preserving `remove`.
