# 187. A pool miss during IGMP general-query spreading abandons all remaining reports

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/multicast.rs:362](../src/multicast.rs#L362), [src/multicast.rs:499](../src/multicast.rs#L499), [src/multicast.rs:293](../src/multicast.rs#L293) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`igmp_report_packet` returns `None` both when there is no IPv4 address and when the pool is empty. The spread treats every `None` as "no address" and goes Inactive. One transient pool miss drops the reports of every remaining group in that round. Separately, join reports are sent once and never repeated, so a pool miss or a lost frame loses the join until the next query.

## Details
src/multicast.rs:499-500:
```rust
let iface_addr = self.ipv4_addr()?;
let mut pkt = PacketBuf::try_new()?;
```
src/multicast.rs:348-364:
```rust
if let Some(pkt) = self.igmp_report_packet(version, addr) {
    ...
    next_index: next_index + 1
} else {
    // No address to report from: nothing else to send.
    self.multicast.igmp_report_state = IgmpReportState::Inactive;
}
```
src/multicast.rs:290-293, the join:
```rust
if let Some(pkt) = pkt {
    self.dispatch_ip(inner, pkt);
}
self.multicast.groups[i].1 = GroupState::Joined;
```
DESIGN.md §3 says stack-generated packets are best effort and "the timers cover them". No timer covers a join. The MLD join path behaves the same. The `ToSpecificQuery` branch also drops its one report on a pool miss, which is in line with best effort.

## Failure scenario
- A general query arrives during an RX burst. The first report finds the pool empty. All other groups go unreported until the next general query (up to 125 s). Twice in a row and the router may prune them.
- The app joins 239.1.2.3 while the pool is empty. No report goes out, and a snooping switch doesn't forward the group until the next query.

## RFC reference
RFC 2236 §3: "To cover the possibility of the initial Membership Report being lost or damaged, it is recommended that it be repeated once or twice after short delays [Unsolicited Report Interval]."

RFC 3810 §6.1: "To cover the possibility of the State Change Report being missed by one or more multicast routers, [Robustness Variable] - 1 retransmissions are scheduled"

## Suggested fix
Tell the two `None` causes apart. On pool exhaustion, keep the state and retry after `POOL_RETRY_DELAY` with `clock.after`, or at least skip only that group. Consider repeating unsolicited reports as the RFCs recommend.
