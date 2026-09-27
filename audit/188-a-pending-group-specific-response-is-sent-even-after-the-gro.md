# 188. A pending group-specific response is sent after the group was left

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/multicast.rs:321](../src/multicast.rs#L321), [src/multicast.rs:387](../src/multicast.rs#L387), [src/multicast.rs:212](../src/multicast.rs#L212) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
When a `ToSpecificQuery` timer fires, IGMP and MLD build a report for the stored `group` without checking that the interface still listens to it. `leave_multicast_group` never clears the pending response. So a leave is followed by a report for the same group, and the router keeps forwarding it.

## Details
`leave_multicast_group` (src/multicast.rs:212) only moves the group to Leaving or removes it. It does not touch `igmp_report_state` or `mld_report_state`.

src/multicast.rs:321-326 (IGMP):
```rust
IgmpReportState::ToSpecificQuery { version, timeout, group } if clock.expired(timeout) => {
    if let Some(pkt) = self.igmp_report_packet(version, group) {
        self.dispatch_ip(inner, pkt);
    }
```
src/multicast.rs:387-388 (MLD):
```rust
MldReportState::ToSpecificQuery { group, timeout } if clock.expired(timeout) => {
    let record = (MldRecordType::ModeIsExclude, group);
```
The Leaving arm runs first in `multicast_egress`, so the report can follow the leave in the same poll or a later one. General-query responses are fine: they read the table when the timer fires.

The finder observed it: joined ff02::1234, received a specific query (MRC 10 s), left, polled. Output was `[(ChangeToInclude, ff02::1234)]`, then a few seconds later `[(ModeIsExclude, ff02::1234)]`.

## Failure scenario
The app leaves a stream shortly after a Multicast Address Specific Query for it (e.g. the router's last listener query after another host left). The stale IS_EX answers the query. The router keeps flooding the stream for the listener interval (260 s by default).

## RFC reference
RFC 3810 §6.3: "2. If the expired timer is a Multicast Address Timer and the list of recorded sources for that multicast address is empty (i.e., there is a pending response to a Multicast Address Specific Query), then if, and only if, the interface has listening state for that multicast address, a single Current State Record is sent for that address."

## Suggested fix
At expiry, send only if the group is still in the table and not Leaving. Or clear a matching pending specific response when the group is left.
