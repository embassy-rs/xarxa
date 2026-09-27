# 190. IGMP host never suppresses its report on hearing another host's report

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/multicast.rs:489](../src/multicast.rs#L489) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`process_igmp` discards received v1/v2 membership reports, so a pending report for that group is never cancelled. RFC 2236 §5 says the host MUST allow suppression. Every xarxa host on a LAN reports every group. Only report volume is affected.

## Details
src/multicast.rs:489-490:
```rust
// Ignore membership reports
IgmpMessage::MembershipReportV1 | IgmpMessage::MembershipReportV2 => (),
```
Reports go to the group address, we are a member, so they reach `process_igmp`. `igmp_report_state` is left alone.

## Failure scenario
50 xarxa devices in one group answer each general query with 50 reports, all at the same instant given the fixed delays of 189. A compliant set of hosts sends about one.

## RFC reference
RFC 2236 §5: "The host MUST allow its Membership Report to be suppressed by either a Version 1 Membership Report or a Version 2 Membership Report."

RFC 2236 §3: "If the host receives another host's Report (version 1 or 2) while it has a timer running, it stops its timer for the specified group and does not send a Report, in order to suppress duplicate Reports."

## Suggested fix
On a received v1/v2 report for G, cancel the pending response for G. With the single slot, clear `ToSpecificQuery` when `group == G`. Per-group flags would handle general-query spreading too.
