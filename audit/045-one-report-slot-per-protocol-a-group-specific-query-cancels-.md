# 045. One report slot per protocol: a group-specific query cancels a pending general-query response

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/multicast.rs:584](../src/multicast.rs#L584), [src/multicast.rs:476](../src/multicast.rs#L476), [src/multicast.rs:469](../src/multicast.rs#L469), [src/multicast.rs:576](../src/multicast.rs#L576), [src/multicast.rs:26](../src/multicast.rs#L26) |
| Features | default (`multicast`) |
| Verification | reproduced with a test |

## Summary

IGMP and MLD each keep a single report state (`igmp_report_state`, `mld_report_state`). A group-specific query overwrites a pending general-query response, so every other group goes unreported in that round. A specific query for group A also cancels a pending specific response for group B. A general query replaces a pending response unconditionally, ignoring how much time it had left. This breaks RFC 3810 §6.2 rules 1, 3 and 4, and the per-group timer rule of RFC 2236 §3.

## Details

The state is one slot per protocol:

src/multicast.rs:43
```rust
pub(crate) enum MldReportState {
    Inactive,
    ToGeneralQuery { timeout: Instant },
    ToSpecificQuery { group: Ipv6Addr, timeout: Instant },
}
```

MLD specific query:

src/multicast.rs:584
```rust
if self.has_multicast_group(mcast_addr.into()) && dst_addr == mcast_addr {
    self.multicast.mld_report_state = MldReportState::ToSpecificQuery {
        group: mcast_addr,
        timeout: inner.now + delay,
    };
}
```

IGMP specific query:

src/multicast.rs:478
```rust
if self.has_multicast_group(group_addr.into()) && dst_addr == group_addr {
    // Don't respond immediately
    let timeout = max_resp_time / 4;
    self.multicast.igmp_report_state = IgmpReportState::ToSpecificQuery {
```

General queries (src/multicast.rs:469 for IGMP, src/multicast.rs:579 for MLD) assign `ToGeneralQuery` with a fresh delay, dropping a pending specific response and ignoring a pending general response that was due sooner. For IGMP that can push the queried group's report past the router's Last Member Query Time.

Side issue, not tested: in `multicast_egress`, the IGMP general-query spread goes `Inactive` when `igmp_report_packet` returns `None` (src/multicast.rs:361). The comment says "No address to report from", but `None` also means the pool was empty, so the rest of the spread is dropped.

## Failure scenario

- The router sends an MLD general query (max resp 10 s). Before our random delay runs out, another host leaves ff02::fb and the router sends a specific query for ff02::fb, which we joined. Our pending general report becomes a report for ff02::fb only. The solicited-node group is not reported that round. If it happens in two consecutive rounds, a snooping switch drops our solicited-node membership after the listener interval (260 s) and peers can no longer resolve our address.
- The host is in groups A and B. Other hosts leave both. The querier sends Last Listener Queries for B and A interleaved, 1 s apart. Each A query overwrites the pending B response. The router concludes B has no listeners and stops forwarding it until the next general query, up to 125 s.

It takes more than one missed round before a router or snooper drops a membership, which keeps this at medium.

## RFC reference

RFC 3810 §6.2:
> 1. If there is a pending response to a previous General Query scheduled sooner than the selected delay, no additional response needs to be scheduled.
>
> 2. If the received Query is a General Query, the Interface Timer is used to schedule a response to the General Query after the selected delay. Any previously pending response to a General Query is canceled.
>
> 3. If the received Query is a Multicast Address Specific Query or a Multicast Address and Source Specific Query and there is no pending response to a previous Query for this multicast address, then the Multicast Address Timer is used to schedule a report.

RFC 2236 §3:
> If a timer for the group is already running, it is reset to the random value only if the requested Max Response Time is less than the remaining value of the running timer.

## Reproduction

Added to the `src/multicast.rs` test module in a scratch copy:

```rust
#[test]
fn verify_mld_specific_cancels_general() {
    let medium = Medium::Ethernet;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    let g = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x1234);
    stack.iface(IFACE).join_multicast_group(g).unwrap();
    stack.poll(Instant::ZERO);
    recv_mld(medium, &tx);
    let q = mld_query(REMOTE_LL, IPV6_LINK_LOCAL_ALL_NODES, Ipv6Addr::UNSPECIFIED, 10000);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, q, Instant::ZERO);
    let q = mld_query(REMOTE_LL, g, g, 10000);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, q, Instant::ZERO);
    let mut all = Vec::new();
    for ms in (0..30_000).step_by(100) {
        stack.poll(Instant::from_millis(ms));
        all.extend(recv_mld(medium, &tx).into_iter().map(|r| r.3));
    }
    println!("MLD reports: {:?}", all);
    assert!(all.iter().flatten().any(|(_, a)| *a == OUR_LL.solicited_node()));
}

#[test]
fn verify_igmp_specific_cancels_general() {
    let medium = Medium::Ip;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    let groups = [Ipv4Addr::new(224, 0, 0, 22), Ipv4Addr::new(224, 0, 0, 56)];
    for g in &groups {
        stack.iface(IFACE).join_multicast_group(*g).unwrap();
    }
    stack.poll(Instant::ZERO);
    recv_igmp(medium, &tx);
    let mrt = Duration::from_secs(10);
    let q = igmp_packet(REMOTE_V4, IPV4_MULTICAST_ALL_SYSTEMS, IgmpMessage::MembershipQuery, mrt,
        Ipv4Addr::UNSPECIFIED);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, q, Instant::ZERO);
    let q = igmp_packet(REMOTE_V4, groups[1], IgmpMessage::MembershipQuery, mrt, groups[1]);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, q, Instant::ZERO);
    let mut all = Vec::new();
    for ms in (0..30_000).step_by(100) {
        stack.poll(Instant::from_millis(ms));
        all.extend(recv_igmp(medium, &tx).into_iter().map(|r| r.4));
    }
    println!("IGMP reports: {:?}", all);
    assert!(all.contains(&groups[0]));
}
```

Output:
```
MLD reports: [[(ModeIsExclude, ff02::1234)]]
panicked: solicited-node group never reported for the general query
IGMP reports: [224.0.0.56]
panicked: 224.0.0.22 never reported for the general query
```

## Suggested fix

Keep a per-group pending-report deadline next to `GroupState`, plus one interface timer for general queries. Apply RFC 3810 §6.2: skip a specific response when a general response is due sooner, and on a re-query keep the earlier deadline. For IGMP, reset a group's timer only when the new max response time is shorter than what remains. Separately, keep the IGMP general spread alive when only the buffer allocation failed.
