# 043. No IGMPv1 Router Present state: joins always go out as v2 and leaves are still sent

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/multicast.rs:446](../src/multicast.rs#L446), [src/multicast.rs:283](../src/multicast.rs#L283), [src/multicast.rs:299](../src/multicast.rs#L299), [README.md:128](../README.md#L128) |
| Features | default (`multicast`, `ipv4`) |
| Verification | reproduced with a test |

## Summary

The IGMP report version is picked per query, from that query's Max Resp Code, and only used for the reply to it. There is no per-interface "IGMPv1 querier heard in the last 400 s" state, which RFC 2236 §4 requires with MUST. Unsolicited joins are always v2, which an IGMPv1 router ignores, and Leave messages are sent even with a v1 querier. The README claims IGMPv1 support.

## Details

src/multicast.rs:446
```rust
let version = if igmp_packet.max_resp_code() == 0 {
    IgmpVersion::Version1
} else {
    IgmpVersion::Version2
};
```

The version is stored only in `igmp_report_state` for that one response.

src/multicast.rs:283
```rust
IpAddr::V4(addr) => self.igmp_report_packet(IgmpVersion::Version2, addr),
```

src/multicast.rs:299
```rust
IpAddr::V4(addr) => self.igmp_leave_packet(addr),
```

Classifying by the code alone also treats an IGMPv3 query (length >= 12) with Max Resp Code 0 as v1, where RFC 3376 §7.1 classifies it as v3. Not tested, and minor.

## Failure scenario

A subnet has an IGMPv1 querier (an RFC 1112 router, or a switch in v1 mode). The host calls `join_multicast_group`. It sends a v2 report, which the router ignores. Group traffic only starts after the next v1 general query, 60 to 125 s later. Every leave sends a useless Leave to 224.0.0.2.

IGMPv1 queriers are rare today, which limits the impact.

## RFC reference

RFC 2236 §4:
> The IGMPv1 router expects Version 1 Membership Reports in response to its Queries, and will not pay attention to Version 2 Membership Reports. Therefore, a state variable MUST be kept for each interface, describing whether the multicast Querier on that interface is running IGMPv1 or IGMPv2. This variable MUST be based upon whether or not an IGMPv1 query was heard in the last [Version 1 Router Present Timeout] seconds, and MUST NOT be based upon the type of the last Query heard. This state variable MUST be used to decide what type of Membership Reports to send for unsolicited Membership Reports as well as Membership Reports in response to Queries.

> An IGMPv2 host MAY suppress Leave Group messages on a network where the Querier is using IGMPv1.

RFC 2236 §6:
> "send leave" for the group on the interface. If the interface state says the Querier is running IGMPv1, this action SHOULD be skipped.

The version selection is the MUST violation. Leave suppression is a SHOULD.

## Reproduction

Added to the `src/multicast.rs` test module in a scratch copy:

```rust
#[test]
fn verif_igmpv1_querier_compat() {
    let medium = Medium::Ip;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    stack.poll(Instant::ZERO);
    tx.borrow_mut().clear();
    let query = igmp_packet(REMOTE_V4, IPV4_MULTICAST_ALL_SYSTEMS, IgmpMessage::MembershipQuery,
        Duration::ZERO, Ipv4Addr::UNSPECIFIED);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, Instant::ZERO);
    let _ = recv_igmp(medium, &tx);
    let t = Instant::from_millis(10_000);
    let g = Ipv4Addr::new(239, 1, 2, 3);
    stack.iface(IFACE).join_multicast_group(g).unwrap();
    stack.poll(t);
    let r = recv_igmp(medium, &tx);
    println!("join after v1 query: {:?}", r);
    stack.iface(IFACE).leave_multicast_group(g).unwrap();
    stack.poll(t);
    println!("leave after v1 query: {:?}", recv_igmp(medium, &tx));
    assert_eq!(r[0].3, IgmpMessage::MembershipReportV1, "v1 querier present: report should be v1");
}
```

Output:
```
join after v1 query: [(192.168.1.1, 239.1.2.3, 1, MembershipReportV2, 239.1.2.3)]
leave after v1 query: [(192.168.1.1, 224.0.0.2, 1, LeaveGroup, 239.1.2.3)]
panicked: assertion `left == right` failed: v1 querier present: report should be v1 (left: MembershipReportV2, right: MembershipReportV1)
```

## Suggested fix

Keep a per-interface Version 1 Router Present deadline (400 s), set by v1 queries (8 bytes, code 0) and counted on the `Clock`. Use it to pick the version of every report, unsolicited ones included, and skip leaves while it runs. Or drop the IGMPv1 claim from the README.
