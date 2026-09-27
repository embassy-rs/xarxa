# 102. IGMPv2 queries have their Max Resp Time decoded with the IGMPv3 floating-point encoding, so reports come late or never

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/wire/igmp.rs:169](../src/wire/igmp.rs#L169), [src/wire/igmp.rs:100](../src/wire/igmp.rs#L100), [src/wire/igmp.rs:145](../src/wire/igmp.rs#L145), [src/multicast.rs:444](../src/multicast.rs#L444), [src/multicast.rs:469](../src/multicast.rs#L469), [src/multicast.rs:480](../src/multicast.rs#L480) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`max_resp_code_to_duration` applies the RFC 3376 exponential decoding to codes >= 128. `process_igmp` uses it for every query, including 8-byte IGMPv2 queries, where the field is a linear count of 1/10 s. A v2 querier configured for 20 s (code 200) is read as 307.2 s. Since each general query restarts the report schedule, a querier with the default 125 s Query Interval gets no report at all for a single group.

## Details

src/wire/igmp.rs:169:

```rust
fn max_resp_code_to_duration(value: u8) -> Duration {
    let value: u32 = value.into();
    let decisecs = if value < 128 {
        value
    } else {
        let mant = value & 0xF;
        let exp = (value >> 4) & 0x7;
        (mant | 0x10) << (exp + 3)
    };
    Duration::from_millis(decisecs * 100)
}
```

src/multicast.rs:444 calls it through `IgmpPacket::max_resp_time` (src/wire/igmp.rs:100) with no length check. The version is picked only by `max_resp_code() == 0`. xarxa is an IGMPv1/v2 host, so every query it acts on should use the v2 meaning.

For a general query, the interval is `max_resp_time / (groups + 1)`, and src/multicast.rs:469 unconditionally overwrites the schedule:

```rust
self.multicast.igmp_report_state = IgmpReportState::ToGeneralQuery {
    version,
    timeout: inner.now + interval,
    interval,
    next_index: 0,
};
```

With one group and code 200 the report is due at 153.6 s. The next query at 125 s resets it, so it never goes out. With N groups, only those scheduled before the next query are sent.

For a group-specific query, src/multicast.rs:480 uses `max_resp_time / 4`. Code 200 gives 76.8 s instead of 5 s.

The public wire docs contradict each other. `Packet` is documented as an IGMP v1/v2 packet ([RFC 2236]). `max_resp_time` and `set_max_resp_time` (src/wire/igmp.rs:145) use the RFC 3376 encoding. `set_max_resp_time` encodes 12.8 s and more in a form a v2 receiver misreads.

Only queriers with Max Resp Time >= 12.8 s are affected. The default is 10 s (code 100).

## Failure scenario

1. A router is set to `ip igmp query-max-response-time 20`. It sends 8-byte v2 general queries with code 200 every 125 s.
2. The host joins one group. Each query schedules the report at +153.6 s, and the next query cancels it.
3. No report is sent. After the Group Membership Interval (2*125+20 = 270 s) the router or snooping switch prunes the group and multicast delivery stops.

## RFC reference

RFC 2236 §2.2:

> The Max Response Time field is meaningful only in Membership Query messages, and specifies the maximum allowed time before sending a responding report in units of 1/10 second.

RFC 3376 §7.1:

> IGMPv2 Query: length = 8 octets AND Max Resp Code field is non-zero
> IGMPv3 Query: length >= 12 octets

RFC 3376 §4.1.1 defines the floating-point form for the IGMPv3 Max Resp Code only. RFC 3376 obsoletes RFC 2236, but §7.1 keeps the v2 query format.

## Reproduction

Tests in `mod test` of src/multicast.rs, in a scratch copy of HEAD:

```rust
#[test]
fn v5_igmpv2_max_resp_time_decoding() {
    let medium = Medium::Ethernet;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    let group = Ipv4Addr::new(224, 0, 0, 22);
    stack.iface(IFACE).join_multicast_group(group).unwrap();
    stack.poll(Instant::ZERO); tx.borrow_mut().clear();
    let mut query = igmp_packet(REMOTE_V4, IPV4_MULTICAST_ALL_SYSTEMS, IgmpMessage::MembershipQuery, Duration::from_secs(1), Ipv4Addr::UNSPECIFIED);
    { let mut igmp = IgmpPacket::new_unchecked(&mut query[IPV4_HEADER_LEN..]); igmp.set_max_resp_code(200); igmp.fill_checksum(); }
    let deadline = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, Instant::ZERO);
    assert_eq!(deadline, Instant::from_secs(10)); // 20 s / 2 intervals
}

#[test]
fn v5_igmpv2_periodic_queries_never_answered() {
    let medium = Medium::Ethernet;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    stack.iface(IFACE).join_multicast_group(Ipv4Addr::new(224, 0, 0, 22)).unwrap();
    stack.poll(Instant::ZERO); tx.borrow_mut().clear();
    let mut total = 0;
    for i in 0..5u32 {
        let now = Instant::from_secs(125 * i);
        let mut query = igmp_packet(REMOTE_V4, IPV4_MULTICAST_ALL_SYSTEMS, IgmpMessage::MembershipQuery, Duration::from_secs(1), Ipv4Addr::UNSPECIFIED);
        { let mut igmp = IgmpPacket::new_unchecked(&mut query[IPV4_HEADER_LEN..]); igmp.set_max_resp_code(200); igmp.fill_checksum(); }
        let mut d = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv4, query, now);
        let next = Instant::from_secs(125 * (i + 1));
        while d < next { d = stack.poll(d); }
        let n = recv_igmp(medium, &tx).len();
        println!("query {} at {:?}: {} reports before next query", i, now, n);
        total += n;
    }
    assert!(total > 0, "no report sent in 625 s of 125 s-periodic v2 queries");
}
```

`cargo test --lib v5_igmpv2 -- --nocapture`:

```
v5_igmpv2_max_resp_time_decoding: assertion failed, left: Instant { millis: 153600 }, right: Instant { millis: 10000 }
query 0 at Instant { millis: 0 }: 0 reports before next query
query 1 at Instant { millis: 125000 }: 0 reports before next query
query 2 at Instant { millis: 250000 }: 0 reports before next query
query 3 at Instant { millis: 375000 }: 0 reports before next query
query 4 at Instant { millis: 500000 }: 0 reports before next query
panicked: no report sent in 625 s of 125 s-periodic v2 queries
```

## Suggested fix

- Decode the field by message length in `process_igmp`: linear 1/10 s for 8-byte queries, the RFC 3376 float form only for 12 octets or more.
- Make `max_resp_time` / `set_max_resp_time` linear for the v1/v2 `Packet`, or document which encoding they use.
- Optionally, don't push back a pending report that is already due sooner than the new query's schedule (RFC 2236 §3 only resets a timer when the new one is shorter).
