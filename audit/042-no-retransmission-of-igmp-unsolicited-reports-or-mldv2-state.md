# 042. IGMP and MLDv2 join/leave reports are sent once, and a join is lost for good if the pool is empty

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/multicast.rs:271](../src/multicast.rs#L271), [src/multicast.rs:290](../src/multicast.rs#L290), [src/multicast.rs:306](../src/multicast.rs#L306) |
| Features | default (`multicast`) |
| Verification | reproduced with a test |

## Summary

A join sends one report and moves the group to `Joined`. A leave sends one report and removes the group. Nothing retransmits them. The group is marked `Joined` even when no report was built (empty pool) or the device refused it. One lost report leaves the router or snooping switch with the wrong state until its next query.

## Details

src/multicast.rs:290
```rust
if let Some(pkt) = pkt {
    self.dispatch_ip(inner, pkt);
}
self.multicast.groups[i].1 = GroupState::Joined;
```

src/multicast.rs:306
```rust
if let Some(pkt) = pkt {
    self.dispatch_ip(inner, pkt);
}
// The last group moves into this slot, and is looked at next.
self.multicast.groups.swap_remove(i);
```

`igmp_report_packet` and `mldv2_report_packet` return `None` when `PacketBuf::try_new()` fails. `dispatch_ip` is best-effort, so a busy device drops the report the same way. There is no retransmission counter or timer, and the poll deadline right after a join is the idle one (1 day). The existing `test_handle_igmp` asserts exactly that.

## Failure scenario

- On Wi-Fi, multicast frames are not acknowledged. The host joins ff02::fb for mDNS behind an AP doing MLD snooping. The single report is lost. No mDNS traffic arrives until the next general query and our reply, up to 125 s by default.
- A lost leave (TO_IN{} or IGMP Leave) keeps the group flowing onto the link for the listener interval (260 s by default).
- The pool is empty at the poll that handles the join. The report is never built and the group is still marked `Joined`. Nothing is sent until a router query.

## RFC reference

RFC 3810 §6.1:
> To cover the possibility of the State Change Report being missed by one or more multicast routers, [Robustness Variable] - 1 retransmissions are scheduled, through a Retransmission Timer, at intervals chosen at random from the range (0, [Unsolicited Report Interval]).

RFC 2236 §3:
> To cover the possibility of the initial Membership Report being lost or damaged, it is recommended that it be repeated once or twice after short delays [Unsolicited Report Interval].

RFC 3810 states this as protocol behavior without a BCP 14 keyword. RFC 2236 only recommends it.

## Reproduction

Added to the `src/multicast.rs` test module in a scratch copy (abridged; the leave part counts reports over 5 polls the same way):

```rust
#[test]
fn verif_join_report_not_retransmitted() {
    let medium = Medium::Ip;
    let (mut stack, _rx, tx, _link) = test_stack(medium);
    stack.poll(Instant::ZERO);
    tx.borrow_mut().clear();
    let g4 = Ipv4Addr::new(239, 1, 2, 3);
    let g6 = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
    stack.iface(IFACE).join_multicast_group(g4).unwrap();
    stack.iface(IFACE).join_multicast_group(g6).unwrap();
    let mut t = Instant::ZERO;
    for _ in 0..5 {
        let d = stack.poll(t);
        let n = recv_all(medium, &tx).len();
        println!("poll at {:?}: {} packets, next deadline {:?}", t, n, d);
        t = t + Duration::from_millis(500);
    }
    // ... leave both groups, count reports over 5 polls ...
    let g4b = Ipv4Addr::new(239, 1, 2, 4);
    let mut hog = Vec::new();
    while let Some(b) = PacketBuf::try_new() { hog.push(b); }
    stack.iface(IFACE).join_multicast_group(g4b).unwrap();
    stack.poll(t);
    drop(hog);
    let mut total = 0;
    for _ in 0..5 {
        t = t + Duration::from_millis(500);
        stack.poll(t);
        total += recv_all(medium, &tx).len();
    }
    println!("reports after pool-starved join: {}", total);
    assert_eq!(total, 1, "join report lost for good");
}
```

Output:
```
poll at Instant { millis: 0 }: 2 packets, next deadline Instant { millis: 86400000 }
poll at Instant { millis: 500 }: 0 packets, next deadline Instant { millis: 86400500 }
poll at Instant { millis: 1000 }: 0 packets, ...
poll at Instant { millis: 1500 }: 0 packets, ...
poll at Instant { millis: 2000 }: 0 packets, ...
total join reports: 2
total leave reports: 2
reports after pool-starved join: 0
panicked: assertion `left == right` failed: join report lost for good (left: 0, right: 1)
```

## Suggested fix

Keep a per-group retransmission count (RV-1, RV=2 by default) and a deadline counted on the `Clock`. Resend TO_EX/TO_IN or the IGMP report at a random time in (0, 1 s]. When the report could not be built, keep the group in `Joining` (or `Leaving`) and retry, with the pool retry delay.
