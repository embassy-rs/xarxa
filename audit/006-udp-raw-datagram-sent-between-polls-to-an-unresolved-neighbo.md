# 006. UDP/raw datagram sent between polls to an unresolved neighbor is dropped at the next poll

| | |
|---|---|
| Severity | high |
| Category | correctness |
| Location | [src/neighbor.rs:492](../src/neighbor.rs#L492), [src/neighbor.rs:186](../src/neighbor.rs#L186), [src/stack.rs:2522](../src/stack.rs#L2522), [src/stack.rs:2714](../src/stack.rs#L2714), [src/stack.rs:2731](../src/stack.rs#L2731), [src/stack.rs:1218](../src/stack.rs#L1218), [src/udp.rs:794](../src/udp.rs#L794) |
| Features | default |
| Verification | reproduced with a test |

## Summary

Socket sends run between polls. They stamp the parked packet (`expires_at = now + 5 s`) and the new Incomplete neighbor entry (`retrans_at = now + 1 s`) with `StackInner::now`, which is the time of the last poll. If the stack has been idle for more than 5 s, the parked datagram is already expired when it is queued. The next poll sends a second solicitation right away and then purges the datagram, before the reply can arrive. `send_slice` returned `Ok`.

## Details

`StackInner::now` is only updated at the top of `Stack::poll`.

src/stack.rs:1071
```rust
self.inner.now = timestamp;
```

A send to an unresolved neighbor starts resolution and parks the packet with that time.

src/stack.rs:2522
```rust
self.neighbor_cache.start_resolution((iface.handle, next_hop), self.now);
```

src/stack.rs:2714 (Ethernet) and src/stack.rs:2731 (802.15.4)
```rust
self.pending.push((iface.handle, next_hop), buf, self.now);
```

src/neighbor.rs:489-493
```rust
let packet = PendingPacket {
    key,
    buf,
    expires_at: timestamp + PENDING_QUEUE_LIFETIME,
};
```

src/neighbor.rs:189-195
```rust
self.insert_state(
    key,
    State::Incomplete {
        probes_sent: 1,
        retrans_at: timestamp + RETRANS_TIMER,
    },
);
```

An idle stack returns a deadline one day away (`MAX_POLL_DELAY`), so `self.now` can be up to a day old at send time. Neighbor entries go Stale after 60 s, so any send after a minute of quiet needs a new resolution. On the next poll:

- `poll_neighbor_timers` finds `timestamp >= retrans_at` (src/neighbor.rs:221) and sends a second solicitation immediately.
- `self.inner.pending.purge_expired(&mut clock)` (src/stack.rs:1218) runs at the end of the poll, finds `expires_at` in the past, and drops the parked packet.

The reply arrives a few ms later. The cache fills, but there is nothing left to flush. The resolution window also shrinks from about 3 s to about 2 s.

This contradicts the `UdpSocket::send_with` doc (src/udp.rs:794-796): "If the destination's neighbor is unresolved, the packet is queued inside the stack and sent when resolution completes. This still counts as a successful send." It also contradicts DESIGN.md §7: "`Ok` means the packet is in the device or parked on a neighbor resolution; it is never dropped on the way there."

Affected: UDP sends, raw sends in IP and Ethernet mode, over ARP and NDISC. TCP is not affected, since its egress runs inside `poll` with a fresh time.

## Failure scenario

1. Ethernet interface, no DHCP. `poll(0)` returns a deadline of 86400 s.
2. At t = 10 s the application calls `udp.send_slice(b"one", (192.168.1.2, 1000))` with the peer unresolved. It returns `Ok`. An ARP request goes out and the packet is parked with `expires_at = 5 s`.
3. The runner polls at t = 10 s. A second ARP request goes out at once and the parked packet is purged.
4. The ARP reply arrives at t = 10.002 s. The datagram is never sent.

A sensor that wakes every few minutes to send one datagram loses the first datagram after every idle period, silently.

## RFC reference

The immediate second solicitation breaks per-neighbor rate limiting.

RFC 4861 §7.2.2: "Retransmissions MUST be rate-limited to at most one solicitation per neighbor every RetransTimer milliseconds."

RFC 4861 §7.3.3: "A node MUST NOT send Neighbor Solicitations to the same neighbor more frequently than once every RetransTimer milliseconds."

## Reproduction

Added to the `mod test` of src/stack.rs in a scratch copy:

```rust
#[test]
fn verify_stale_now_drops_parked() {
    let (mut stack, rx, tx, _room) = test_stack_with_room(Medium::Ethernet);
    let remote_hw = EthernetAddress([0x02, 0, 0, 0, 0, 0x02]);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let d = stack.poll(Instant::ZERO);
    println!("deadline after idle poll: {:?}", d);
    assert!(stack.udp_socket(udp).send_slice(b"one", (REMOTE_V4, 1000)).is_ok());
    stack.poll(Instant::from_secs(10));
    rx.borrow_mut().push_back(arp_request_from(remote_hw, REMOTE_V4));
    stack.poll(Instant::from_millis(10_002));
    stack.poll(Instant::from_millis(10_003));
    let kinds: Vec<_> = tx.borrow().iter().map(|f| ethertype_of(f)).collect();
    println!("tx: {:?}", kinds);
    assert!(
        tx.borrow().iter().any(|f| ethertype_of(f) == EthernetProtocol::Ipv4 && f.ends_with(b"one")),
        "parked datagram lost"
    );
}
```

`cargo test --lib stack::test::verify_ -- --nocapture`:

```
deadline after idle poll: Instant { millis: 86400000 }
tx: [Arp, Arp, Arp]
panicked: parked datagram lost
```

## Suggested fix

Don't stamp deadlines with a time that may be stale. Options:

- Mark pending and Incomplete entries created outside a poll, and set `expires_at` and `retrans_at` from `clock.now()` at the start of the next poll, before `poll_neighbor_timers`.
- Have the send APIs take the current time.

At the least, document that `poll` must run with the current time right before a send.
