# 063. Ingress drain in poll is unbounded: a sustained packet flood keeps poll from returning

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/stack.rs:1093](../src/stack.rs#L1093), [src/stack.rs:1047](../src/stack.rs#L1047) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`poll` drains each driver with `while let Some(buf) = driver.receive()` and no budget. If frames arrive faster than the stack processes them, the loop never ends. TCP dispatch, timers, the other interfaces and, in embassy, every other task on the executor starve for as long as the flood lasts.

## Details

src/stack.rs:1093:

```rust
while let Some(mut buf) = self.ifaces.get_mut(index).driver.receive() {
    ...
    self.process(handle, buf);
}
```

Only after this loop ends does `poll` go on to that interface's fragmenter, pending flush, link-state edge, DHCP, SLAAC and multicast. Then come the next interface (including its `poll_neighbor_timers`), TCP dispatch (src/stack.rs:1162), the socket wakes and the expiries.

Each processed frame gives its buffer back to the pool, so a DMA driver can always refill its ring. Nothing throttles the loop except the driver running dry. On 100 Mbit, minimum-size frames arrive every ~6.7 µs, about 1200 cycles at 180 MHz. Parsing, demux and building an ICMP error or ARP reply can take longer than that.

Interfaces are served in index order, so a flood on iface 0 also blocks RX and timers on iface 1.

The public doc (src/stack.rs:1047) says "Process all pending ingress packets on all ifaces", which is this behavior. So this is a design gap, not a doc mismatch. Linux (NAPI budget of 64) and lwIP bound this. README and DESIGN.md don't mention it.

Severity is medium: it needs a sustained on-link flood faster than per-frame processing, and during that the CPU is saturated anyway. A budget would keep TCP, timers, other interfaces and other tasks running. It would not make the flood free.

## Failure scenario

A host on the same Ethernet segment sends 64-byte UDP datagrams to a closed port at line rate. `Stack::poll` stays in the receive loop. Established TCP connections get no ACKs or retransmissions and time out at the peer. DHCP renewals are missed. A second interface is never serviced. Other embassy tasks on the same executor never run.

## Reproduction

Test added to the `stack.rs` test module in a scratch copy:

```rust
#[test]
fn zz_unbounded_rx() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    for _ in 0..200 {
        let dg = udp_datagram(REMOTE_V4.into(), 4000, OUR_V4.into(), 9, b"x");
        rx.borrow_mut().push_back(ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &dg));
    }
    stack.poll(Instant::ZERO);
    println!("frames left after one poll: {}", rx.borrow().len());
}
```

`cargo test --lib zz_ -- --nocapture`:

```
frames left after one poll: 0
```

One poll drained all 200 frames before doing anything else. A driver that refills faster than processing would never let it return.

## Suggested fix

Give each interface a per-poll RX budget, for example 32 to 64 frames or the driver's ring depth. When the budget runs out, go on with the rest of the poll and make sure the caller polls again soon, for example with a short `clock.after(..)` deadline like `POOL_RETRY_DELAY`. Consider round-robin between interfaces.
