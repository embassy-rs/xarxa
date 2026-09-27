# 245. UDP datagrams sent while resolved-but-parked packets wait for device room overtake them

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:2709](../src/stack.rs#L2709), [src/stack.rs:2404](../src/stack.rs#L2404), [src/stack.rs:2512](../src/stack.rs#L2512) |
| Features | default |
| Verification | reproduced with a test |

## Summary
When a neighbor resolves while the device is busy, `flush_pending` leaves the parked packets in the queue for the next poll. A UDP send before that poll finds the entry Reachable and the device ready, and transmits at once, ahead of the older packets. DESIGN §6 says the flush is FIFO.

## Details
`flush_pending` (src/stack.rs:2404) stops at the first `can_transmit_new_packet()` error. `dispatch_ip` transmits directly on `Found` (src/stack.rs:2709):
```rust
NeighborLookup::Found(hardware_addr) => {
    self.transmit_ethernet(iface, hardware_addr.ethernet_or_panic(), buf, ethertype)
}
```
Neither it nor `lookup_hardware_addr` checks `pending.has_matching(key)`. In embassy-net the application can run between the driver freeing room and the runner polling.

## Failure scenario
The app sends A, B, C to an unresolved neighbor. All park. The ARP reply arrives while the TX ring is full. The ring drains, and the app sends D before the next poll. Wire order: D, A, B, C.

## Reproduction
Test in `src/stack.rs` `mod test`, scratch copy of HEAD. The resolution is installed with `NeighborCache::insert` while the device has no room, which is the same state as an ARP reply arriving then.
```rust
#[test]
#[cfg(all(feature = "ipv4", feature = "medium-ethernet"))]
fn lo4_fifo_overtake() {
    let (mut stack, _rx, tx, room) = test_stack_with_room(Medium::Ethernet);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    for p in [b"A", b"B", b"C"] { stack.udp_socket(h).send_slice(p, (REMOTE_V4, 1000)).unwrap(); }
    tx.borrow_mut().clear();
    room.set(Some(0));
    stack.neighbor_cache_mut().insert(IfaceHandle::new(0), REMOTE_V4.into(), HardwareAddress::Ethernet(EthernetAddress([2,0,0,0,0,2])), Instant::from_secs(100)).unwrap();
    stack.poll(Instant::ZERO);
    assert!(tx.borrow().is_empty());
    room.set(Some(10));
    stack.udp_socket(h).send_slice(b"D", (REMOTE_V4, 1000)).unwrap();
    stack.poll(Instant::ZERO);
    let order: Vec<u8> = tx.borrow().iter().map(|f| *f.last().unwrap()).collect();
    assert_eq!(order, b"DABC");
}
```
Output:
```
order "DABC"
test stack::test::lo4_fifo_overtake ... ok
```

## Suggested fix
In `dispatch_ip`, when the lookup is `Found` but packets are still parked on the key, flush them first while there is room, or park the new packet behind them.
