# 249. NeighborCache::insert accepts a hardware address of the wrong medium, and egress then panics

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/neighbor.rs:355](../src/neighbor.rs#L355), [src/stack.rs:2710](../src/stack.rs#L2710), [src/stack.rs:2727](../src/stack.rs#L2727) |
| Features | default (needs both `medium-ethernet` and `medium-ieee802154`) |
| Verification | reproduced with a test |

## Summary
The public `NeighborCache::insert` only checks that both addresses are unicast. It does not check that the hardware address kind matches the interface's medium. An 802.15.4 address inserted for an Ethernet interface, or the reverse, makes the next send to that neighbor panic. The docs of `insert` list only `NotUnicast` and no panic.

## Details
src/neighbor.rs:355 `insert` checks `!addr.is_unicast() || !hardware_addr.is_unicast()` and nothing else.

src/stack.rs:2710:
```rust
self.transmit_ethernet(iface, hardware_addr.ethernet_or_panic(), buf, ethertype)
```
src/stack.rs:2727:
```rust
self.dispatch_ieee802154(iface, hardware_addr.ieee802154_or_panic(), buf)
```
`flush_pending` goes through `transmit_link`, which matches on the address kind and has the same problem.

## Failure scenario
An app with Ethernet and 802.15.4 interfaces pre-populates neighbor entries and passes the wrong `IfaceHandle` for one. `insert` returns `Ok`. The next packet to that IP panics the stack.

## Reproduction
Stack test harness (`stack::test`):
```rust
#[test]
#[cfg(all(feature = "ipv4", feature = "medium-ethernet", feature = "medium-ieee802154"))]
#[should_panic]
fn lo4_neighbor_insert_wrong_medium_panics() {
    let (mut stack, _rx, _tx) = test_stack(Medium::Ethernet);
    stack.neighbor_cache_mut().insert(IfaceHandle::new(0), REMOTE_V4.into(), HardwareAddress::Ieee802154(Ieee802154Address::Extended([2; 8])), Instant::from_secs(100)).unwrap();
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    let _ = stack.udp_socket(h).send_slice(b"hi", (REMOTE_V4, 1000));
}
```
Output: `panicked at src/wire/mod.rs:344:18: hardware address is not an Ethernet address`.

## Suggested fix
Reject a medium mismatch in `insert` with a new error, and document it. Or treat a mismatched entry as not found on lookup.
