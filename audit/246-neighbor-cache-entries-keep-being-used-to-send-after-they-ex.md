# 246. Neighbor cache entries keep being used to send after they expire, until the next poll

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/stack.rs:2512](../src/stack.rs#L2512), [src/neighbor.rs:242](../src/neighbor.rs#L242), [src/neighbor.rs:342](../src/neighbor.rs#L342), [DESIGN.md:765](../DESIGN.md#L765) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Egress between polls looks up the neighbor cache with `StackInner::now`, the last poll's time. A Reachable entry whose expiry passed after that poll is still `Found`, so sends go to the old MAC with no new ARP/NS. The Reachable expiry does not count toward the poll deadline, so on an idle stack this window can be a day long. This contradicts the public `NeighborCache::insert` doc and DESIGN.md.

## Details
src/stack.rs:2512:
```rust
match self.neighbor_cache.lookup(&(iface.handle, next_hop), self.now) {
```
src/neighbor.rs:242:
```rust
/// An expiry doesn't count toward the deadline: nothing is due then, a lookup
```
Public doc, src/neighbor.rs:342: "`expires_at` is when the entry stops being used."

DESIGN.md:765: "The expiries are compared at use too, so a lookup between two polls is still exact". DESIGN §6 says a Stale entry is "not used to send".

The public `NeighborCache::get` doc does say an expired entry stays `Reachable` until the next poll. It does not say the entry is still used to send.

## Failure scenario
An app sends a UDP report every 10 minutes and nothing else polls in between. Each send uses the MAC from before, past its 60 s lifetime, without re-resolving. If the IP moved to another host, the datagram goes to the wrong machine and `send` returns `Ok`. Hand-inserted entries are also used past the `expires_at` the caller gave.

## Reproduction
Test in `src/stack.rs` `mod test`, scratch copy of HEAD:
```rust
#[test]
fn vg2_neighbor_expired_between_polls() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ethernet);
    stack.neighbor_cache_mut().insert(IfaceHandle::new(0), REMOTE_V4.into(), HardwareAddress::Ethernet(EthernetAddress([2,0,0,0,0,2])), Instant::from_secs(60)).unwrap();
    let d = stack.poll(Instant::from_secs(1));
    std::println!("deadline {:?}", d);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(5000, 0u16).unwrap();
    tx.borrow_mut().clear();
    stack.udp_socket(h).send_slice(b"x", (REMOTE_V4, 1000)).unwrap();
    std::println!("before poll: frame {:02x?}", &tx.borrow()[0][..14]);
    tx.borrow_mut().clear();
    stack.poll(Instant::from_secs(3600));
    tx.borrow_mut().clear();
    stack.udp_socket(h).send_slice(b"x", (REMOTE_V4, 1000)).unwrap();
    std::println!("after poll: frame {:02x?}", &tx.borrow()[0][..14]);
}
```
Output:
```
deadline Instant { millis: 86401000 }
before poll: frame [02, 00, 00, 00, 00, 02, 02, 00, 00, 00, 00, 01, 08, 00]
after poll: frame [ff, ff, ff, ff, ff, ff, 02, 00, 00, 00, 00, 01, 08, 06]
test stack::test::vg2_neighbor_expired_between_polls ... ok
```
The send "1 hour" later, with no poll, went straight to the cached MAC.

## Suggested fix
Count the Reachable expiry toward the deadline in `NeighborCache::expire` (use `clock.expired`), so a poll happens at expiry and turns the entry Stale. Or document that expiry takes effect at the first poll after it, and fix the `insert` doc and DESIGN.md:765.
