# 215. Route expiry and address deprecation are checked against the last poll's time

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:372](../src/stack.rs#L372), [src/stack.rs:303](../src/stack.rs#L303), [src/stack.rs:312](../src/stack.rs#L312), [src/stack.rs:1224](../src/stack.rs#L1224), [src/route.rs:292](../src/route.rs#L292), [src/iface/mod.rs:230](../src/iface/mod.rs#L230), [src/iface/slaac.rs:303](../src/iface/slaac.rs#L303), [DESIGN.md:765](../DESIGN.md#L765) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Between polls, `TxContext::route` and source selection use `self.inner.now`, the last poll's time. Neither route `expires_at` nor address `preferred_until` counts toward the poll deadline, so an idle stack can go a day without polling. In that window an expired route is still used, and a deprecated SLAAC address is still treated as preferred. A TCP connect or connected UDP bind can pin the deprecated address for the life of the socket.

## Details
src/stack.rs:372
```rust
let route = self.inner.routes.lookup(binding, dst_addr, self.inner.now)?;
```
src/stack.rs:303 and 312 pass `self.inner.now` to `get_source_address`, which reaches RFC 6724 rule 3 and src/iface/mod.rs:230:
```rust
self.preferred_until.is_none_or(|until| until > now)
```
src/stack.rs:1224
```rust
// Expired routes go. That isn't due at any particular time, so it doesn't
// count toward the deadline: a lookup checks the expiry itself.
self.inner.routes.remove_expired(clock.now());
```
SLAAC counts only `valid_until` (src/iface/slaac.rs:303-317). The public doc of `Route::expires_at` says removal happens at the next poll, so it is consistent. What the behavior contradicts is the comment above and DESIGN.md:765 ("a lookup between two polls is still exact").

## Failure scenario
- A temporary route expires after 10 minutes. The idle stack's deadline is a day away. Half an hour later a UDP send behind it returns Ok and goes to the gateway, where it should fail with `Unaddressable`.
- A SLAAC address's preferred lifetime runs out between polls. The next connect picks it over a preferred address and keeps it until close.

## RFC reference
RFC 4862 §5.5.4: "A deprecated address SHOULD continue to be used as a source address in existing communications, but SHOULD NOT be used to initiate new communications if an alternate (non-deprecated) address of sufficient scope can easily be used instead."

RFC 6724 §5 Rule 3: "If one of the two source addresses is 'preferred' and one of them is 'deprecated' (in the RFC 4862 sense), then prefer the one that is 'preferred'."

## Reproduction
Test in the `stack` module test harness (`cargo test --lib vg2_ -- --nocapture`). The deprecated-address case follows the same mechanism and was not re-run by the verifier.
```rust
#[test]
fn vg2_route_expired_between_polls() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let route = crate::route::Route { expires_at: Some(Instant::from_secs(10)), ..crate::route::Route::new_ipv4_gateway(Ipv4Addr::new(192,168,1,254), IfaceHandle::new(0)) };
    stack.routes_mut().add(route).unwrap();
    let d = stack.poll(Instant::ZERO);
    std::println!("deadline {:?}", d);
    let h = stack.add_udp_socket().unwrap();
    stack.udp_socket(h).bind(5000, 0u16).unwrap();
    tx.borrow_mut().clear();
    let r = stack.udp_socket(h).send_slice(b"x", (Ipv4Addr::new(8,8,8,8), 1000));
    std::println!("before poll: {:?} sent {}", r, tx.borrow().len());
    stack.poll(Instant::from_secs(3600));
    let r = stack.udp_socket(h).send_slice(b"x", (Ipv4Addr::new(8,8,8,8), 1000));
    std::println!("after poll: {:?}", r);
}
```
Output:
```
deadline Instant { millis: 86400000 }
before poll: Ok(()) sent 1
after poll: Err(Unaddressable)
```

## Suggested fix
The stack can't know the time between polls, so either count route `expires_at` and address `preferred_until` toward the poll deadline (`clock.expired` in `Routes::remove_expired`, a pass over `preferred_until` in poll), or document that expiries take effect at the first poll after them and fix the comment at src/stack.rs:1224 and DESIGN.md:765.
