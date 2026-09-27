# 021. `DnsClient::poll` docs say to call it again at its deadline, but it uses the last `Stack::poll` time, so doing only that busy-loops

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/dns.rs:349](../src/dns.rs#L349), [src/dns.rs:9](../src/dns.rs#L9), [src/dns.rs:526](../src/dns.rs#L526) |
| Features | default (`dns`) |
| Verification | reproduced with a test |

## Summary

`DnsClient::poll` takes its time from `stack.inner.now`, which only `Stack::poll` advances. The module docs and the method docs say to call it "again when that deadline arrives". A caller that does exactly that, without calling `Stack::poll` first, sees no time pass. It gets the same deadline back, now in the past, and spins at 100% CPU with no retransmission or server rotation.

## Details

src/dns.rs:9-10:

```rust
//! - Call [`DnsClient::poll`] after every [`Stack::poll`], and again when the
//!   deadline it returns arrives.
```

src/dns.rs:351-356:

```rust
    /// Uses the time of the last `Stack::poll`.
    ///
    /// Returns the next time `poll` should be called to retransmit a query or try
    /// the next server, or one day after the last `Stack::poll` if no query is
    /// pending. It is always later than the time of the last `Stack::poll`. Call
    /// it after every [`Stack::poll`], and again when that deadline arrives.
```

src/dns.rs:526-527:

```rust
        let now = stack.inner.now;
        let mut clock = Clock::new(now);
```

src/dns.rs:578-582:

```rust
                if !clock.expired(pq.retransmit_at) {
                    // query is waiting for retransmit
                    clock.schedule(timeout);
                    continue;
                }
```

With `now` stuck at the last `Stack::poll`, `clock.expired(pq.retransmit_at)` stays false. The returned deadline is the same `retransmit_at` (set with `clock.after(pq.delay)` at line 626) every time. The doc does say "Uses the time of the last `Stack::poll`", but never says that `Stack::poll` must run before `DnsClient::poll` at the DNS deadline. `examples/dns.rs:78-93` works only because it always calls `stack.poll(now)` first and takes the `.min()` of both deadlines.

## Failure scenario

The app runs DNS in its own task:

```rust
loop {
    let d = dns.poll(&mut stack);
    timer_at(d).await;
}
```

The network task polls the stack only on driver wakeups and at the stack's own deadline, which is one day on an idle stack. Once the first retransmit deadline passes, the DNS task spins. No retransmission or server rotation happens until the network task next polls, which can be up to a day.

## Reproduction

Test in `src/stack.rs` `mod test`, scratch copy of the crate:

```rust
#[test]
#[cfg(all(feature = "dns", feature = "medium-ip", feature = "ipv4"))]
fn v_dns_poll_alone_at_deadline_spins() {
    use crate::dns::DnsClient;
    use crate::wire::dns::Type;
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
    dns.start_query(&mut stack, "example.com", Type::A).unwrap();
    let sd = stack.poll(Instant::ZERO);
    let d1 = dns.poll(&mut stack);
    assert_eq!(tx.borrow().len(), 1);
    let d2 = dns.poll(&mut stack);
    let d3 = dns.poll(&mut stack);
    std::println!("stack deadline {:?}, dns deadlines {:?} {:?} {:?}, sent {}", sd, d1, d2, d3, tx.borrow().len());
    assert_eq!(d1, d2);
    assert_eq!(d2, d3);
    assert_eq!(tx.borrow().len(), 1);
}
```

Output:

```
stack deadline Instant { millis: 86400000 }, dns deadlines Instant { millis: 1000 } Instant { millis: 1000 } Instant { millis: 1000 }, sent 1
test ok
```

## Suggested fix

Either:
- Document that `Stack::poll` must be called before `DnsClient::poll` when the DNS deadline arrives, so the caller should merge the DNS deadline into the stack loop with `.min()` as the example does.
- Or have `DnsClient::poll` take `now` itself.
