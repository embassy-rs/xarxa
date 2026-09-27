# 121. start_query sends nothing, and the DnsClient docs don't say to poll after it

| | |
|---|---|
| Severity | low |
| Category | hang-stall |
| Location | [src/dns.rs:291](../src/dns.rs#L291), [src/dns.rs:6](../src/dns.rs#L6) |
| Features | default (`dns`) |
| Verification | reproduced with a test |

## Summary
`start_query_raw` only records the query with `retransmit_at = stack.inner.now`. The first transmission happens in the next `DnsClient::poll`. The DnsClient docs don't say a new query needs a poll. A loop that computed its deadline before `start_query` sleeps until that deadline, which is one day on an idle stack.

## Details
src/dns.rs:291, inside the query added by `start_query_raw`:
```rust
retransmit_at: stack.inner.now,
```
Nothing is sent. The module usage list (src/dns.rs:6-11) says to call `DnsClient::poll` after every `Stack::poll` and at its deadline. It never mentions polling after starting a query. `register_query_waker` only fires on completion.

Mitigations, which is why this is low:
- The `Stack::poll` doc (src/stack.rs:1054-1055) says to poll after "an operation is done on the Stack", and `start_query` takes `&mut Stack`.
- embassy-net's `dns_query` returns `Wake` after `start_query` (embassy-net/src/lib.rs:414-415), so its runner polls right away.

So this is a documentation gap in xarxa's own DnsClient docs, not a stall in shipped integrations.

## Failure scenario
```rust
loop {
    let d = stack.poll(now).min(dns.poll(&mut stack));
    if want { q = dns.start_query(...) }
    wait_for_driver_or(d);
}
```
On an idle network the query goes out only when an unrelated packet arrives, or after one day.

## Reproduction
Test in `mod test` of src/stack.rs (scratch copy):
```rust
#[test]
#[cfg(all(feature = "dns", feature = "medium-ip", feature = "ipv4"))]
fn v_dns_start_query_not_sent_until_poll() {
    use crate::dns::DnsClient;
    use crate::wire::dns::Type;
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
    let d = stack.poll(Instant::ZERO).min(dns.poll(&mut stack));
    std::println!("idle deadline = {:?}", d);
    let _q = dns.start_query(&mut stack, "example.com", Type::A).unwrap();
    std::println!("sent after start_query: {}", tx.borrow().len());
    assert_eq!(tx.borrow().len(), 0);
    assert_eq!(d, Instant::from_secs(86400));
}
```
Output:
```
idle deadline = Instant { millis: 86400000 }
sent after start_query: 0
```

## Suggested fix
Document that `DnsClient::poll` must be called after `start_query`. Or send the first query from `start_query`, which already has `&mut Stack`.
