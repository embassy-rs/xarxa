# 120. Two concurrent queries with the same random txid: a response for one blocks the other

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/dns.rs:282](../src/dns.rs#L282), [src/dns.rs:407](../src/dns.rs#L407) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Txids are drawn with no uniqueness check among pending queries. `process()` stops at the first pending query with a matching txid. A response meant for a later query with the same txid is never matched to it, and that query fails after every server times out.

## Details
src/dns.rs:282:
```rust
let txid = stack.inner.rand.rand_u16();
```
src/dns.rs:409-439 (abridged):
```rust
if p.transaction_id() != pq.txid {
    continue;
}
matched = true;
if p.rcode() == Rcode::NXDomain {
    q.set_state(State::Failure);
    continue;
}
...
if question.type_ != pq.type_ {
    break;
}
match name_eq(&p, question.name, &pq.name) {
    Ok(false) => { break; }
```
A question type or name mismatch does `break` (lines 426, 432, 439, 443), not `continue`. So later queries with the same txid are never looked at. On NXDOMAIN the code does `continue`, so both queries fail. The collision odds are the birthday rate, about 6/65536 for 4 concurrent queries.

## Failure scenario
A and AAAA lookups for one host start together and draw the same txid. Every response for the second one stops at the first. It retransmits, gets the same answer, is blocked again, and fails after 10 s per server although every server answered.

## Suggested fix
Redraw the txid while it collides with a pending query. Also `continue` to the next query on a question mismatch instead of `break`.
