# 296. peek() and recv() disagree while an ICMP error is pending, and can_recv() never reports one

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/udp.rs:718](../src/udp.rs#L718), [src/udp.rs:683](../src/udp.rs#L683), [src/udp.rs:663](../src/udp.rs#L663) |
| Features | default (`icmp-errors`) |
| Verification | confirmed against the code |

## Summary
`recv()` returns a pending ICMP error before any queued datagram. `peek()`/`peek_slice()` ignore the error and return the head datagram. So "peek, then recv" can return an error instead of the peeked datagram. `can_recv()` only checks the queue, so it never reports a pending error. No data is lost: the datagram comes back on the next `recv`.

## Details
src/udp.rs:663:
```rust
pub fn can_recv(&self) -> bool {
    !self.inner().rx_queue.is_empty()
}
```
src/udp.rs:683:
```rust
if let Some((error, remote)) = state.pending_error.take() {
    return Err(RecvError::IcmpError { error, remote });
}
```
`peek` (src/udp.rs:718) reads `rx_queue.front_mut()` only. Its doc says "Peek at the next received datagram without dequeueing it". The recv doc says the error "is reported before any queued datagram". Neither mentions the interaction. `process_icmp_error` wakes the RX waker, but a future that only checks `can_recv()` on an empty queue re-registers and never sees the error.

## Failure scenario
The app calls `peek_slice` to size the next datagram, allocates, then calls `recv_slice`. An ICMP error arrived in between, so it gets `Err(IcmpError)`. Code that assumes recv returns the peeked datagram mishandles it.

## Suggested fix
Make `peek`/`peek_slice` report the pending error like `recv`, or document the ordering on `peek`. Make `can_recv` return true when an error is pending, or document that it doesn't.
