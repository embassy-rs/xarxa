# 265. A TCP transmit buffer over 2 GiB makes every incoming ACK panic in sequence arithmetic

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/tcp/mod.rs:1056](../src/tcp/mod.rs#L1056), [src/wire/tcp.rs:37](../src/wire/tcp.rs#L37), [src/stack.rs:879](../src/stack.rs#L879) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The receive buffer size is checked and documented (1 GiB max). The transmit buffer size is not. On a target with a usize wider than 32 bits, a socket whose tx buffer holds more than `i32::MAX` bytes panics on the next ACK, because `SeqNumber + usize` panics for rhs > `i32::MAX`.

## Details
src/tcp/mod.rs:1052
```rust
let unacknowledged = self.tx_buffer.len() + control_len;
...
let ack_max = self.local_seq_no + unacknowledged;
```
src/wire/tcp.rs:37 panics with "attempt to add to sequence number with unsigned overflow" when rhs > `i32::MAX`. The `add_tcp_socket` docs (src/stack.rs:879, 908) list only the receive buffer limit. Other places that add `tx_buffer.len()` to a sequence number would hit the same panic.

## Failure scenario
A hosted server calls `add_tcp_socket(rx, 3 << 30)` and queues 3 GiB. The first ACK processed panics the stack.

## Suggested fix
Reject tx capacities above 1 GiB (or `i32::MAX`) at socket creation and document it, like the rx check.
