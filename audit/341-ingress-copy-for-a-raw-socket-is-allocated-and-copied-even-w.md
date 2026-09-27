# 341. Raw socket ingress copy is allocated and copied even when the RX queue is full

| | |
|---|---|
| Severity | info |
| Category | performance |
| Location | [src/raw.rs:651](../src/raw.rs#L651), [src/raw.rs:705](../src/raw.rs#L705), [src/raw.rs:194](../src/raw.rs#L194) |
| Features | default (`raw-ethernet`, `raw-ip`) |
| Verification | confirmed against the code |

## Summary
When the stack also wants a packet, `copy_packet` takes a pool buffer and copies the whole packet before `rx_enqueue` finds the queue full and drops the copy. A raw socket that is not being read costs one allocation and one full memcpy per stack-handled packet received.

## Details
src/raw.rs:650-654 (and 704-708 in IP mode):
```rust
if stack_wants {
    if let Some(copy) = copy_packet(&buf) {
        socket.rx_enqueue(copy);
    }
```
`rx_enqueue` (src/raw.rs:194) drops the buffer when `push_back` fails. The copy also briefly takes a pool slot while a stalled reader already holds a full queue of buffers.

## Failure scenario
A raw IP sniffer socket whose reader stalls. Under a UDP or TCP flood every packet pays an extra allocation and copy for nothing.

## Suggested fix
Check `rx_queue.is_full()` before `copy_packet` and skip the copy when it is.
