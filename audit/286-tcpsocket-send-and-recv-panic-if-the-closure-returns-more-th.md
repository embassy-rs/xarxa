# 286. TcpSocket::send and recv panic if the closure returns more than the slice length, and this is not documented

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2824](../src/tcp/mod.rs#L2824), [src/tcp/mod.rs:2880](../src/tcp/mod.rs#L2880), [src/tcp/ring_buffer.rs:193](../src/tcp/ring_buffer.rs#L193), [src/tcp/ring_buffer.rs:242](../src/tcp/ring_buffer.rs#L242) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`TcpSocket::send` and `recv` pass the user closure straight to `RingBuffer::enqueue_many_with` and `dequeue_many_with`, which assert that the returned size fits the slice. Only the private ring buffer documents the panic. The public docs list only error returns. CLAUDE.md asks for panics to be documented.

## Details
src/tcp/mod.rs:2824-2825:
```rust
pub fn send<'b, R>(&'b mut self, f: impl FnOnce(&'b mut [u8]) -> (usize, R)) -> Result<R, SendError> {
    self.send_impl(|tx_buffer| tx_buffer.enqueue_many_with(f))
```
src/tcp/ring_buffer.rs:190-193:
```rust
let max_size = self.contiguous_window();
let (size, result) = f(&mut self.storage[write_at..write_at + max_size]);
assert!(size <= max_size);
```
`recv` (mod.rs:2880) and ring_buffer.rs:242 have the same shape. The slice is the contiguous window, which is smaller than the free space when the ring wraps.

## Failure scenario
The app checks `send_capacity() - send_queue() >= 100`, then calls `send(|buf| { buf[..100.min(buf.len())].copy_from_slice(..); (100, ()) })`. When the free space wraps, `buf.len() < 100` and the stack panics.

## Suggested fix
Add a `# Panics` section to `send` and `recv`: "Panics if `f` returns a size larger than the slice it was given." Or clamp the returned size.
