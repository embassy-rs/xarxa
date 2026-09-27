# 298. Undocumented panics when a send/recv closure returns more than the slice it was given

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/udp.rs:820](../src/udp.rs#L820), [src/raw.rs:568](../src/raw.rs#L568), [src/tcp/ring_buffer.rs:193](../src/tcp/ring_buffer.rs#L193), [src/tcp/ring_buffer.rs:242](../src/tcp/ring_buffer.rs#L242), [src/tcp/mod.rs:2824](../src/tcp/mod.rs#L2824), [src/tcp/mod.rs:2880](../src/tcp/mod.rs#L2880) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`UdpSocket::send_with`, `RawSocket::send_with`/`send_with_meta`, `TcpSocket::send` and `TcpSocket::recv` assert that the closure's returned size fits the slice. None of their public docs mention the panic. The internal `RingBuffer` methods document it, but they are not public.

## Details
src/udp.rs:819-820:
```rust
let size = f(&mut buf);
assert!(size <= max_size);
```
src/raw.rs:568 is the same. The raw doc has a Panics section (src/raw.rs:501-502), but it only covers a removed bound interface. `TcpSocket::send` reaches `enqueue_many_with` (src/tcp/ring_buffer.rs:193) and `TcpSocket::recv` reaches `dequeue_many_with` (src/tcp/ring_buffer.rs:242), both with `assert!(size <= max_size);`. Their docs (src/tcp/mod.rs:2818-2822, 2873-2879) list only errors. CLAUDE.md asks public docs to list panics the caller has to care about.

## Failure scenario
A closure returns the length of its own source message instead of the bytes it wrote into the slice. The firmware panics inside the stack.

## Suggested fix
Add a `# Panics` section to each method, or clamp and return an error.
