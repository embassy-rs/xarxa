# 134. TunTapDriver and RawSocketDriver leave the frame in the kernel when the pool is empty, so the main loop spins

| | |
|---|---|
| Severity | low |
| Category | hang-stall |
| Location | [src/driver_impls/tuntap.rs:219](../src/driver_impls/tuntap.rs#L219), [src/driver_impls/raw_socket.rs:206](../src/driver_impls/raw_socket.rs#L206) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`receive()` returns `None` before reading when `PacketBuf::try_new()` fails. The frame stays queued and the fd stays readable, so `wait(fd, timeout)` returns at once on every loop iteration. The host main loop spins until a buffer is freed. DESIGN §3 says a driver drops the incoming frame on RX allocation failure.

## Details
src/driver_impls/tuntap.rs:218:
```rust
fn receive(&mut self) -> Option<PacketBuf> {
    let mut buf = PacketBuf::try_new()?;
    buf.set_len(buf.capacity());
    match self.recv(&mut buf[..]) {
```
raw_socket.rs:205-216 is identical. `wait` (src/driver_impls/mod.rs) is a `select` on readability. The examples loop on `deadline = stack.poll(now); wait(fd, Some(deadline - now))`.

Even with the frame dropped, a starved stack may return `POOL_RETRY_DELAY` (1 ms) deadlines, so the loop would wake every millisecond. It would no longer be a 100% spin.

## Failure scenario
The app holds received `RecvPacket`s in its own queue while a peer keeps sending, until all 16 pool buffers are taken. From then on `wait()` returns immediately and the loop burns a full CPU until the app releases its packets. If the release depends on a timer (e.g. the 60 s reassembly timeout), it spins that long.

## Suggested fix
When no buffer is available, read the frame into a small scratch buffer (or `recv` with `MSG_TRUNC` into 1 byte) and discard it.
