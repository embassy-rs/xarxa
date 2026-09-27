# 129. RawSocketDriver::can_transmit always returns true but transmit fails with EAGAIN

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/driver_impls/raw_socket.rs:229](../src/driver_impls/raw_socket.rs#L229), [src/driver_impls/raw_socket.rs:218](../src/driver_impls/raw_socket.rs#L218), [src/stack.rs:2761](../src/stack.rs#L2761) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The AF_PACKET socket is `SOCK_NONBLOCK`. When its send buffer is full, `send()` returns EAGAIN and `transmit` hands the buffer back, after `can_transmit` said `true`. That breaks the Driver contract. The stack drops the frame, so a UDP send that already returned `Ok` is lost.

## Details
xarxa-driver/src/lib.rs:256:
```rust
/// If this returns `true`, the next `transmit()` call must not fail.
```

src/driver_impls/raw_socket.rs:218:
```rust
fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
    match self.send(&buf) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
            debug!("phy: tx failed due to WouldBlock");
            Err(buf)
        }
        Err(err) => core::panic!("{}", err),
    }
}

fn can_transmit(&mut self) -> bool {
    true
}
```

src/stack.rs:2761:
```rust
if iface.driver.transmit(buf).is_err() {
    warn!("iface {}: device refused a frame, dropping it", iface.handle.index());
}
```

DESIGN §4 says socket data is never lost locally after `Ok`. With this driver it is, whenever the host device is slower than the app. There is also no waker, so a `false` from `can_transmit` would need `wait` to also wait for POLLOUT.

Unverified: when the qdisc drops, AF_PACKET `send` may return ENOBUFS, which hits the catch-all `panic!` arm instead of a drop.

`TunTapDriver` has the same shape (src/driver_impls/tuntap.rs:242), though a tap write rarely returns EAGAIN.

## Failure scenario
An app sends UDP as fast as `send_slice` allows over RawSocketDriver on a 100 Mbit NIC. Once the socket send buffer fills, `send()` returns EAGAIN, `transmit` returns `Err`, and stack.rs:2761 drops the datagram. The app got `Ok` for it.

## Suggested fix
Implement `can_transmit` with `poll(fd, POLLOUT, 0)`, and make `wait` wait for POLLOUT after a `false`. Or document that this driver does not keep the no-local-loss contract. Map ENOBUFS to `Err(buf)` instead of panicking.
