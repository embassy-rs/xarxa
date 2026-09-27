# 301. A UDP/raw sender blocked by DeviceBusy is not woken when routing moves away from that interface

| | |
|---|---|
| Severity | low |
| Category | missed-wake |
| Location | [src/udp.rs:912](../src/udp.rs#L912), [src/raw.rs:548](../src/raw.rs#L548), [src/raw.rs:607](../src/raw.rs#L607), [src/stack.rs:1194](../src/stack.rs#L1194), [src/stack.rs:795](../src/stack.rs#L795) |
| Features | default (`async`) |
| Verification | confirmed against the code |

## Summary
`tx_blocked_on` records the egress interface of the failed send. The send waker is woken only when that interface has room, on `close()`, or on `remove_iface`. Route or address changes wake no sockets. A sender blocked on a stuck interface stays asleep after the destination moves to another interface or becomes unroutable.

## Details
src/udp.rs:907-914:
```rust
if self.tx.can_transmit(route.iface).is_err() {
    #[cfg(feature = "async")]
    {
        self.inner_mut().tx_blocked_on = Some(route.iface);
    }
    return Err(SendError::DeviceBusy);
}
```
Raw does the same at src/raw.rs:548 and src/raw.rs:607. The clears are src/udp.rs:608 (close), src/raw.rs:327, `remove_iface` (src/stack.rs:763-771), and the end of poll (src/stack.rs:1194, 1203), gated on `can_transmit_new_packet().is_ok()` for that same interface. `routes_mut` (src/stack.rs:795) just returns `&mut Routes`. DHCP/SLAAC installs, address removal and route expiry don't touch socket wakers.

## Failure scenario
Two interfaces, default route via eth0. eth0's driver stops draining while the carrier is down. A UDP send returns `DeviceBusy` and the task waits with `tx_blocked_on = eth0`. The default route then switches to wlan0. A retry would succeed, but nothing wakes the sender until eth0 frees room. If the route is removed instead, a retry would return `Unaddressable`, but the sender keeps waiting.

## Suggested fix
On route or address changes, wake and clear every socket with `tx_blocked_on` set so it routes again. Spurious wakes are allowed.
