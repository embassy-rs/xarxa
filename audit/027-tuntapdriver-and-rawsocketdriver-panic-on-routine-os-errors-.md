# 027. TunTapDriver and RawSocketDriver panic on routine OS errors (interface down)

| | |
|---|---|
| Severity | medium |
| Category | panic |
| Location | [src/driver_impls/raw_socket.rs:214](../src/driver_impls/raw_socket.rs#L214), [src/driver_impls/raw_socket.rs:225](../src/driver_impls/raw_socket.rs#L225), [src/driver_impls/tuntap.rs:227](../src/driver_impls/tuntap.rs#L227), [src/driver_impls/tuntap.rs:238](../src/driver_impls/tuntap.rs#L238) |
| Features | default (`std`) |
| Verification | reproduced with a test |

## Summary

Both host drivers `panic!` on any read or write error other than `WouldBlock`. Taking the host interface down makes the next receive or transmit fail with ENETDOWN (AF_PACKET) or EIO (TAP write), and the whole program crashes. A TAP that `TunTapDriver::new` just created is down until the user brings it up, so the stack's first packets (RS, MLD report, DHCP discover, ARP) panic.

## Details

src/driver_impls/raw_socket.rs:213-214 (receive), and the same at src/driver_impls/tuntap.rs:226-227:

```rust
Err(err) if err.kind() == io::ErrorKind::WouldBlock => None,
Err(err) => core::panic!("{}", err),
```

src/driver_impls/raw_socket.rs:219-225 (transmit), and the same at src/driver_impls/tuntap.rs:232-238:

```rust
match self.send(&buf) {
    Ok(_) => Ok(()),
    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
        debug!("phy: tx failed due to WouldBlock");
        Err(buf)
    }
    Err(err) => core::panic!("{}", err),
}
```

The `Driver` contract lets `transmit` return `Err(buf)`, which the stack drops with a warning. Neither driver implements `link_state`, so the stack always sees `Up` and keeps transmitting while the interface is down.

Checked in an unprivileged user+net namespace (`unshare -rn`):

- AF_PACKET socket bound to a veth, after `ip link set down`: `recv` and `send` both return ENETDOWN.
- TAP fd written while the interface is down: EIO.

Not tested, but plausible from the same code: EMSGSIZE after the host MTU is lowered (the driver caches the MTU at `new()`), and ENOBUFS from AF_PACKET under qdisc pressure. Both panic the same way.

## Failure scenario

Run an example on `RawSocketDriver` bound to `eth0`, then `ip link set eth0 down` (or unplug a USB NIC). The next `Stack::poll` calls `receive()`, `recv` returns ENETDOWN, and the process panics with "Network is down".

## Reproduction

Added to `src/driver_impls/tuntap.rs` in a scratch copy:

```rust
#[cfg(test)]
mod verify_test {
    use super::*;
    use crate::driver::Driver;
    #[test]
    fn verify_tap_down_transmit_panics() {
        if std::env::var("VERIFY_NS").is_err() { return; }
        let mut d = TunTapDriver::new("tapv", HardwareAddress::Ethernet(crate::wire::EthernetAddress([2,0,0,0,0,1]))).unwrap();
        let mut buf = PacketBuf::try_new().unwrap();
        buf.set_len(42);
        buf[..6].copy_from_slice(&[0xff; 6]);
        let r = d.transmit(buf);
        println!("transmit returned ok={}", r.is_ok());
    }
}
```

`VERIFY_NS=1 unshare -rn <test binary> verify_tap_down --nocapture`:

```
panicked at src/driver_impls/tuntap.rs:238:25: Input/output error (os error 5)
```

A separate Python check under `unshare -rn` on a downed veth gave `recv err ENETDOWN` and `send err ENETDOWN` for AF_PACKET.

## Suggested fix

- `receive`: return `None` on any error, with a log line.
- `transmit`: drop the frame with a warning on errors other than `WouldBlock` (return `Ok(())` or `Err(buf)`).
- Implement `link_state` from SIOCGIFFLAGS (`IFF_UP`/`IFF_RUNNING`).

Related, not tested: `driver_impls::wait` uses `libc::FD_SET` ([src/driver_impls/mod.rs:41](../src/driver_impls/mod.rs#L41)), which indexes a bounds-checked array and so panics for fd >= 1024. And `receive` returns `None` before reading when the pool is empty, so the fd stays readable and the examples' `wait` loop spins until a buffer frees.
