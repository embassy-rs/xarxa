# 132. TunTapDriver::new leaks the /dev/net/tun fd on every error path

| | |
|---|---|
| Severity | low |
| Category | resource-leak |
| Location | [src/driver_impls/tuntap.rs:102](../src/driver_impls/tuntap.rs#L102), [src/driver_impls/tuntap.rs:94](../src/driver_impls/tuntap.rs#L94) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`new()` opens `/dev/net/tun` into a plain `c_int`. The `TunTapDriver` whose `Drop` closes it is built only after the fallible steps. Any `?` early return leaks the fd.

## Details
src/driver_impls/tuntap.rs:101:
```rust
let mut ifreq = ifreq_for(name);
Self::attach_interface_ifreq(lower, medium, &mut ifreq)?;
let mtu = Self::mtu_ifreq(medium, &mut ifreq)?;

Ok(TunTapDriver {
    lower,
    mtu,
    hardware_addr,
})
```
Leaking paths:
- TUNSETIFF fails (EPERM, EBUSY, ...).
- The medium is IEEE 802.15.4: `attach_interface_ifreq` returns `Unsupported` before any ioctl (tuntap.rs:133-139).
- SIOCGIFMTU in `mtu_ifreq` fails. It closes its own helper socket, not `lower`.

`RawSocketDriver::new` builds the driver before its fallible ioctls, so it does not leak. The long-name panic of finding 131 happens before `open()`.

## Failure scenario
An app retries `TunTapDriver::new` without CAP_NET_ADMIN. Each attempt fails TUNSETIFF with EPERM and leaks one fd, until EMFILE.

## Suggested fix
Hold the fd in an `OwnedFd` until the driver is built, or build the driver first as raw_socket.rs does.
