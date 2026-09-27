# 109. Example run instructions omit creating the TAP/TUN device: `cargo run` as a normal user panics with EPERM

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [examples/tuntap.rs:7](../examples/tuntap.rs#L7), [examples/tuntap.rs:42](../examples/tuntap.rs#L42), [src/driver_impls/tuntap.rs:142](../src/driver_impls/tuntap.rs#L142) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The TUN/TAP examples say to run `cargo run --example X -- tap0` as a normal user. `TunTapDriver::new` issues `TUNSETIFF`, which needs `CAP_NET_ADMIN` unless a persistent device owned by the user already exists. No example or the README says to run `ip tuntap add ... user $USER`, so the documented command panics at the `unwrap()`.

## Details
src/driver_impls/tuntap.rs:142:
```rust
ifreq_ioctl(lower, ifr, TUNSETIFF).map(|_| ())
```
examples/tuntap.rs:42:
```rust
let driver = TunTapDriver::new(name, hardware_addr).unwrap();
```
The only hint is the driver doc at src/driver_impls/tuntap.rs:87 about persistent interfaces, which example users won't read. The headers of tuntap, dns, ping, multicast, multicast6, tcp_server and tcp_client document `--tun tun0` runs, but give host commands only for tap0. `sixlowpan.rs` says to run with sudo and is not affected.

## Failure scenario
`cargo run --example tuntap -- tap0` without a pre-created tap0 panics with `Os { code: 1, kind: PermissionDenied }`.

## Suggested fix
Document `sudo ip tuntap add name tap0 mode tap user $USER` (and `mode tun` for tun0), in each header or once in the README. Give tun0 versions of the host commands.
