# 133. TunTapDriver::from_fd: nonblocking fd, fd ownership and mtu units are undocumented

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/driver_impls/tuntap.rs:119](../src/driver_impls/tuntap.rs#L119), [src/driver_impls/tuntap.rs:199](../src/driver_impls/tuntap.rs#L199), [src/driver_impls/tuntap.rs:215](../src/driver_impls/tuntap.rs#L215) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`from_fd` stores the fd as given. `receive()` treats only EAGAIN as "no frame", so a blocking fd makes `Stack::poll` block in `read()` until a frame arrives. The doc does not say the fd must be O_NONBLOCK, that `Drop` closes it, or that `mtu` is the whole frame including the Ethernet header. A short IEEE 802.15.4 address is accepted and panics later.

## Details
src/driver_impls/tuntap.rs:119:
```rust
pub fn from_fd(fd: RawFd, hardware_addr: HardwareAddress, mtu: usize) -> io::Result<TunTapDriver> {
    Ok(TunTapDriver {
        lower: fd,
        mtu,
        hardware_addr,
    })
}
```
- `new()` opens with `O_NONBLOCK` (tuntap.rs:94). `from_fd` does not set it.
- `Drop` calls `libc::close(self.lower)` (tuntap.rs:199-203). A caller that also closes the fd double-closes.
- `new()` sets `mtu = ip_mtu + ETHERNET_HEADER_LEN` for Ethernet (tuntap.rs:169), and `Iface::ip_mtu` subtracts it again (src/iface/mod.rs:731). Passing 1500 for a TAP fd gives an IP MTU of 1486.
- `hardware_address()` does `self.hardware_addr.to_driver().unwrap()` (tuntap.rs:215). `to_driver` returns `None` for a non-extended IEEE 802.15.4 address, so `add_iface` panics.

## Failure scenario
A privileged helper opens `/dev/net/tun` without O_NONBLOCK and passes the fd to `from_fd`. The first `Stack::poll` with no traffic blocks in `read()`. No TCP retransmits, no DHCP renewals, no return to the main loop.

## Suggested fix
Set O_NONBLOCK with `fcntl` in `from_fd`, or document it. Document that the driver takes ownership of the fd and that `mtu` includes the link header. Reject IEEE 802.15.4 addresses as `new()` does.
