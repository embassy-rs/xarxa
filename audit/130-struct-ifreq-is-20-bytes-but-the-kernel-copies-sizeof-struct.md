# 130. Local struct ifreq is 20 bytes but the kernel copies 40, and TUNSETIFF flags are written as an int (0 on big-endian)

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/driver_impls/tuntap.rs:38](../src/driver_impls/tuntap.rs#L38), [src/driver_impls/tuntap.rs:141](../src/driver_impls/tuntap.rs#L141), [src/driver_impls/tuntap.rs:56](../src/driver_impls/tuntap.rs#L56), [src/driver_impls/raw_socket.rs:19](../src/driver_impls/raw_socket.rs#L19) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The local `ifreq` is `{ [c_char; 16], c_int }`, 20 bytes. The kernel's `struct ifreq` is 40 bytes on LP64, and TUNSETIFF, SIOCGIFMTU and SIOCGIFINDEX copy the full size in and back out. So the kernel reads and writes 20 bytes past the Rust object. Separately, TUNSETIFF reads `ifr_flags` as a `short` at offset 16, and flags stored as a `c_int` read as 0 there on big-endian hosts.

## Details
src/driver_impls/tuntap.rs:38:
```rust
struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_data: libc::c_int, /* ifr_ifindex or ifr_mtu */
}
```

tun's `__tun_chr_ioctl` does `copy_from_user` / `copy_to_user` with `ifreq_len`, and `dev_ioctl` uses `get_user_ifreq` / `put_user_ifreq`, all `sizeof(struct ifreq)`. The write-back normally restores the bytes it just read, so nothing visible changes. It is still an out-of-bounds kernel write into the Rust stack frame.

Endianness. src/driver_impls/tuntap.rs:141:
```rust
ifr.ifr_data = mode | IFF_NO_PI;
```
`ifr_flags` is `ifr_ifru.ifru_flags`, a short at offset 16 (linux/if.h). On big-endian the short holds the high half of the int, 0. TUNSETIFF sees no IFF_TUN/IFF_TAP (EINVAL for a new device) and no IFF_NO_PI (an existing persistent device attaches with packet info on, so every frame is misparsed). SIOCGIFMTU and SIOCGIFINDEX read an int, so they are fine. The raw_socket.rs copy (lines 17-22) only has the size problem, since it never passes flags.

The TUNSETIFF constant already handles mips/powerpc/sparc64, so big-endian hosts are meant to work.

## Failure scenario
- Any successful `TunTapDriver::new` or `RawSocketDriver::new`: the kernel writes 40 bytes into a 20-byte stack object.
- On powerpc64 or mips, `TunTapDriver::new("tap0", addr)` fails with EINVAL for a new interface. On a persistent interface every frame carries a 4-byte PI header the stack does not expect.

## Reproduction
Added to src/driver_impls/tuntap.rs in a scratch copy (tuntap module test harness):
```rust
#[cfg(test)]
mod verify_test {
    use super::*;
    #[test]
    fn verify_ifreq_size() {
        println!("ours={} kernel={}", core::mem::size_of::<ifreq>(), core::mem::size_of::<libc::ifreq>());
        assert!(core::mem::size_of::<ifreq>() < core::mem::size_of::<libc::ifreq>());
    }
}
```
`cargo test --lib verify_ifreq -- --nocapture`:
```
ours=20 kernel=40
test ... verify_ifreq_size ... ok
```
The big-endian part was not run, it is a layout trace.

## Suggested fix
Use `libc::ifreq`, or pad the struct to the kernel size. Write the TUNSETIFF flags as a `c_short` at offset 16.
