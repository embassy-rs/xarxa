# 131. ifreq_for panics on interface names of 17+ bytes and silently truncates 16-byte names

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/driver_impls/tuntap.rs:49](../src/driver_impls/tuntap.rs#L49), [src/driver_impls/raw_socket.rs:30](../src/driver_impls/raw_socket.rs#L30) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`ifreq_for` copies the name into a `[c_char; 16]` with no length check. A name of 17 or more bytes panics, although `new()` returns `io::Result` for every other failure. A 16-byte name leaves no NUL, and the kernel forces `ifr_name[15] = 0`, truncating it. Names with an embedded NUL are not rejected either.

## Details
src/driver_impls/tuntap.rs:48:
```rust
for (i, byte) in name.as_bytes().iter().enumerate() {
    ifreq.ifr_name[i] = *byte as libc::c_char
}
```
The same code is at src/driver_impls/raw_socket.rs:29-31.

## Failure scenario
`TunTapDriver::new("a-very-long-ifname0", addr)` (for example from a CLI argument) panics with index out of bounds instead of returning an error.

## Reproduction
In a scratch copy, tuntap module test harness:
```rust
#[test]
fn verify_ifreq_long_name_panics() {
    let r = std::panic::catch_unwind(|| ifreq_for("a-very-long-ifname0"));
    assert!(r.is_err());
    let q = ifreq_for("0123456789abcdef");
    assert!(q.ifr_name.iter().all(|&c| c != 0));
}
```
`cargo test --lib verify_ifreq -- --nocapture`:
```
panicked at src/driver_impls/tuntap.rs:49:9: index out of bounds: the len is 16 but the index is 16
test ... verify_ifreq_long_name_panics ... ok
```

## Suggested fix
Return `io::ErrorKind::InvalidInput` when `name.len() >= IF_NAMESIZE` or the name contains a NUL.
