# 127. driver_impls::wait panics for fds >= FD_SETSIZE (1024)

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/driver_impls/mod.rs:41](../src/driver_impls/mod.rs#L41), [src/driver_impls/mod.rs:66](../src/driver_impls/mod.rs#L66) |
| Features | default (`std`) |
| Verification | confirmed against the code |

## Summary
`wait` uses `select` and `FD_SET`. libc's `FD_SET` on Linux indexes `fds_bits[fd / 64]` with Rust bounds checking, so an fd of 1024 or more panics. `select` cannot watch such an fd anyway.

## Details
src/driver_impls/mod.rs:41:
```rust
libc::FD_SET(fd, readfds.as_mut_ptr());
```
libc 0.2.189, src/unix/linux_like/mod.rs:1799-1802:
```rust
let fd = fd as usize;
let size = size_of_val(&(*set).fds_bits[0]) * 8;
(*set).fds_bits[fd / size] |= 1 << (fd % size);
```

## Failure scenario
A host process with 1100 open files creates a `TunTapDriver` (fd 1100) and calls `wait(fd, ...)`. It panics with index out of bounds.

## Suggested fix
Use `poll(2)` with a single `pollfd`.
