# 182. Default std feature compiles driver_impls unconditionally, breaking non-unix builds

| | |
|---|---|
| Severity | low |
| Category | feature-gating |
| Location | [src/lib.rs:43](../src/lib.rs#L43), [src/driver_impls/mod.rs:16](../src/driver_impls/mod.rs#L16), [src/driver_impls/mod.rs:34](../src/driver_impls/mod.rs#L34) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`pub mod driver_impls` is gated only on `feature = "std"`, a default feature. The module uses `std::os::unix` and libc `select`/`fd_set`/`ioctl` with no target gate. A default-features build of xarxa fails on Windows, even for code that never uses the host drivers.

## Details
- src/lib.rs:42-43: `#[cfg(feature = "std")] pub mod driver_impls;`
- src/driver_impls/mod.rs:15-16: `mod tuntap;` gated only on medium features. tuntap.rs uses `std::os::unix::io`.
- src/driver_impls/mod.rs:34: `pub fn wait(fd: std::os::unix::io::RawFd, ...)` with no gate.
- Only `raw_socket` is gated on linux/android.

The `std` feature is described as needing the standard library, not unix. Not cross-compiled (no Windows target installed), but `std::os::unix` does not exist there.

## Failure scenario
`cargo build --target x86_64-pc-windows-msvc` of a crate depending on xarxa with default features fails with "could not find `unix` in `os`". The workaround, turning off `std`, also loses `Instant::now()`.

## Suggested fix
Gate `driver_impls` on `all(feature = "std", unix)` (or tuntap on linux/android) and say so in the feature doc.
