# 111. README says "No `unsafe`" but the packet buffer and the no-alloc slab use unsafe code

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [README.md:15](../README.md#L15), [src/storage/slab.rs:136](../src/storage/slab.rs#L136), [xarxa-driver/src/buf.rs:351](../xarxa-driver/src/buf.rs#L351) |
| Features | default |
| Verification | confirmed against the code |

## Summary
README.md:15, also the crate docs through `include_str!`, says: "No `unsafe`. ... We want the guarantee that there is no memory safety vulnerabilities." The slab and the re-exported `xarxa::driver` packet pool both use unsafe. No memory-safety bug is shown here. The claim is just inaccurate.

## Details
- src/storage/slab.rs:136 and :257: `#[allow(unsafe_code)]`, with `assume_init_drop/read/ref/mut` at :180, :198, :210, :223.
- xarxa-driver/src/buf.rs:79 `unsafe impl Sync for Pool`, :177 `NonNull::new_unchecked`, :190-191 `unsafe impl Send/Sync for PacketBuf`, :351 and :360 `get_unchecked(_mut)` in the payload accessors.
- `driver_impls` (std only) uses unsafe for FFI, which is expected.

## Suggested fix
Reword, for example: "No unsafe in protocol processing. Unsafe is confined to the packet pool and fixed-size slab storage." Or remove the unsafe.
