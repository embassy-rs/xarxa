# 359. checksum::data overflows its u32 accumulator for slices over about 128 KiB

| | |
|---|---|
| Severity | info |
| Category | panic |
| Location | [src/wire/ip.rs:544](../src/wire/ip.rs#L544) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The public `wire::checksum::data` adds 16-bit words into a u32 and folds only once at the end. More than 65537 words of 0xffff overflow it. Debug builds panic, release builds return a wrong checksum. Stack inputs are bounded by `PacketBuf` (at most 65535 bytes), so only direct callers of the public API are affected.

## Details
src/wire/ip.rs:544-555:
```rust
let mut accum: u32 = 0;
...
accum += val_0 as u32;
accum += val_1 as u32;
```
`propagate_carries` runs once, at line 570. The doc states no length limit.

## Reproduction
In the test module of src/wire/ip.rs, run with `cargo test --lib zz_`:
```rust
#[test]
fn zz_checksum_big() { let v = std::vec![0xffu8; 200_000]; let _ = checksum::data(&v); }
```
Output: `thread 'wire::ip::test::zz_checksum_big' panicked at src/wire/ip.rs:555:13: attempt to add with overflow`.

## Suggested fix
Use a u64 accumulator or fold periodically. Or document the maximum length.
