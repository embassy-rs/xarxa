# 325. TcpSeqNumber ordering is not antisymmetric at distance 2^31, and its operators panic undocumented

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/tcp.rs:74](../src/wire/tcp.rs#L74), [src/wire/tcp.rs:11](../src/wire/tcp.rs#L11), [src/wire/tcp.rs:36](../src/wire/tcp.rs#L36), [src/wire/tcp.rs:66](../src/wire/tcp.rs#L66) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The public `xarxa::wire::TcpSeqNumber` says it has no discontinuity across signed overflow. For two numbers exactly 2^31 apart, `partial_cmp` returns `Less` both ways, breaking `PartialOrd`. `Add<usize>`/`Sub<usize>` panic for `rhs > i32::MAX`, and `Sub<SeqNumber>` panics when `rhs` is after `self`. None of this is documented. The inherent `max`/`min` (lines 17-23) are undocumented and order-dependent for such inputs. The stack's windows stay far below 2^31, so only external users are affected.

## Details
src/wire/tcp.rs:74:
```rust
self.0.wrapping_sub(other.0).partial_cmp(&0)
```
`i32::MIN` is its own negation, so both directions give `Less`.

src/wire/tcp.rs:36 (and 47):
```rust
if rhs > i32::MAX as usize {
```
src/wire/tcp.rs:66:
```rust
panic!("attempt to subtract sequence numbers with underflow")
```

## Reproduction
Added to `src/wire/tcp.rs` in a scratch copy, run with `cargo test --lib vt_`:
```rust
#[test]
fn vt_seq_antisym() {
    let a = SeqNumber(0);
    let b = SeqNumber(i32::MIN);
    println!("a<b={} b<a={}", a < b, b < a);
    assert!(!(a < b && b < a));
}
```
Output: `a<b=true b<a=true`, then the assert fails.

## Suggested fix
Document the 2^31 ambiguity on the type, and add `# Panics` sections to the operators. Document `max`/`min`.
