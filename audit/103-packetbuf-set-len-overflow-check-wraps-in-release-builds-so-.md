# 103. PacketBuf::set_len overflow check wraps in release builds, so safe code can break the headroom+len invariant (UB)

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [xarxa-driver/src/buf.rs:321](../xarxa-driver/src/buf.rs#L321), [xarxa-driver/src/buf.rs:307](../xarxa-driver/src/buf.rs#L307), [xarxa-driver/src/buf.rs:351](../xarxa-driver/src/buf.rs#L351), [xarxa-driver/src/buf.rs:360](../xarxa-driver/src/buf.rs#L360) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`set_len` checks `self.headroom() + len <= PACKET_BUF_SIZE` with a plain usize addition. Without overflow checks (the release profile, which the workspace does not override) a `len` above `usize::MAX - headroom` wraps and passes. `len as u16` is then stored, and `Deref`/`DerefMut` build an out-of-bounds slice with `get_unchecked`. That is undefined behaviour from a safe public API.

## Details

xarxa-driver/src/buf.rs:320:

```rust
pub fn set_len(&mut self, len: usize) {
    assert!(self.headroom() + len <= PACKET_BUF_SIZE);
    self.inner_mut().len = len as u16;
}
```

xarxa-driver/src/buf.rs:349 (and the same at :358-360 for `DerefMut`):

```rust
// SAFETY: `headroom + len <= PACKET_BUF_SIZE`, which every method that
// changes either of them checks.
unsafe { inner.data.get_unchecked(start..start + inner.len as usize) }
```

With `reserve(4); set_len(usize::MAX - 3)` the sum wraps to 0, the assert passes, and `len` becomes 65532. The slice then covers neighbouring pool slots owned by other `PacketBuf`s. A debug build panics with "attempt to add with overflow" instead of the documented assert.

xarxa-driver/src/buf.rs:307, in `ensure_headroom`, has the same pattern:

```rust
if headroom + len > PACKET_BUF_SIZE {
    return false;
}
```

It stays memory safe because the following `copy_within` is bounds-checked. But it panics where its doc promises `false`.

## Failure scenario

A driver reserves 4 bytes of headroom and computes the received length as `desc_len - 4` to strip the FCS. On an error descriptor `desc_len` is 0, and a wrapping subtraction gives `usize::MAX - 3`. In release, `set_len` accepts it. The stack then parses and writes through a 65532-byte slice over a 1514-byte buffer, corrupting other pool buffers.

## Reproduction

Test in `mod tests` of xarxa-driver/src/buf.rs, in a scratch copy:

```rust
#[test]
fn verify_set_len_wrap() {
    let mut buf = PacketBuf::try_new().unwrap();
    buf.reserve(4);
    buf.set_len(usize::MAX - 3);
    println!("len={} slice_len={} capacity={}", buf.len(), (&buf[..]).len(), buf.capacity());
    assert!(buf.headroom() + buf.len() <= PACKET_BUF_SIZE, "invariant broken");
}
```

`cargo test --release -p xarxa-driver verify_set_len_wrap -- --nocapture`:

```
len=65532 slice_len=65532 capacity=1514
panicked: invariant broken
```

Debug build: `panicked at xarxa-driver/src/buf.rs:321:17: attempt to add with overflow`.

## Suggested fix

Compare without overflow:

- `set_len`: `assert!(len <= PACKET_BUF_SIZE - self.headroom())`.
- `ensure_headroom`: `if headroom > PACKET_BUF_SIZE - len { return false; }`.
