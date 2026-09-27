# 332. Timestamp::from_seconds_and_nanos does not enforce the documented sub-second invariant

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [xarxa-driver/src/meta.rs:41](../xarxa-driver/src/meta.rs#L41), [xarxa-driver/src/meta.rs:33](../xarxa-driver/src/meta.rs#L33) |
| Features | packetmeta-timestamp |
| Verification | confirmed against the code |

## Summary
`quarter_nanos` is documented as "Always less than `4_000_000_000`". The constructor shifts `nanos << 2` with no check or carry. For `nanos >= 1e9` the invariant breaks, and for `nanos >= 2^30` high bits are lost. The shift never panics.

## Details
xarxa-driver/src/meta.rs:41:
```rust
pub const fn from_seconds_and_nanos(seconds: u32, nanos: u32) -> Self {
    Self {
        seconds,
        quarter_nanos: nanos << 2,
    }
}
```
The constructor doc states no `nanos < 1_000_000_000` precondition. The fields are `pub`, so "Always" can't be a guarantee anyway. The stack never builds Timestamps, so only drivers are affected.

## Failure scenario
A driver calls `from_seconds_and_nanos(s, 1_500_000_000)` after an unnormalized add. `quarter_nanos` is 6e9 mod 2^32 = 1_705_032_704, so `nanos()` is 426_258_176 and nothing carries into seconds.

## Suggested fix
Carry into seconds (`seconds + nanos / 1_000_000_000`, `(nanos % 1_000_000_000) << 2`), or document the precondition and `debug_assert!` it.
