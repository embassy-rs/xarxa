# 321. SixlowpanFragRepr::emit silently truncates datagram sizes above 2047

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/wire/sixlowpan/frag.rs:179](../src/wire/sixlowpan/frag.rs#L179), [src/wire/sixlowpan/frag.rs:184](../src/wire/sixlowpan/frag.rs#L184), [src/wire/sixlowpan/frag.rs:51](../src/wire/sixlowpan/frag.rs#L51) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The public `SixlowpanFragRepr` has `size: u16` fields documented only as "The size of the whole IPv6 datagram". RFC 4944 §5.3 makes datagram_size 11 bits. `emit` masks the value, so 2048 or more is written modulo 2048 with no error. The stack never builds a 6LoWPAN datagram above 1280 bytes, so only direct users of the type are affected.

## Details
src/wire/sixlowpan/frag.rs:179 (FRAGN at line 184 is the same):
```rust
let word = ((DISPATCH_FIRST_FRAGMENT_HEADER as u16) << 11) | (size & 0b111_1111_1111);
```
Neither the field docs nor the `emit` doc mention the limit.

## Failure scenario
A caller emits `FirstFragment { size: 2100, tag }`. The header says 52. The receiver reassembles a 52-byte datagram or drops the fragments.

## Suggested fix
Document that `size` must be at most 2047. Optionally `debug_assert!` it in `emit`.
