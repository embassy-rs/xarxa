# 320. NdiscOption::check_len accepts Length 0, then data() and link_layer_addr() panic

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ndiscoption.rs:155](../src/wire/ndiscoption.rs#L155), [src/wire/ndiscoption.rs:148](../src/wire/ndiscoption.rs#L148), [src/wire/ndiscoption.rs:202](../src/wire/ndiscoption.rs#L202), [src/wire/ndiscoption.rs:254](../src/wire/ndiscoption.rs#L254) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`check_len` is documented as "Ensure that no accessor method will panic if called." It returns `Ok` for an SLLA, TLLA, MTU or unknown option with Length 0. Only `new_checked` rejects Length 0. After that, `data()` panics and `link_layer_addr()` underflows. The stack uses `new_checked` everywhere, so this is not reachable from the network. It affects users of the public `xarxa::wire::NdiscOption` who use `new_unchecked` + `check_len`.

## Details
src/wire/ndiscoption.rs:148, the zero check lives only in `new_checked`:
```rust
if opt.data_len() == 0 {
```
src/wire/ndiscoption.rs:202:
```rust
let len = MAX_HARDWARE_ADDRESS_LEN.min(self.data_len() as usize * 8 - 2);
```
src/wire/ndiscoption.rs:254, with `field::DATA(0)` = `2..0`:
```rust
&self.buffer[field::DATA(len)]
```
`data()` panics in debug and release. `link_layer_addr()` panics on subtract overflow in debug. In release it wraps, `min` picks `MAX_HARDWARE_ADDRESS_LEN`, and it returns garbage bytes from the 8-byte buffer.

## Failure scenario
User code parses `[0x01, 0x00, 0, 0, 0, 0, 0, 0]` with `NdiscOption::new_unchecked(buf)` and `check_len()?`, then calls `data()`. The program panics.

## Reproduction
Test in the `src/wire/ndiscoption.rs` test module of a scratch copy:
```rust
#[test]
fn vv_check_len_zero_then_data_panics() {
    let mut b = [1u8, 0, 0, 0, 0, 0, 0, 0];
    let opt = NdiscOption::new_unchecked(&mut b);
    assert_eq!(opt.check_len(), Ok(()));
    let r = std::panic::catch_unwind(|| { let mut b = [1u8, 0, 0, 0, 0, 0, 0, 0]; let o = NdiscOption::new_unchecked(&mut b); o.check_len().unwrap(); o.data().len() });
    assert!(r.is_err(), "data() did not panic");
    let r = std::panic::catch_unwind(|| { let mut b = [1u8, 0, 0, 0, 0, 0, 0, 0]; let o = NdiscOption::new_unchecked(&mut b); o.check_len().unwrap(); o.link_layer_addr(); });
    assert!(r.is_err(), "link_layer_addr() did not panic");
}
```
Output:
```
panicked at src/wire/ndiscoption.rs:254:21: slice index starts at 2 but ends at 0
panicked at src/wire/ndiscoption.rs:202:48: attempt to subtract with overflow
test ... ok
```

## Suggested fix
Move the zero-length rejection from `new_checked` into `check_len`.
