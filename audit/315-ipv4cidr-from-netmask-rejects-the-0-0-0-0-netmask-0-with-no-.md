# 315. Ipv4Cidr::from_netmask rejects the 0.0.0.0 netmask (/0), with no documented error

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/wire/ipv4.rs:132](../src/wire/ipv4.rs#L132) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`from_netmask` requires `netmask.leading_zeros() == 0`, so the valid mask 0.0.0.0 returns `Err(Malformed)`. `Cidr::new(addr, 0)` and `prefix_len` both accept /0. The doc has no Errors section. No internal callers.

## Details
src/wire/ipv4.rs:130-132:
```rust
pub fn from_netmask(addr: Address, netmask: Address) -> Result<Cidr, Malformed> {
    let netmask = netmask.to_bits();
    if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
```
For netmask 0, `leading_zeros()` is 32.

## Reproduction
```rust
#[test]
fn zz_from_netmask_zero() {
    use crate::wire::{Ipv4Addr, Ipv4Cidr};
    assert!(Ipv4Cidr::from_netmask(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).is_ok());
}
```
Output: `assertion failed: Ipv4Cidr::from_netmask(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).is_ok()`.

## Suggested fix
Accept netmask 0. Add an Errors section: `Malformed` for non-contiguous masks.
