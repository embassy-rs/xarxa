# 319. Wire lifetime accessors saturate at Duration::MAX, infinite PIO lifetimes can't be read or written, set_router_lifetime truncates

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/wire/ndiscoption.rs:232](../src/wire/ndiscoption.rs#L232), [src/wire/ndiscoption.rs:313](../src/wire/ndiscoption.rs#L313), [src/wire/ndisc.rs:119](../src/wire/ndisc.rs#L119), [src/iface/slaac.rs:110](../src/iface/slaac.rs#L110) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The public PIO lifetime accessors go through `Duration`, which caps at 2^30 ms (about 12.4 days). Infinity (0xffffffff) and 14 days read the same. `set_valid_lifetime(Duration::MAX)` writes 1073741, never 0xffffffff. `set_router_lifetime` does `as_secs() as u16`, so 70000 s wraps to 4464 s. None of this is documented on the public accessors, and DESIGN.md §8 promises every wire bit is reachable. The RFC 4862 §5.5.3(c) check compares capped values, so valid=13 d, preferred=14 d passes. The effect there is minor: two equal capped lifetimes.

## Details
src/wire/ndiscoption.rs:232-233 (same for `preferred_lifetime`):
```rust
pub fn valid_lifetime(&self) -> Duration {
    Duration::from_secs(NetworkEndian::read_u32(&self.buffer[field::VALID_LT]))
```
The setters at 313-321 write `time.as_secs()`. src/wire/ndisc.rs:119:
```rust
NetworkEndian::write_u16(&mut self.buffer[field::ROUTER_LT], value.as_secs() as u16);
```
src/iface/slaac.rs:110:
```rust
&& self.preferred_lifetime <= self.valid_lifetime
```
The capping is documented only on the private `PrefixInformation` (slaac.rs:84-88). The `router_lifetime` getter is fine, since a u16 of seconds is below `Duration::MAX`.

## Failure scenario
An application builds an RA with `xarxa::wire` and infinite lifetimes. It advertises 12.4-day lifetimes. A router lifetime of 70000 s goes out as 4464 s.

## RFC reference
RFC 4861 §4.6.2: "A value of all one bits (0xffffffff) represents infinity."

RFC 4862 §5.5.3 c): "If the preferred lifetime is greater than the valid lifetime, silently ignore the Prefix Information option."

## Reproduction
Added to `mod test` in src/wire/ndiscoption.rs:
```rust
#[test]
fn vv_lifetimes_saturate() {
    let mut b = [0u8; 32];
    let mut opt = NdiscOption::new_unchecked(&mut b);
    opt.set_option_type(Type::PrefixInformation);
    opt.set_data_len(4);
    opt.set_valid_lifetime(Duration::MAX);
    let raw = u32::from_be_bytes(b[4..8].try_into().unwrap());
    std::println!("set_valid_lifetime(MAX) wrote {raw:#x}");
    b[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    b[8..12].copy_from_slice(&(14u32 * 86400).to_be_bytes());
    let opt = NdiscOption::new_unchecked(&mut b);
    std::println!("infinite reads {:?}, 14d reads {:?}", opt.valid_lifetime(), opt.preferred_lifetime());
    assert_eq!(opt.valid_lifetime(), opt.preferred_lifetime());
    let mut ra = [0u8; 16];
    let mut p = crate::wire::Icmpv6Packet::new_unchecked(&mut ra[..]);
    p.set_router_lifetime(Duration::from_secs(70000));
    std::println!("router lifetime 70000 -> {:?}", p.router_lifetime());
    assert_eq!(raw, 1073741);
}
```
Output:
```
set_valid_lifetime(MAX) wrote 0x10624d
infinite reads Duration { millis: 1073741824 }, 14d reads Duration { millis: 1073741824 }
router lifetime 70000 -> Duration { millis: 4464000 }
test wire::ndiscoption::test::vv_lifetimes_saturate ... ok
```

## Suggested fix
Add raw u32/u16 accessors, or make these raw and convert in slaac.rs. Do check (c) on raw values. Document the saturation on the `Duration` accessors. Make `set_router_lifetime` saturate at 0xffff.
