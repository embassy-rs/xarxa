# 242. An NDISC link-layer address option holding an 802.15.4 short address makes the whole NS/NA be dropped

| | |
|---|---|
| Severity | low |
| Category | other |
| Location | [src/stack.rs:2260](../src/stack.rs#L2260), [src/stack.rs:2333](../src/stack.rs#L2333), [src/wire/mod.rs:474](../src/wire/mod.rs#L474) |
| Features | medium-ieee802154, ipv6 |
| Verification | confirmed against the code |

## Summary
`RawHardwareAddress::parse` for 802.15.4 accepts only an 8-byte extended address. A SLLA/TLLA option with a 16-bit short address (RFC 4944 §8, Length=1) fails to parse, and `check!` drops the whole NS or NA instead of ignoring the option.

## Details
For `data_len == 1`, `NdiscOption::link_layer_addr` returns 6 bytes (src/wire/ndiscoption.rs:201):
```rust
let len = MAX_HARDWARE_ADDRESS_LEN.min(self.data_len() as usize * 8 - 2);
```
src/wire/mod.rs:474:
```rust
Medium::Ieee802154 => {
    if self.len() != 8 {
        return Err(Malformed);
    }
```
src/stack.rs:2260 (NS) and src/stack.rs:2333 (NA):
```rust
let lladdr = check!(lladdr.parse(iface.medium()));
```
The NS gets no NA, although the stack could answer with its own extended address. The NA is ignored completely.

## Failure scenario
A PAN peer with a 16-bit short address sends an NS for our link-local address with a Length=1 SLLA. xarxa sends no NA, so the peer cannot resolve us.

## RFC reference
RFC 4944 §8: "The Source/Target Link-layer Address option has the following forms when the link layer is IEEE 802.15.4 and the addresses are EUI-64 or 16-bit short addresses, respectively." Figure 7 shows the `Length=1` form with a "16-bit short Address" field.

## Suggested fix
Parse the short form into `Ieee802154Address::Short`. Failing that, treat an unparseable option as absent instead of dropping the message.
