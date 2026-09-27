# 363. `Icmpv6Packet::set_qrv` panics on values >= 8 without documenting it

| | |
|---|---|
| Severity | info |
| Category | doc-mismatch |
| Location | [src/wire/mld.rs:145](../src/wire/mld.rs#L145) |
| Features | default (`multicast`) |
| Verification | confirmed against the code |

## Summary
The public setter `Icmpv6Packet::set_qrv` asserts `value < 8`. Its doc only says "Set the Querier's Robustness Variable." and lists no panic. RFC 3810 says a Robustness Variable above 7 is encoded as QRV 0, so a caller passing its raw RV panics. The stack only calls `set_qrv(1)` (src/multicast.rs:900), so nothing is reachable from the network.

## Details
src/wire/mld.rs:143:
```rust
/// Set the Querier's Robustness Variable.
#[inline]
pub fn set_qrv(&mut self, value: u8) {
    assert!(value < 8);
    self.buffer[field::SQRV] = (self.buffer[field::SQRV] & 0x8) | value & 0x7;
}
```

## RFC reference
RFC 3810 §5.1.8: "If the Querier's [Robustness Variable] exceeds 7 (the maximum value of the QRV field), the QRV field is set to zero."

## Suggested fix
Document the panic, or encode values above 7 as 0 per RFC 3810 §5.1.8.
