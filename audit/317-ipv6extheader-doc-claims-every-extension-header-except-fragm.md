# 317. Ipv6ExtHeader doc claims every extension header except Fragment uses the 8-octet length layout

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ipv6ext.rs:9](../src/wire/ipv6ext.rs#L9), [src/wire/ipv6ext.rs:60](../src/wire/ipv6ext.rs#L60) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
The public doc says all extension headers except Fragment share the (next header, 8-octet length) layout. That is false for AH (length in 4-octet units minus 2) and ESP (no such prefix). `header_len()` gives wrong lengths for them. The stack only uses the type for Hop-by-Hop, Routing and Destination Options, so internal use is correct.

## Details
src/wire/ipv6ext.rs:9-11:
```rust
/// All IPv6 extension headers (except Fragment) share the same layout: a next
/// header field, a length field in units of 8 octets not counting the first 8,
/// and header-specific data.
```
src/wire/ipv6ext.rs:60 computes `(self.buffer[field::LENGTH] as usize + 1) * 8`. The Mobility header (RFC 6275) does fit the layout.

## Failure scenario
A user walks a header chain with `Ipv6ExtHeader` and meets AH with Payload Len 4 (24 bytes). `header_len()` returns 40 and the walk lands 16 bytes past the upper-layer header.

## RFC reference
RFC 8200 §4.3 / §4.4 / §4.6: "Hdr Ext Len ... Length of the ... header in 8-octet units, not including the first 8 octets." AH and ESP are defined in RFC 4302/4303 with their own formats (not in rfcs/).

## Suggested fix
Limit the doc to Hop-by-Hop, Routing and Destination Options. Say that Fragment, AH and ESP use other layouts.
