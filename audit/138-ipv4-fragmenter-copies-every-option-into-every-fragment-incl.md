# 138. IPv4 fragmenter copies every option into every fragment, including options whose copied flag is 0

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/fragmentation.rs:274](../src/fragmentation.rs#L274) |
| Features | default (`raw-ip`, `ipv4-fragmentation`) |
| Verification | confirmed against the RFC text |

## Summary
`dispatch_ipv4_frag` copies the whole original header, options included, into each fragment. RFC 791 says options with the copied flag clear (Record Route, Timestamp) stay in the first fragment only. Only raw IP-mode sockets can produce IPv4 options, since `push_ipv4_header` never writes any. The impact is interop and cosmetic, not data corruption.

## Details
src/fragmentation.rs:274, run for every fragment:
```rust
tx_buffer[..ip_header_len].copy_from_slice(&buffer[..ip_header_len]);
```
There is no pass over the options and no IHL adjustment for later fragments. DESIGN.md §6 says the header is byte-copied "so options survive", but does not address the copied flag.

## Failure scenario
A raw socket sends a 1400-byte IPv4 packet with a Record Route option (type 7, copied flag 0) on a 576-MTU interface. Every fragment carries the RR option, and routers record the route in each one.

## RFC reference
RFC 791 §3.1:
> The copied flag indicates that this option is copied into all fragments on fragmentation.
> 0 = not copied

RFC 791 §3.2:
> When fragmentation occurs, some options are copied, but others remain with the first fragment only.

RFC 791 §3.2, procedure step (7) and the IHL update:
> Selectively copy the internet header (some options are not copied, see option definitions)
> ...
> IHL <- (((OIHL*4)-(length of options not copied))+3)/4;

## Suggested fix
For fragments after the first, build the header from the fixed 20 bytes plus the options with bit 0x80 set (walking EOL/NOP/TLV), pad to 4 bytes, set IHL, and size those fragments by that header length.
