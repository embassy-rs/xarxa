# 336. Quoted packet parsing ignores the IPv4 fragment offset and reads payload bytes of non-first fragments as ports

| | |
|---|---|
| Severity | info |
| Category | correctness |
| Location | [src/icmp_error.rs:128](../src/icmp_error.rs#L128), [src/icmp_error.rs:91](../src/icmp_error.rs#L91) |
| Features | default (`icmp-errors`, `ipv4-fragmentation`) |
| Verification | confirmed against the code |

## Summary
`parse_quoted_packet` reads the first 8 bytes after the quoted IPv4 header as ports and the TCP sequence number. It never checks the quoted header's fragment offset. The stack sends non-first fragments itself, so an ICMP error about one of them decodes payload bytes as ports. In practice the error matches no socket and is dropped.

## Details
src/icmp_error.rs:91-106 takes addresses, protocol and header length from the quoted IPv4 header. `frag_offset()` is not consulted.

src/icmp_error.rs:128:
```rust
let l4 = quote.get(l4_offset..l4_offset + 8)?;
```

## Failure scenario
A UDP socket sends a 3000-byte datagram. A router drops the second fragment and sends Time Exceeded. The quoted "ports" are datagram payload bytes. The error goes to no socket. Misdelivery needs another socket on the same address pair whose ports happen to match those bytes (and, for TCP, a sequence number in the send window), so it is very unlikely.

## Suggested fix
Return `None` when the quoted IPv4 header has a nonzero fragment offset.
