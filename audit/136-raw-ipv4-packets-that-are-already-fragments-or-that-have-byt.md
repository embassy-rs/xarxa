# 136. Raw IPv4 packets that are already fragments, or that have bytes beyond total_len, are fragmented wrongly

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/fragmentation.rs:186](../src/fragmentation.rs#L186), [src/fragmentation.rs:213](../src/fragmentation.rs#L213), [src/fragmentation.rs:280](../src/fragmentation.rs#L280), [src/raw.rs:588](../src/raw.rs#L588), [src/wire/ipv4.rs:263](../src/wire/ipv4.rs#L263) |
| Features | default (`raw-ip`, `ipv4-fragmentation`) |
| Verification | confirmed against the code |

## Summary
`fragment_ipv4` takes the datagram length from `buf.len()`, not from the header's `total_len`. It always starts at offset 0, derives MF only from the remaining length, and always clears DF. A raw IP-mode packet with trailing bytes past `total_len` has them sent as payload. A raw packet that is itself a fragment loses its offset and MF, and one with DF set is fragmented anyway.

## Details
The raw send path only validates with `parse_ip_headers`, which uses `Ipv4Packet::new_checked`. That check is a lower bound only.

src/wire/ipv4.rs:263
```rust
} else if len < self.total_len() as usize {
    Err(Malformed)
```

`transmit_ip` compares `buf.len()` with the MTU (src/stack.rs:2668-2670), and the fragmenter records the same length.

src/fragmentation.rs:186, 208, 213
```rust
let total_ip_len = buf.len();
...
frag.packet_len = total_ip_len;
...
frag.ipv4.frag_offset = 0;
```

src/fragmentation.rs:261, 280-283
```rust
let more_frags = (frag.packet_len - frag.sent_bytes) != payload_len;
...
packet.set_more_frags(more_frags);
packet.set_dont_frag(false);
packet.set_frag_offset(frag.ipv4.frag_offset);
```

Stack-generated packets set DF (src/stack.rs:2805) and the fragmenter overrides it. That is the stack's own policy. For a user-supplied raw header with DF=1 it contradicts what the user asked for.

Only raw IP-mode sockets can produce these packets.

## Failure scenario
- A raw socket sends a 1200-byte buffer whose IPv4 `total_len` is 900, on a 576-MTU interface. The receiver reassembles a 1200-byte datagram with 300 bytes of garbage at the end.
- A raw socket sends an 800-byte fragment with offset 1480 and MF=1 on a 576-MTU interface. The pieces go out with offsets starting at 0 and the last has MF=0, which corrupts the receiver's reassembly.
- A raw socket sends a 1000-byte packet with DF=1 on a 576-MTU interface. It is fragmented instead of dropped.

## RFC reference
RFC 791 §3.2, example fragmentation procedure:
> (2) OIHL <- IHL; OTL <- TL; OFO <- FO; OMF <- MF;
> ...
> FO <- OFO + NFB; MF <- OMF; Recompute Checksum;

RFC 791 §3.2:
> If the Don't Fragment flag (DF) bit is set, then internet fragmentation of this datagram is NOT permitted, although it may be discarded.

## Suggested fix
- In the raw IP send path, reject `len != total_len` as `Malformed`, or trim to `total_len`.
- In `fragment_ipv4`, start from the original's `frag_offset` and keep its MF on the last fragment, or refuse to re-fragment packets that are already fragments.
- Drop raw packets with DF set that exceed the MTU, instead of clearing DF.
