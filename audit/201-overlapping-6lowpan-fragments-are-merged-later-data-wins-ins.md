# 201. Overlapping 6LoWPAN fragments are merged instead of discarding the reassembly

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/reassembly.rs:112](../src/reassembly.rs#L112), [src/reassembly.rs:150](../src/reassembly.rs#L150), [src/sixlowpan.rs:729](../src/sixlowpan.rs#L729) |
| Features | sixlowpan-reassembly |
| Verification | confirmed against the RFC text |

## Summary
`PacketAssembler::add` accepts a fragment that overlaps earlier ones with a different offset or size and overwrites the bytes already there. RFC 4944 requires discarding the accumulated fragments. Fragments past `datagram_size` are also accepted, and such a reassembly never completes, holding the slot until the timeout.

## Details
src/reassembly.rs:115-126
```rust
if buffer.capacity() < offset + len {
    return Err(AssemblerError);
}
self.assembler.add(offset, len)...;
buffer[offset..][..len].copy_from_slice(data);
```
Only the buffer capacity is checked. There is no overlap detection and no bound against `total_size`. Completion needs an exact match:

src/reassembly.rs:150
```rust
self.total_size == Some(self.assembler.peek_front())
```
A FRAGN past `datagram_size` moves the contiguous front beyond `total_size`, so it never matches. FRAGN goes straight to `frag_slot.add(&buf, offset)` (src/sixlowpan.rs:729).

## Failure scenario
A sender reuses a tag within the 60 s timeout (wrap or reboot) with the same `datagram_size`. Stale and new fragments are merged into a corrupt datagram. Upper-layer checksums usually catch it, but not with elided UDP checksums, which xarxa accepts. Separately, one on-link frame extending past `datagram_size` pins the only reassembly slot (default `REASSEMBLY_BUFFER_COUNT` is 1) for the full timeout.

## RFC reference
RFC 4944 §5.3: "If a link fragment that overlaps another fragment is received, as identified above, and differs in either the size or datagram_offset of the overlapped fragment, the fragment(s) already accumulated in the reassembly buffer SHALL be discarded. A fresh reassembly may be commenced with the most recently received link fragment."

## Suggested fix
For 6LoWPAN only (IPv4 reassembly shares this code, and RFC 791 allows overlaps): restart the reassembly on a non-identical overlap, and reject `offset + len > datagram_size`.
