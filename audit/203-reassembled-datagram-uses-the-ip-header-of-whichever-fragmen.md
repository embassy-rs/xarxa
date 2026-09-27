# 203. Reassembled IPv4 datagram uses the completing fragment's header, not fragment 0's

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/reassembly.rs:318](../src/reassembly.rs#L318) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`reassemble_ipv4` puts the header of whichever fragment completed the datagram in front of the payload. When that is not the offset-0 fragment, options only fragment 0 carries are lost, and TOS/ECN and TTL come from an arbitrary fragment. A CE mark on another fragment is dropped, which RFC 3168 forbids. The docs describe this behavior, so it is not a doc mismatch.

## Details
src/reassembly.rs:317-326
```rust
payload.push_front(header_len);
payload[..header_len].copy_from_slice(&buf[..header_len]);
let mut packet = Ipv4Packet::new_unchecked(&mut payload);
packet.set_total_len(...);
packet.set_more_frags(false);
packet.set_frag_offset(0);
packet.fill_checksum();
```
`buf` is the fragment just received. Only length, MF, offset and checksum are patched. The stack's TCP does not use ECN, so the effect is mostly on raw IP sockets, which receive this header.

## Failure scenario
- Fragment 0 carries Record Route or Timestamp and arrives first. A raw socket sees the reassembled packet with a 20-byte header and no options.
- A router marks fragment 0 CE, the last fragment is ECT(0). The reassembled packet is ECT(0) and the congestion signal is lost.

## RFC reference
RFC 3168 §5.3: "Reassembly of a fragmented packet MUST NOT lose indications of congestion. In other words, if any fragment of an IP packet to be reassembled has the CE codepoint set, then one of two actions MUST be taken:"

RFC 791 §3.2 (example procedure, not normative): "If this is the first fragment (that is the fragment offset is zero) this header is placed in the header buffer."

## Suggested fix
Keep fragment 0's header, for example by copying it into the assembler buffer's headroom when offset 0 arrives. OR any CE mark into it when all fragments were ECT.
