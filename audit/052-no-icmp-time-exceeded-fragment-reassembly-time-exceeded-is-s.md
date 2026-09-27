# 052. No ICMP Time Exceeded is sent when IPv4 reassembly times out

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/reassembly.rs:197](../src/reassembly.rs#L197), [src/reassembly.rs:277](../src/reassembly.rs#L277) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary

`remove_expired` resets expired assemblers and does nothing else. RFC 1122 requires an ICMP Time Exceeded (code 1) to the source when the reassembly timeout expires and fragment zero was received. The stack never builds an ICMPv4 Time Exceeded, and the assembler does not keep the first fragment's header needed to quote one. This applies to IPv4 only. RFC 4944 sets no such requirement for 6LoWPAN.

## Details

src/reassembly.rs:197:

```rust
pub fn remove_expired(&mut self, clock: &mut Clock) {
    for frag in &mut self.assemblers {
        if !frag.is_free() && clock.expired(frag.expires_at) {
            frag.reset();
        }
    }
}
```

The assembler stores only payload bytes at their offsets. `reassemble_ipv4` builds the final header from whichever fragment completes the datagram. The only Time Exceeded code in the crate is in `packet_log.rs` and the incoming-error mapping in `icmp_error.rs`. Neither README "Not yet implemented" nor DESIGN.md §10/§11 lists this.

## Failure scenario

A peer sends fragments 0 and 2 of a datagram. Fragment 1 is lost. After 60 s the partial datagram is dropped silently. The sender gets no Time Exceeded and cannot tell that reassembly failed at this host. In practice few senders act on this error, so the interop impact is small.

## RFC reference

RFC 1122 §3.3.2:

> There MUST be a reassembly timeout. The reassembly timeout value SHOULD be a fixed value, not set from the remaining TTL. It is recommended that the value lie between 60 seconds and 120 seconds. If this timeout expires, the partially-reassembled datagram MUST be discarded and an ICMP Time Exceeded message sent to the source host (if fragment zero has been received).

RFC 1122 §3.3.2, IMPLEMENTATION:

> However, note that, contrary to [IP:10], the first fragment header needs to be saved for inclusion in a possible ICMP Time Exceeded (Reassembly Timeout) message.

RFC 1122 requirements summary: "Send ICMP Time Exceeded on reassembly timeout |3.3.2 |x|" (MUST column).

## Suggested fix

When fragment 0 arrives, keep its IP header and first 8 payload bytes. On expiry, send ICMPv4 Time Exceeded code 1 to the source, best effort like the other stack-generated errors, with the usual suppression rules (no error to non-unicast sources, none about ICMP errors). Or list it under "Not yet implemented".
