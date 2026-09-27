# 351. RST to an unmatched non-SYN segment without ACK omits the ACK field

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:846](../src/tcp/mod.rs#L846), [src/stack.rs:1537](../src/stack.rs#L1537) |
| Features | `tcp` |
| Verification | confirmed against the RFC text |

## Summary
`rst_reply` sets the ACK field only when the incoming segment is a SYN without ACK. For other segments without ACK (a bare FIN or PSH, which the parser accepts) it sends `<SEQ=0><CTL=RST>`. RFC 9293 asks for `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`. There is no practical effect: the RFC reply also has SEQ=0, and the ACK only matters to a peer in SYN-SENT, whose SYNs are already handled. Also reported as tcp-scenarios-21 and x-panics-13.

## Details
src/tcp/mod.rs:846:
```rust
reply_repr.seq_number = repr.ack_number.unwrap_or_default();
if repr.control == TcpControl::Syn && repr.ack_number.is_none() {
    reply_repr.ack_number = Some(repr.seq_number + repr.segment_len());
}
```
Used by the unmatched-segment fallback in src/stack.rs:1537.

## Failure scenario
A peer sends a FIN without ACK to a closed port. xarxa answers RST, seq 0, no ACK. The wire format differs from the RFC. The peer's handling is the same as for the RFC-compliant reply.

## RFC reference
RFC 9293 §3.10.7.1: "If the ACK bit is off, sequence number zero is used, <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> If the ACK bit is on, <SEQ=SEG.ACK><CTL=RST>"

## Suggested fix
Set `reply_repr.ack_number = Some(repr.seq_number + repr.segment_len())` whenever `repr.ack_number.is_none()`.
