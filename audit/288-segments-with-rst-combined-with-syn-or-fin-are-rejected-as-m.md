# 288. Segments with RST combined with SYN or FIN are rejected as malformed instead of being processed as resets

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/tcp/repr.rs:82](../src/tcp/repr.rs#L82), [src/stack.rs:1501](../src/stack.rs#L1501) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
`TcpRepr::parse` returns `Malformed` for any segment with more than one of SYN, FIN and RST set. The stack drops it silently. An in-window RST|FIN or RST|FIN|ACK, which some stacks and middleboxes send when they abort, does not reset the connection.

## Details
src/tcp/repr.rs:82:
```rust
let control = match (packet.syn(), packet.fin(), packet.rst(), packet.psh()) {
    (false, false, false, false) => TcpControl::None,
    (false, false, false, true) => TcpControl::Psh,
    (true, false, false, _) => TcpControl::Syn,
    (false, true, false, _) => TcpControl::Fin,
    (false, false, true, _) => TcpControl::Rst,
    _ => return Err(Malformed),
};
```
src/stack.rs:1501:
```rust
let Ok(tcp_repr) = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr) else {
    trace!("tcp: malformed packet");
    return;
};
```

## Failure scenario
The peer or a middlebox aborts with RST|FIN|ACK. xarxa drops it, keeps the connection, and retransmits into a dead peer until its own timeout.

## RFC reference
RFC 9293 §3.10.7.4, SEGMENT ARRIVES, after the sequence number check: "Second, check the RST bit:". No condition on SYN or FIN applies. No MUST explicitly requires accepting RST with FIN, so this is a robustness and interop deviation, not a MUST violation.

## Suggested fix
Map any segment with RST set to `TcpControl::Rst`, ignoring SYN and FIN, as Linux does. Keep rejecting SYN|FIN.
