# 031. ICMP Source Quench is delivered to TCP and aborts connections in SYN-SENT/SYN-RECEIVED

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/icmp_error.rs:36](../src/icmp_error.rs#L36), [src/tcp/mod.rs:956](../src/tcp/mod.rs#L956), [src/stack.rs:1636](../src/stack.rs#L1636) |
| Features | default (`icmp-errors`, `tcp`, `ipv4`) |
| Verification | reproduced with a test |

## Summary
`IcmpError::from_icmpv4` maps ICMPv4 Source Quench to `Some(IcmpError::Other)`. TCP aborts any connection still in the handshake on any delivered ICMP error. So a Source Quench quoting our SYN kills a `connect()`. RFC 9293 requires TCP to silently discard Source Quench.

## Details
src/icmp_error.rs:36:
```rust
Icmpv4Message::TimeExceeded | Icmpv4Message::ParamProblem | Icmpv4Message::SourceQuench => {
    Some(IcmpError::Other)
}
```

`Icmpv4Message::is_error()` includes `SourceQuench` (src/wire/icmpv4.rs:44), so `process_icmpv4` passes it on.

src/stack.rs:1636:
```rust
(msg_type, msg_code) if msg_type.is_error() => {
    if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
        self.deliver_icmp_error(error, icmp_packet.data_mut());
    }
}
```

`TcpSocketState::process_icmp_error` checks only that the quoted seq is in `[local_seq_no, remote_last_seq]`, then:

src/tcp/mod.rs:956:
```rust
State::SynSent | State::SynReceived => {
    debug!("{} during handshake, aborting connection", error);
    self.set_state(State::Closed);
    self.tuple = None;
}
```

In synchronized states the quench is recorded and returned by `take_icmp_error()`. UDP gets it too, as `IcmpError::Other` from `recv()`. Neither is useful for a deprecated message.

## Failure scenario
A legacy router, or an on-path sender that sees the ISN, answers our SYN with ICMP type 4 quoting it. The socket goes to `Closed` and `take_icmp_error()` returns `Some(Other)`. The connect fails instead of the quench being ignored.

## RFC reference
RFC 9293 §3.9.2.2:

> Source Quench: TCP implementations MUST silently discard any received ICMP Source Quench messages (MUST-55).

Related, and a documented design choice (DESIGN.md §7): the same path aborts the handshake on soft errors (Time Exceeded, Parameter Problem, Destination Unreachable codes 0, 1, 5). RFC 9293 §3.9.2.2 says "a TCP implementation MUST NOT abort the connection (MUST-56)" for those, while noting that treating them as hard during connection establishment is widespread practice. This finding is only about Source Quench.

## Reproduction
Test added to `mod test` in src/stack.rs, in a scratch copy of HEAD:
```rust
#[test]
fn verif_source_quench_aborts_connect() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let handle = stack.add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak()).unwrap();
    stack.tcp_socket(handle).connect((REMOTE_V4, 80), 0).unwrap();
    stack.poll(Instant::ZERO);
    assert_eq!(stack.tcp_socket(handle).state(), TcpState::SynSent);
    let syn = tx.borrow().last().unwrap().clone();
    let error = icmpv4_error_packet(REMOTE_V4, OUR_V4, Icmpv4Message::SourceQuench, 0, &syn[..28]);
    inject(&mut stack, &rx, error);
    let st = stack.tcp_socket(handle).state();
    let e = stack.tcp_socket(handle).take_icmp_error();
    println!("after source quench: state {:?} err {:?}", st, e);
    assert_eq!(st, TcpState::SynSent, "source quench must be silently discarded");
}
```

`cargo test --lib verif_source_quench -- --nocapture`:
```
after source quench: state Closed err Some(Other)
panicked: assertion `left == right` failed: source quench must be silently discarded
  left: Closed
 right: SynSent
```

## Suggested fix
Map `Icmpv4Message::SourceQuench` to `None` in `from_icmpv4`, like redirects. Update the `IcmpError::Other` doc (src/error.rs:130) if it ends up listing message types.
