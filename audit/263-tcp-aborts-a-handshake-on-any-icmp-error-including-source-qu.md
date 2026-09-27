# 263. TCP aborts a handshake on any ICMP error, including Source Quench

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:957](../src/tcp/mod.rs#L957), [src/icmp_error.rs:36](../src/icmp_error.rs#L36), [src/stack.rs:1636](../src/stack.rs#L1636) |
| Features | default (`icmp-errors`) |
| Verification | reproduced with a test |

## Summary
`from_icmpv4` maps Source Quench to `IcmpError::Other`, and it is delivered to sockets like any error. A Source Quench quoting our SYN aborts the connect. On a synchronized connection it is recorded as a soft error. It also reaches UDP sockets as `Other`. That is an undocumented MUST-55 violation. Aborting the handshake on soft errors (net/host unreachable, time exceeded, parameter problem) violates MUST-56, but is a documented decision (DESIGN.md §7, doc comment at mod.rs:937-945).

## Details
src/icmp_error.rs:36:
```rust
Icmpv4Message::TimeExceeded | Icmpv4Message::ParamProblem | Icmpv4Message::SourceQuench => {
```
src/stack.rs:1636 delivers every error type:
```rust
(msg_type, msg_code) if msg_type.is_error() => {
    if let Some(error) = IcmpError::from_icmpv4(msg_type, msg_code) {
        self.deliver_icmp_error(error, icmp_packet.data_mut());
```
src/tcp/mod.rs:957, in `process_icmp_error`:
```rust
State::SynSent | State::SynReceived => {
    debug!("{} during handshake, aborting connection", error);
    self.set_state(State::Closed);
    self.tuple = None;
}
```
The quoted seq must be in flight (mod.rs:951), which limits off-path spoofing. Routers rarely send Source Quench today.

## Failure scenario
A loaded router or on-path box sends a Source Quench quoting our SYN. `connect` fails immediately instead of retrying. On an established connection, `take_icmp_error()` reports it as `Other`.

## RFC reference
RFC 9293 §3.9.2.2: "TCP implementations MUST silently discard any received ICMP Source Quench messages (MUST-55)."

Same section: "Soft Errors: For IPv4 ICMP, these include: Destination Unreachable -- codes 0, 1, 5; Time Exceeded -- codes 0, 1; and Parameter Problem. ... a TCP implementation MUST NOT abort the connection (MUST-56)". It also notes "[35], Section 4 describes widespread implementation behavior that treats soft errors as hard errors during connection establishment."

## Reproduction
Test in the `src/tcp/mod.rs` `mod test` harness, scratch copy:
```rust
#[test]
fn vv_f4_source_quench_aborts_connect() {
    let e = IcmpError::from_icmpv4(crate::wire::Icmpv4Message::SourceQuench, 0);
    let mut s = socket_syn_sent();
    s.process_icmp_error(e.unwrap(), LOCAL_SEQ);
    assert_eq!(s.state, State::SynSent);
}
```
Output:
```
F4 mapping: Some(Other); F4 state: CLOSED
assertion failed: left: Closed, right: SynSent
```

## Suggested fix
Return `None` for Source Quench in `from_icmpv4`, so neither TCP nor UDP sees it. Optionally limit the handshake abort to hard errors (protocol/port unreachable, codes 2-4) plus the locally generated neighbor failure.
