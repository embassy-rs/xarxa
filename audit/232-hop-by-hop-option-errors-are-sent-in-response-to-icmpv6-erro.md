# 232. Hop-by-hop option errors are sent in response to ICMPv6 error messages

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1730](../src/stack.rs#L1730), [src/stack.rs:2090](../src/stack.rs#L2090) |
| Features | default |
| Verification | reproduced with a test |

## Summary
An unrecognized hop-by-hop option with action bits 10 or 11 makes the stack send a Parameter Problem. It never looks at the upper-layer header first. If that header is an ICMPv6 error or a Redirect, the stack sends an error about an error. With action 10 this also happens for multicast destinations.

## Details
src/stack.rs:1730:
```rust
HopByHopAction::DiscardSendError {
    pointer,
    allow_multicast_dst,
} => {
    self.transmit_icmpv6_error(
        iface,
        &mut buf,
        Icmpv6Message::ParamProblem,
        Icmpv6ParamProblem::UnrecognizedOption.into(),
        pointer,
        allow_multicast_dst,
    );
    return;
}
```
`transmit_icmpv6_error` (src/stack.rs:2090) only checks that the source is unicast and that the destination is not multicast unless `allow_multicast_dst`. The "no error about an error" check exists only in `deliver_neighbor_failure_error` (src/stack.rs:2008).

## Failure scenario
A peer sends IPv6 + HBH(next header 58, option type 0x80) + ICMPv6 Destination Unreachable to us, or to ff02::1. The stack replies with Parameter Problem code 2. Two nodes with the same behavior can ping-pong errors.

## RFC reference
RFC 4443 §2.4(e): "An ICMPv6 error message MUST NOT be originated as a result of receiving the following: (e.1) An ICMPv6 error message. (e.2) An ICMPv6 redirect message [IPv6-DISC]."

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
fn vt_hbh_error_about_error() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let mut icmp = vec![0u8; 8 + 48];
    icmp[0] = 1; // Destination Unreachable
    let options = [0x80, 0x04, 0x00, 0x00, 0x00, 0x00];
    let packet = ipv6_packet(REMOTE_V6, OUR_V6, IpProtocol::HopByHop, &hbh_payload(IpProtocol::Icmpv6, &options, &icmp));
    inject(&mut stack, &rx, packet);
    let tx = tx.borrow();
    assert_eq!(tx.len(), 1);
    let (t, c, p, _) = parse_icmpv6_reply(&tx[0], OUR_V6, REMOTE_V6);
    println!("VT2 type {:?} code {} ptr {}", t, c, p);
    assert_eq!(t, Icmpv6Message::ParamProblem);
}
```
`cargo test --lib vt_ -- --nocapture` prints `VT2 type ParamProblem code 2 ptr 42`. The test passes, so the error about an error was sent.

## Suggested fix
Before sending, look at the header after the HBH header. If it is ICMPv6 with an error type (< 128) or Redirect (137), drop silently. The check in `deliver_neighbor_failure_error` can be shared, ideally inside `transmit_icmpv6_error`.
