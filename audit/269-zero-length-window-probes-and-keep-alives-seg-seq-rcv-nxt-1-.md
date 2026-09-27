# 269. Zero-length window probes and keep-alives (SEG.SEQ = RCV.NXT-1) are throttled by the 1/s challenge-ACK limiter and go unanswered

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1191](../src/tcp/mod.rs#L1191), [src/tcp/mod.rs:903](../src/tcp/mod.rs#L903) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Linux and BSD send zero-window probes and keep-alives as empty segments at RCV.NXT-1. They are unacceptable and carry no payload, so xarxa answers them through `challenge_ack_reply`, one reply per second. Linux's probes start 200 ms apart, so the second is always ignored. Any unrelated empty unacceptable segment (a duplicated pure ACK) in the previous second also silences the next probe or keep-alive. Related to 268: same limiter, different segment class.

## Details
src/tcp/mod.rs:1191: only segments with payload are exempt (see 268 for the excerpt). The limiter timer in `challenge_ack_reply` (src/tcp/mod.rs:903) is shared with the RFC 5961 challenges.

Capture, Linux sending 1 MB to a xarxa socket whose app does not read (64 KiB buffer):
```
5.749423 L probe seq 65536 len 0   -> 5.749453 X ack 65537 win 0
6.157423 L probe seq 65536 len 0   -> (no reply)
6.965425 L probe seq 65536 len 0   -> 6.965456 X ack 65537 win 0
```
Linux recovers on the next answered probe, and xarxa sends a window update when it reopens. A peer with a short keep-alive interval and a low probe count may count missed replies toward declaring the connection dead.

## Failure scenario
Our window is zero. The peer probes at 200 ms, 400 ms, ... Every probe within 1 s of the last answered one is dropped silently.

## RFC reference
- RFC 9293 §3.8.6.1: "When the receiving TCP peer has a zero window and a segment arrives, it must still send an acknowledgment showing its next expected sequence number and current window (zero)."
- RFC 9293 §3.10.7.4: "If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return)".
- RFC 5961 §7: "In order to alleviate multiple RSTs/SYNs from triggering multiple challenge ACKs, an ACK throttling mechanism is suggested". The throttle is scoped to RFC 5961 challenge ACKs.

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn zz_keepalive_probe_throttled() {
    let mut s = socket_established();
    let probe = TcpRepr { seq_number: REMOTE_SEQ, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL };
    let r1 = send(&mut s, Instant::from_millis(1000), &probe);
    let r2 = send(&mut s, Instant::from_millis(1400), &probe);
    let r3 = send(&mut s, Instant::from_millis(2200), &probe);
    assert!(r1.is_some());
    assert!(r2.is_some(), "second probe within 1s got no ACK");
}
```
Output:
```
probe1 reply Some(Some(SeqNumber(-10000)))
probe2 (400ms later) reply None
probe3 reply Some(Some(SeqNumber(-10000)))
panicked: second probe within 1s got no ACK
```

## Suggested fix
Keep the limiter only for RFC 5961 cases (in-window SYN, non-exact RST, unacceptable ACK). Answer ordinary unacceptable segments, or at least empty non-SYN non-RST segments at RCV.NXT-1, with a plain ACK.
