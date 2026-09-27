# 268. A retransmitted bare FIN is answered under the 1/s challenge-ACK rate limit, although the comment says FINs are exempt

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/tcp/mod.rs:1191](../src/tcp/mod.rs#L1191), [src/tcp/mod.rs:903](../src/tcp/mod.rs#L903) |
| Features | default |
| Verification | reproduced with a test |

## Summary
A retransmitted bare FIN arrives at RCV.NXT-1 with no payload. It is out of window, and because the exemption requires a payload, it goes to `challenge_ack_reply`, limited to one reply per second. The comment above says FIN is exempt. This affects every synchronized state after the peer's FIN: CLOSE-WAIT, CLOSING, LAST-ACK and TIME-WAIT.

## Details
src/tcp/mod.rs:1184 comment: "The exemption covers FIN (a retransmitted final segment is the same lost-ACK situation)". The code:

src/tcp/mod.rs:1191
```rust
if !repr.payload.is_empty()
    && matches!(repr.control, TcpControl::None | TcpControl::Psh | TcpControl::Fin)
{
    return Some(self.ack_reply(now, repr));
}

return self.challenge_ack_reply(now, repr);
```
src/tcp/mod.rs:903: `challenge_ack_reply` returns `None` if `now < self.challenge_ack_timer`, else pushes the timer 1 s out.

## Failure scenario
Our ACK of the peer's FIN is lost. The peer retransmits the FIN at 200 ms and 600 ms. Only the first gets an ACK. If that ACK is lost too, the peer stays in LAST-ACK or CLOSING for at least another backoff round.

## RFC reference
RFC 9293 §3.10.7.4, TIME-WAIT: "The only thing that can arrive in this state is a retransmission of the remote FIN. Acknowledge it, and restart the 2 MSL timeout."

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn vv_f9_fin_retrans_rate_limited() {
    let mut s = socket_time_wait(false);
    recv!(s, [TcpRepr { seq_number: LOCAL_SEQ + 1 + 1, ack_number: Some(REMOTE_SEQ + 1 + 1), ..RECV_TEMPL }]);
    let fin = TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 1), ..SEND_TEMPL };
    let r1 = send(&mut s, Instant::from_millis(5000), &fin);
    let r2 = send(&mut s, Instant::from_millis(5400), &fin);
    assert!(r2.is_some());
}
```
Output: `r1=true r2=false`, assertion fails.

## Suggested fix
Exempt non-SYN segments with `segment_len() > 0` (payload or FIN), matching the comment.
