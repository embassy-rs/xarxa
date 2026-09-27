# 257. RTO is not re-initialized to 3 s after a handshake that needed a SYN retransmission

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:343](../src/tcp/mod.rs#L343), [src/tcp/mod.rs:238](../src/tcp/mod.rs#L238) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The initial RTO is 1 s. A SYN timeout doubles it, and Karn's rule means the SYN|ACK gives no sample. The connection enters ESTABLISHED with RTO 2 s (or whatever the backoff reached). RFC 6298 (5.7) requires 3 s here.

## Details
src/tcp/mod.rs:238:
```rust
const RTTE_INITIAL_RTO: u32 = 1000;
```
src/tcp/mod.rs:347, in `on_rto`:
```rust
self.rto = (self.rto * 2).min(RTTE_MAX_RTO);
```
`on_retransmit` (mod.rs:363) clears the pending sample, and `on_send` does not re-arm it for the same seq. Nothing on the SYN-SENT/SYN-RECEIVED to ESTABLISHED path touches the RTO. `RttEstimator` has no flag for a handshake retransmission.

## Failure scenario
The first SYN is lost. The SYN is retransmitted at 1 s and answered at 1.1 s. The first data segment is delayed more than 2 s on this slow path. It is retransmitted at 2 s instead of 3 s: a spurious retransmission and a cwnd collapse.

## RFC reference
RFC 6298 (5.7): "If the timer expires awaiting the ACK of a SYN segment and the TCP implementation is using an RTO less than 3 seconds, the RTO MUST be re-initialized to 3 seconds when data transmission begins (i.e., after the three-way handshake completes)."

## Reproduction
Test in the `src/tcp/mod.rs` `mod test` harness, scratch copy:
```rust
#[test]
fn zz_syn_rto() {
    let mut s = socket_syn_sent();
    let syn = TcpRepr { control: TcpControl::Syn, seq_number: LOCAL_SEQ, ack_number: None,
        max_seg_size: Some(BASE_MSS), window_scale: Some(0),
        #[cfg(feature = "tcp-sack")] sack_permitted: true, ..RECV_TEMPL };
    recv!(s, time 0, [syn]);
    recv!(s, time 1000, [syn]);
    send!(s, time 1100, TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ,
        ack_number: Some(LOCAL_SEQ + 1), max_seg_size: Some(BASE_MSS - 80),
        window_scale: Some(0), ..SEND_TEMPL });
    assert_eq!(s.state, State::Established);
    std::println!("rto after handshake with SYN retransmit: {}", s.rtte.rto);
}
```
Output:
```
rto after handshake with SYN retransmit: 2000
```

## Suggested fix
Record that a handshake segment was retransmitted. On entering ESTABLISHED with no RTT sample, set `rto = max(rto, 3000)`.
