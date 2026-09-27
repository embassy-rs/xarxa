# 273. Peer's FIN (and other SYN/FIN segments) counted as duplicate ACKs for fast retransmit

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1426](../src/tcp/mod.rs#L1426) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The duplicate-ACK condition checks for an empty payload, an unchanged ACK, outstanding data and an unchanged window, but not the control flags. A bare FIN from the peer with the same ACK and window counts as a duplicate. With two genuine duplicates before it, this arms a spurious fast retransmit and a cwnd cut.

## Details
src/tcp/mod.rs:1426:
```rust
Some(last_rx_ack)
    if repr.payload.is_empty()
        && last_rx_ack == ack_number
        && ack_number < self.remote_last_seq
        && !is_window_update =>
```
Established+FIN, FinWait1/2+FIN and so on fall through to this code.

## Failure scenario
1. We have data in flight and receive two duplicate ACKs.
2. The peer closes with a bare FIN carrying the same ACK and window.
3. `local_rx_dup_acks` reaches 3 and `Timer::FastRetransmit` is armed. The next dispatch retransmits and calls `on_loss`.

## RFC reference
RFC 5681 §2: "An acknowledgment is considered a 'duplicate' ... when (a) the receiver of the ACK has outstanding data, (b) the incoming acknowledgment carries no data, (c) the SYN and FIN bits are both off, ..."

## Reproduction
In the `src/tcp/mod.rs` test module, with a helper `vcollect()` that dispatches and collects segments:
```rust
#[test] fn vtest_f2_fin_counts_as_dupack() {
    let mut s = socket_established();
    send!(s, time 0, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL });
    s.view().send_slice(b"abcdef").unwrap();
    let p = vcollect(&mut s, 10);
    for i in 0..2 {
        let _ = send(&mut s, Instant::from_millis(20 + i), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL });
    }
    let _ = send(&mut s, Instant::from_millis(30), &TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL });
    assert_eq!(s.local_rx_dup_acks, 3);
    assert_eq!(s.timer, Timer::FastRetransmit);
}
```
`cargo test --lib vtest_ -- --nocapture`:
```
dup=2 timer=Retransmit { expires_at: 1010 }
after FIN dup=3 timer=FastRetransmit state=CLOSE-WAIT
ok
```

## Suggested fix
Add `repr.control == TcpControl::None` (after `quash_psh`) to the condition.
