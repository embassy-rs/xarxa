# 274. Duplicate ACKs after the third that arrive before dispatch never inflate cwnd

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1443](../src/tcp/mod.rs#L1443), [src/tcp/mod.rs:1861](../src/tcp/mod.rs#L1861), [src/tcp/congestion/cubic.rs:171](../src/tcp/congestion/cubic.rs#L171), [src/tcp/congestion/reno.rs:70](../src/tcp/congestion/reno.rs#L70) |
| Features | tcp-cubic (default) or tcp-reno |
| Verification | reproduced with a test |

## Summary
The third duplicate ACK only arms `Timer::FastRetransmit`. `on_loss`, which sets `in_fast_recovery`, runs later in `dispatch`. Duplicate ACKs 4..N handled in the same poll reach `on_dup_ack` while `in_fast_recovery` is false and are ignored. cwnd starts recovery at ssthresh + 3*SMSS regardless of how many segments left the network.

## Details
src/tcp/mod.rs:1443: on dup ACK #3, `self.timer.set_for_fast_retransmit();`, then `on_dup_ack`.

src/tcp/congestion/cubic.rs:171 (reno.rs:70 is the same): `on_dup_ack` only adds `len` to cwnd `if self.in_fast_recovery`.

src/tcp/mod.rs:1861: `self.congestion_controller.on_loss(now, in_flight);` runs in `dispatch`, after all ingress of the poll. A burst of dup ACKs usually arrives in one RX drain.

## Failure scenario
10 segments of 100 bytes in flight, the first lost. 9 dup ACKs arrive before dispatch. After dispatch, cwnd = 1000 = ssthresh (700) + 3*100. RFC 5681 step 4 would give 1600. Recovery sends fewer new segments. No stall.

## RFC reference
RFC 5681 §3.2 step 4: "For each additional duplicate ACK received (after the third), cwnd MUST be incremented by SMSS."

## Reproduction
`src/tcp/mod.rs` test module:
```rust
#[test] fn vtest_f3_dupacks_same_batch() {
    let mut s = socket_established_with_buffer_sizes(6000, 64);
    s.remote_mss = 100; s.congestion_controller.set_mss(100);
    send!(s, time 0, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), window_len: 20000, ..SEND_TEMPL });
    s.view().send_slice(&[0u8; 1000]).unwrap();
    let p = vcollect(&mut s, 10);
    for i in 0..9 {
        let _ = send(&mut s, Instant::from_millis(20 + i), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), window_len: 20000, ..SEND_TEMPL });
    }
    let p = vcollect(&mut s, 40);
    println!("{:?} cc={:?}", p, s.congestion_controller);
}
```
Output:
```
after 9 dupacks cc=Cubic { cwnd: 2048, ssthresh: MAX, in_fast_recovery: false }
dispatch [(10001, None, 100, ..)] cc=Cubic { cwnd: 1000, mss: 100, ssthresh: 700, in_fast_recovery: true }
```

## Suggested fix
Call `on_loss` when the third duplicate ACK is processed and leave only the retransmission for dispatch. Or count dup ACKs above 3 and apply them in `on_loss`.
