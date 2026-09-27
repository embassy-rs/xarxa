# 018. The zero-window probe byte is not counted as sent, so when both ends probe at once each drops the other's ACKs and window updates, with no loss

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:2048](../src/tcp/mod.rs#L2048), [src/tcp/mod.rs:1919](../src/tcp/mod.rs#L1919), [src/tcp/mod.rs:2069](../src/tcp/mod.rs#L2069), [src/tcp/mod.rs:2127](../src/tcp/mod.rs#L2127), [src/tcp/mod.rs:881](../src/tcp/mod.rs#L881), [src/tcp/mod.rs:1105](../src/tcp/mod.rs#L1105) |
| Features | default (also `tcp-reno` without timestamps or SACK) |
| Verification | reproduced with a test |

## Summary

A zero-window probe carries one new octet at SEQ = `remote_last_seq`, but `remote_last_seq` is deliberately not advanced. If the peer's window has reopened when the probe arrives, the peer accepts the octet and its RCV.NXT moves one past our SND.NXT. Every later pure ACK or window update from us has SEG.SEQ = RCV.NXT - 1 and the peer drops it before processing its ACK and window. Normally the peer's ACK of the probe byte resyncs us. When both ends probe each other and both reopen within one one-way delay, each drops the other's ACKs, and both stay in persist state forever with both windows actually open.

## Details

src/tcp/mod.rs:2044-2066:

```rust
// A zero-window probe is the next octet of data, past the edge of the
// window. It isn't counted as sent, so the rest of the state is left
// intact. ...
if let Timer::ZeroWindowProbe { expires_at, delay } = self.timer
    && clock.expired(expires_at)
{
    trace!("sending a zero-window probe");
    let offset = self.flight_size();
    let payload = self.tx_buffer.get_allocated(offset, 1);
    send(TcpRepr {
        control: data_control(offset, payload.len()),
        seq_number: self.remote_last_seq,
        payload,
        ..repr
    })?;
    self.ack_sent(repr.ack_number, repr.window_len);
```

Neither `remote_last_seq` nor `rtte.max_seq_sent` is updated. Later pure ACKs go out with SEQ = `remote_last_seq` (src/tcp/mod.rs:1919, 2069-2071 via `send_segment` at 2127, and `ack_reply` at 881).

On the peer, a zero-length segment one below RCV.NXT hits the keep-alive branch, src/tcp/mod.rs:1105-1108:

```rust
(true, _) if segment_end == window_start - 1 => {
    debug!("received a keep-alive or window probe packet, will send an ACK");
    false
}
```

The segment is then dropped before its ACK and window are processed.

One-sided case: our ACKs are discarded until the peer's ACK of the probe byte reaches us. That ACK is itself a pure ACK. If it is lost, resync waits for our next probe, which backs off exponentially.

This is a separate bug from the ZWP timer stalls. Here every timer is armed and every probe is answered. The answers are dropped because of the uncounted byte. Root cause is shared with 017: pure ACKs use a SEQ below what the peer has accepted.

A two-stack netsim with no loss, duplication or reordering (A->B 45 ms + 7 ms jitter, B->A 70 ms + 23 ms jitter, 4 KiB rx, 20 kB each way, readers resuming at 2308 ms and 2328 ms) was still stuck at 304 s simulated. A random scan of that shape hit it in 18 of 4000 runs.

## Failure scenario

Two peers exchange data in both directions and both read slowly, for example two embedded nodes that each fill the other's small receive buffer. Both windows reach zero and both sides probe. Both applications resume reading at about the same time. Each side accepts the other's probe byte, and each side's window update and probe ACK are dropped. The connection never resumes, with zero packet loss.

## RFC reference

RFC 9293 §3.8.6.1:

> The sending TCP peer must regularly transmit at least one octet of new data (if available), or retransmit to the receiving TCP peer even if the send window is zero, in order to "probe" the window. This retransmission is essential to guarantee that when either TCP peer has a zero window the reopening of the window will be reliably reported to the other.

RFC 9293 §3.10.7.4, zero-length acceptability: "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND". Once the peer accepted the probe octet, segments that do not count it fall below RCV.NXT.

## Reproduction

Same helpers as 017 (`zz_own`, `zz_out`, `zz_deliver`, `zz_pair`, `zz_pair_mss`, `zz_exchange`), in `mod test` of src/tcp/mod.rs, in a scratch copy of HEAD.

```rust
#[test]
fn zz_zwp_mutual_hang() {
    let (mut a, mut b) = zz_pair_mss(64, 8, 100, 8);
    a.view().send_slice(&[b'a'; 32]).unwrap();
    b.view().send_slice(&[b'b'; 32]).unwrap();
    let t0 = Instant::from_millis(0);
    zz_exchange(&mut a, &mut b, t0, true);
    let t = a.deadline.min(b.deadline);
    let pa = zz_out(&mut a, t); let pb = zz_out(&mut b, t);      // both probe
    let mut buf = [0u8; 64];
    let mut got_a = a.view().recv_slice(&mut buf).unwrap();       // both apps read
    let mut got_b = b.view().recv_slice(&mut buf).unwrap();
    let wa = zz_out(&mut a, t); let wb = zz_out(&mut b, t);      // window updates
    let mut ra = Vec::new(); let mut rb = Vec::new();
    for r in &pa { if let Some(x) = zz_deliver(&mut b, t, r) { rb.push(x); } }
    for r in &pb { if let Some(x) = zz_deliver(&mut a, t, r) { ra.push(x); } }
    for r in &wa { if let Some(x) = zz_deliver(&mut b, t, r) { rb.push(x); } }
    for r in &wb { if let Some(x) = zz_deliver(&mut a, t, r) { ra.push(x); } }
    for r in &ra { let _ = zz_deliver(&mut b, t, r); }
    for r in &rb { let _ = zz_deliver(&mut a, t, r); }
    // lossless, zero delay from here on, apps keep reading
    loop { let t = a.deadline.min(b.deadline); if t > Instant::from_millis(600_000) { break; }
        zz_exchange(&mut a, &mut b, t, false);
        while let Ok(n) = a.view().recv_slice(&mut buf) { if n == 0 { break; } got_a += n; }
        while let Ok(n) = b.view().recv_slice(&mut buf) { if n == 0 { break; } got_b += n; } }
    assert!(got_a == 32 && got_b == 32, "stalled with zero loss");
}
```

Output (excerpt):

```
A: win=0 timer=ZeroWindowProbe { expires_at: 200, delay: 200 } rx=8; B: win=0 timer=ZeroWindowProbe { expires_at: 200, delay: 200 } rx=8
  A probe seq=10009 ack=Some(-9992) len=1 win=0
  B probe seq=-9992 ack=Some(10009) len=1 win=0
  A wupd seq=10009 ack=Some(-9992) len=0 win=8
  B wupd seq=-9992 ack=Some(10009) len=0 win=8
  A reply seq=10009 ack=Some(-9991) len=0 win=7
  B reply seq=-9992 ack=Some(10010) len=0 win=7
t=600 / 1400 / 3000 / ... / 222200:
  A>B seq=10009 ack=Some(-9991) len=1 win=8
  B>A seq=-9992 ack=Some(10010) len=1 win=8
  A>B seq=10009 ack=Some(-9991) len=0 win=8
  B>A seq=-9992 ack=Some(10010) len=0 win=8
after 600s: A got 9 B got 9; A win=0 timer=ZeroWindowProbe { expires_at: 642200, delay: 60000 }; B win=0 timer=ZeroWindowProbe { expires_at: 642200, delay: 60000 }
panicked: stalled with zero loss
```

## Suggested fix

One of:

- Count a probe that carries a new octet as sent: advance `remote_last_seq` / SND.MAX and let it be retransmitted normally.
- Send pure ACKs at the highest sequence number ever sent, probe octets included (the fix for 017).
- Probe like Linux, with SEG.SEQ = SND.UNA - 1 and no new data. The peer always answers without consuming anything.

The first two also fix the one-sided delay.
