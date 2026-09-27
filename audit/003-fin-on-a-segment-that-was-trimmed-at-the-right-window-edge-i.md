# 003. TCP: FIN on a segment trimmed at the right window edge is still processed: stream truncated, unreceived data ACKed, clean EOF reported

| | |
|---|---|
| Severity | critical |
| Category | correctness |
| Location | [src/tcp/mod.rs:1236](../src/tcp/mod.rs#L1236), [src/tcp/mod.rs:1145](../src/tcp/mod.rs#L1145), [src/tcp/mod.rs:1263](../src/tcp/mod.rs#L1263), [src/tcp/mod.rs:1313](../src/tcp/mod.rs#L1313), [src/tcp/mod.rs:1329](../src/tcp/mod.rs#L1329), [src/tcp/mod.rs:1343](../src/tcp/mod.rs#L1343) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`process` drops a FIN only when the segment starts past RCV.NXT. It does not drop it when the segment's tail, where the FIN sits, was cut off at the right window edge. The truncated segment's FIN is accepted: `remote_seq_no += 1`, the socket goes to CLOSE-WAIT, and `recv` reports `Finished` after the truncated data. The ACK covers one sequence number that was never received. A conforming peer can trigger this when the RX buffer is larger than 65535 bytes, through our own window rounding.

## Details

src/tcp/mod.rs:1144-1151, the payload is clipped to the window:
```rust
let overlap_start = window_start.max(segment_start);
let overlap_end = window_end.min(segment_end);
...
&repr.payload[overlap_start - segment_start..overlap_end - segment_start],
```

src/tcp/mod.rs:1236, the only FIN guard:
```rust
if control == TcpControl::Fin && window_start < segment_start {
```

Then, for example src/tcp/mod.rs:1312-1316:
```rust
(State::Established, TcpControl::Fin) => {
    self.remote_seq_no += 1;
    self.rx_fin_received = true;
    self.set_state(State::CloseWait);
}
```

The FIN's real sequence number is `segment_end`, not `overlap_end`. The same unguarded handling is at line 1263 (SYN-RECEIVED), 1329 (FIN-WAIT-1) and 1343 (FIN-WAIT-2).

How a conforming peer hits it: `scaled_window()` (line 679-681) rounds the free space down to a multiple of 2^shift. So after an odd-sized segment the advertised right edge moves left by up to 2^shift - 1 bytes. A peer that fills the previously advertised window and ends with a FIN gets its last segment right-trimmed. The unscaled SYN window bug (002) is another path, and so is any peer that ignores the window.

After this the peer has its data ACKed and never resends it. Its retransmitted FIN reaches a socket in CLOSE-WAIT and is not ACKed, so the peer stays in FIN-WAIT-1.

## Failure scenario

- Misbehaving peer: RX window 64. The peer sends 70 bytes + FIN at RCV.NXT. We store 64 bytes, go to CLOSE-WAIT and ACK RCV.NXT + 65. The application gets 64 bytes, then `RecvError::Finished`. 6 bytes are lost.
- Conforming peer: RX buffer 65536, shift 1, first edge +65536. The peer sends 1 byte. We ACK with win 32767, so the edge becomes +65535. The peer, acting on the earlier window, fills up to +65000 and sends 536 bytes + FIN ending at +65536. We store 65535 bytes, go to CLOSE-WAIT and ACK +65536. That ACK covers all 65536 data bytes the peer sent, but only 65535 were stored. The application sees a clean EOF on a truncated stream.

## RFC reference

RFC 9293 §3.10.7.4: "In the following it is assumed that the segment is the idealized segment that begins at RCV.NXT and does not exceed the window. One could tailor actual segments to fit this assumption by trimming off any portions that lie outside the window (including SYN and FIN) and only processing further if the segment then begins at RCV.NXT."

## Reproduction

Tests in `mod test` of src/tcp/mod.rs, scratch copy of HEAD:

```rust
#[test]
fn zzv_fin_trimmed_small() {
    let mut s = socket_established();
    let data = [0x55u8; 70];
    let _ = send(&mut s, Instant::ZERO, &TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &data, ..SEND_TEMPL });
    println!("state {} rx {} fin {}", s.state, s.rx_buffer.len(), s.rx_fin_received);
    recv(&mut s, Instant::ZERO, 1, |_, r| println!("ACK {:?}", r.ack_number));
    let mut buf = [0u8; 128];
    println!("recv_slice {:?} then {:?}", s.view().recv_slice(&mut buf), s.view().recv_slice(&mut buf));
    assert_eq!(s.state, State::Established);
}

#[test]
fn zzv_fin_trimmed_by_rounding() {
    let mut s = socket_established_with_buffer_sizes(64, 65536);
    s.remote_win_scale = Some(0);
    assert_eq!(s.remote_last_win, 32768);
    let one = [0u8; 1];
    let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &one, ..SEND_TEMPL });
    recv(&mut s, Instant::ZERO, 1, |_, r| println!("ACK win {}", r.window_len));
    let chunk = [0u8; 1000];
    let mut off = 1;
    while off < 65000 {
        let len = (65000 - off).min(1000);
        let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + off, ack_number: Some(LOCAL_SEQ + 1), payload: &chunk[..len], ..SEND_TEMPL });
        off += len;
    }
    let _ = send(&mut s, Instant::ZERO, &TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1 + 65000, ack_number: Some(LOCAL_SEQ + 1), payload: &chunk[..536], ..SEND_TEMPL });
    println!("state {} rx {} fin {}", s.state, s.rx_buffer.len(), s.rx_fin_received);
    recv(&mut s, Instant::ZERO, 1, |_, r| println!("ACK {:?} = +{}", r.ack_number, r.ack_number.unwrap() - (REMOTE_SEQ + 1)));
    assert_eq!(s.rx_buffer.len(), 65536);
}
```

`cargo test --lib zzv_ -- --nocapture`:
```
state CLOSE-WAIT rx 64 fin true
ACK Some(SeqNumber(-9935))          (REMOTE_SEQ+1+64 = SeqNumber(-9936))
recv_slice Ok(64) then Err(Finished)
assertion failed: left CloseWait, right Established

ACK win 32767
state CLOSE-WAIT rx 65535 fin true
ACK Some(SeqNumber(55536)) = +65536
assertion failed: left 65535, right 65536
```

## Suggested fix

Treat the FIN as present only if the segment was not trimmed on the right: clear `control` when `overlap_end != segment_end`. Check SYN handling for the same trimming. Separately, the edge retraction from rounding (RFC 7323 §2.4) is worth avoiding on its own.
