# 002. TCP: unscaled SYN/SYN|ACK window is stored in remote_last_win and later left-shifted, so a peer can overrun the RX ring and panic the stack (RX buffers > 65535 bytes)

| | |
|---|---|
| Severity | critical |
| Category | panic |
| Location | [src/tcp/mod.rs:1092](../src/tcp/mod.rs#L1092), [src/tcp/mod.rs:1979](../src/tcp/mod.rs#L1979), [src/tcp/mod.rs:2164](../src/tcp/mod.rs#L2164), [src/tcp/mod.rs:1145](../src/tcp/mod.rs#L1145), [src/tcp/mod.rs:1550](../src/tcp/mod.rs#L1550), [src/tcp/ring_buffer.rs:341](../src/tcp/ring_buffer.rs#L341), [src/tcp/mod.rs:697](../src/tcp/mod.rs#L697) |
| Features | default |
| Verification | reproduced with a test |

## Summary

Our SYN and SYN|ACK carry an unscaled window, as RFC 7323 requires, and `send_segment` records that raw value in `remote_last_win`. The receive check then shifts it left by `remote_win_shift`, so the right edge is up to 2^shift times the real free space. Data past the real space is accepted, only partly written to the ring, but fully recorded in the assembler. When the gap fills, `enqueue_unallocated` hits a release `assert!` and the whole stack panics. If the island fits, never-written stale ring bytes are delivered to the application and ACKed instead.

## Details

src/tcp/mod.rs:1978-1979, the SYN / SYN|ACK in `dispatch`:
```rust
// window len must NOT be scaled in SYNs.
window_len: u16::try_from(self.rx_buffer.window()).unwrap_or(u16::MAX),
```

src/tcp/mod.rs:2164, in `send_segment`:
```rust
self.ack_sent(repr.ack_number, repr.window_len);
```

So `remote_last_win = 65535` for any RX buffer of 65535 bytes or more. `remote_win_shift` is `bitlen(capacity) - 16` (src/tcp/mod.rs:618, 642): 1 for 65536 or 100000, 2 for 131072. Once capacity > 65535, `65535 << shift` is always larger than the capacity.

src/tcp/mod.rs:1091-1092, in `process`:
```rust
let window_end = if let Some(last_ack) = self.remote_last_ack {
    last_ack + ((self.remote_last_win as usize) << self.remote_win_shift)
```

With a 65536-byte buffer the edge is RCV.NXT + 131070. An accepted segment is clipped only to `window_end` (src/tcp/mod.rs:1145-1153). Then:

src/tcp/mod.rs:1550-1551
```rust
let len_written = self.rx_buffer.write_unallocated(payload_offset, payload);
debug_assert!(len_written == payload_len);
```

`write_unallocated` writes only what fits. The assembler, called just before (line 1527), has already recorded the whole range. When in-order data fills the hole, `add_then_remove_front` returns a `contig_len` larger than the free space, and:

src/tcp/ring_buffer.rs:341
```rust
assert!(count <= self.window());
```

`last_scaled_window` (line 697) reads the same stored value with the same shift, so `window_to_update` sees a last window of 65535 and does not send a correcting update.

How long the bad edge lasts:
- SYN-RECEIVED (accepted socket, or simultaneous open): until we send any non-SYN segment. The handshake-completing ACK alone does not make an ACK due, so the peer has as long as it wants.
- SYN-SENT: `remote_last_ack` is set to the SYN|ACK's seq (line 1286) with the old unscaled `remote_last_win`. The dispatch at the end of the same poll corrects it, so only segments in the same ingress batch as the SYN|ACK see the inflated edge.

The immediate ACK for an out-of-order segment fixes `remote_last_win`, but the island is already in the assembler. The peer then fills the gap inside the corrected window, which is legal from that point on.

The maintainer's fuzz harness uses 2048-byte TCP buffers, so it cannot reach this.

## Failure scenario

1. A listener-accepted socket has an RX buffer of 65536 bytes (shift 1). The client offers window scaling.
2. The client sends the handshake ACK with 100 bytes at RCV.NXT + 65536. It is accepted, since the edge is +131070. Nothing is written to the ring. The assembler holds `[ (65536) 100 ]`.
3. The client sends bytes 0..65536 in order.
4. `enqueue_unallocated` panics in `Stack::poll`, in release builds too.

A malicious server can do the same to a client in SYN-SENT by sending data in the same batch as its SYN|ACK. If the application reads while this happens and the island fits in the free space, no panic occurs: bytes that were never written, possibly from an earlier connection on a reused buffer, are delivered as stream data and ACKed.

## RFC reference

RFC 7323 §2.2: "The window field in a segment where the SYN bit is set (i.e., a <SYN> or <SYN,ACK>) MUST NOT be scaled."

The emitted window is correct. The bug is that the stored copy is then treated as scaled.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, scratch copy of HEAD:

```rust
#[test]
fn zzv_syn_window_unscaled_overrun() {
    let mut s = socket_syn_received_with_buffer_sizes(64, 65536);
    s.remote_win_scale = Some(0);
    assert_eq!(s.remote_win_shift, 1);
    recv(&mut s, Instant::ZERO, 1, |_, r| { assert_eq!(r.control, TcpControl::Syn); });
    println!("remote_last_win {} shift {} -> edge +{}", s.remote_last_win, s.remote_win_shift, (s.remote_last_win as usize) << s.remote_win_shift);
    let far = [0xAAu8; 100];
    let r = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + 65536, ack_number: Some(LOCAL_SEQ + 1), payload: &far, ..SEND_TEMPL });
    println!("state {} reply {:?} assembler {}", s.state, r.map(|r| (r.ack_number, r.window_len)), s.assembler);
    let chunk = [0x11u8; 1000];
    let mut off = 0;
    while off < 65536 {
        let len = (65536 - off).min(1000);
        let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + off, ack_number: Some(LOCAL_SEQ + 1), payload: &chunk[..len], ..SEND_TEMPL });
        off += len;
    }
}
```

`cargo test --lib zzv_syn_window -- --nocapture`:
```
remote_last_win 65535 shift 1 -> edge +131070
panicked at src/tcp/mod.rs:1551:9: assertion failed: len_written == payload_len
```

`CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false cargo test --lib zzv_syn_window -- --nocapture`:
```
state ESTABLISHED reply Some((Some(SeqNumber(-10000)), 32768)) assembler [ (65536) 100 ]
panicked at src/tcp/ring_buffer.rs:341:9: assertion failed: count <= self.window()
```

## Suggested fix

- Record the SYN window so that `remote_last_win << remote_win_shift` equals what was really advertised. For example, store it pre-shifted (rounded down), or keep the right edge in bytes.
- Independently, clip accepted payload to the free space in the ring, and never record in the assembler more than was written.
