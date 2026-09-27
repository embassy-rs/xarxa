# 080. Window scale rounding retracts the advertised right edge, and data that was in window for an earlier ACK is trimmed (RFC 7323 §2.4 MUST)

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1091](../src/tcp/mod.rs#L1091), [src/tcp/mod.rs:679](../src/tcp/mod.rs#L679), [src/tcp/mod.rs:1144](../src/tcp/mod.rs#L1144) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`scaled_window()` rounds the free receive buffer down to a multiple of 2^shift. After k < 2^shift bytes arrive, the next ACK can put the right edge up to 2^shift - 1 bytes left of the previous one. `process()` accepts data only up to the edge of the most recent ACK. So bytes the peer was allowed to send are trimmed and must be retransmitted. Only rx buffers larger than 65535 bytes (shift >= 1) are affected.

## Details

src/tcp/mod.rs:679:

```rust
fn scaled_window(&self) -> u16 {
    u16::try_from(self.rx_buffer.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
}
```

src/tcp/mod.rs:1091, the edge comes from the latest ACK only:

```rust
let window_end = if let Some(last_ack) = self.remote_last_ack {
    last_ack + ((self.remote_last_win as usize) << self.remote_win_shift)
} else {
    window_start
};
```

The payload is then trimmed to `window_end` (mod.rs:1144-1153). Nothing tracks the highest edge ever advertised.

Example with rx = 100000 and shift 1. The first ACK advertises 50000, so the edge is +100000. After 1 byte arrives the free space is 99999, sent as 49999, so the edge is 1 + 99998 = +99999. It moved left by one byte.

## Failure scenario

A bulk transfer into a socket with an rx buffer over 64 KiB, with a reader slower than the sender, so the peer keeps the window full. Each time the edge retracts, the tail of the peer's segment that ends at the old edge is dropped. The bytes are not ACKed, so the peer recovers them by fast retransmit, or by RTO if too few segments follow. The result is repeated retransmissions whenever the buffer fills. If the trimmed segment carries a FIN, the stream is truncated (x-panics-3, reported separately).

## RFC reference

RFC 7323 §2.4:

> Implementations MUST ensure that they handle a shrinking window, as specified in Section 4.2.2.16 of [RFC1122].
>
> For the receiver, this implies that:
>
> 1) The receiver MUST honor, as in window, any segment that would have been in window for any <ACK> sent by the receiver.
>
> 2) When window scaling is in effect, the receiver SHOULD track the actual maximum window sequence number (which is likely to be greater than the window announced by the most recent <ACK>, if more than one segment has arrived since the application consumed any data in the receive buffer).

## Reproduction

Added to `mod test` in src/tcp/mod.rs, in a scratch copy:

```rust
#[test]
fn zzv_window_rounding_retracts_edge() {
    let mut s = socket_established_with_buffer_sizes(64, 100_000);
    s.remote_win_scale = Some(0);
    assert_eq!(s.remote_win_shift, 1);
    assert_eq!(s.remote_last_win, 50000);
    let one = [0u8; 1];
    let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &one, ..SEND_TEMPL });
    recv(&mut s, Instant::ZERO, 1, |_, r| { assert_eq!(r.window_len, 49999); });
    let chunk = [0u8; 1000];
    let r = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + 99_000, ack_number: Some(LOCAL_SEQ + 1), payload: &chunk, ..SEND_TEMPL });
    println!("reply to tail {:?}; assembler {}", r.map(|r| (r.ack_number, r.window_len)), s.assembler);
    let mut off = 1;
    while off < 99_000 { let len = (99_000 - off).min(1000);
        let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + off, ack_number: Some(LOCAL_SEQ + 1), payload: &chunk[..len], ..SEND_TEMPL });
        off += len; }
    assert_eq!(s.rx_buffer.len(), 100_000);
}
```

`cargo test --lib zzv_ -- --nocapture`:

```
ACK after 1 byte: ack=Some(SeqNumber(-9999)) win=49999
reply to tail Some((Some(SeqNumber(-9999)), 49999)); assembler [ (98999) 999 ]
rx len 99999
assertion failed: left: 99999 right: 100000
```

The segment [99000, 100000) was in window for the first ACK but only 999 of its bytes were kept.

## Suggested fix

Track the highest right edge ever advertised, as a sequence number, and use max(that, current edge) as `window_end`. Alternatively, never advertise an edge left of the previous one: round the scaled window up when the buffer allows it, or keep the old edge, like Linux's `tcp_select_window`.
