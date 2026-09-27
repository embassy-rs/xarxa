# 089. No receiver SWS avoidance: reading 1 byte from a full buffer advertises a 1-byte window

| | |
|---|---|
| Severity | medium |
| Category | performance |
| Location | [src/tcp/mod.rs:1687](../src/tcp/mod.rs#L1687), [src/tcp/mod.rs:1643](../src/tcp/mod.rs#L1643), [src/tcp/mod.rs:679](../src/tcp/mod.rs#L679), [src/tcp/mod.rs:1921](../src/tcp/mod.rs#L1921) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`window_to_update()` fires when `new_win / 2 >= last_win`. After a zero-window ACK, `last_win` is 0, so any read of 1 byte or more makes a window update due, and dispatch sends it at once. Every segment also advertises the exact free space. The right window edge moves in steps as small as the application's reads. RFC 9293 makes receiver SWS avoidance a MUST. With a sender that does no SWS avoidance either (xarxa itself), the connection degrades to tiny segments.

## Details

src/tcp/mod.rs:1687-1699:

```rust
fn window_to_update(&self) -> bool {
    match self.state {
        State::SynSent | State::SynReceived | State::Established | State::FinWait1 | State::FinWait2 => {
            let new_win = self.scaled_window();
            if let Some(last_win) = self.last_scaled_window() {
                new_win > 0 && new_win / 2 >= last_win
```

With `last_win == 0`, `1 / 2 >= 0` is true. `ack_due()` (src/tcp/mod.rs:1643) then makes dispatch send the update immediately.

src/tcp/mod.rs:679, the window on every segment (used at src/tcp/mod.rs:1921) is the full free space:

```rust
fn scaled_window(&self) -> u16 {
    u16::try_from(self.rx_buffer.window() >> self.remote_win_shift).unwrap_or(u16::MAX)
}
```

Nothing keeps RCV.NXT+RCV.WND fixed until the gain reaches min(RCV.BUFF/2, Eff.snd.MSS).

The existing test `test_zero_window_ack_on_window_growth` (6-byte buffer, 3-byte read, window 3) happens to be compliant, since 3 = RCV.BUFF/2. The violation shows with reads smaller than min(buffer/2, MSS).

## Failure scenario

A bulk transfer into a xarxa socket whose application reads 64 bytes per loop iteration (for example while writing to flash). Once the buffer is full, each read opens a 64-byte window, and a sender without SWS avoidance sends a 64-byte segment. Throughput drops to one small segment per round trip, and packet and ACK counts grow by 20x or more. Linux as sender holds back some of these, but every small read still costs an extra window-update ACK.

## RFC reference

RFC 9293 §3.8.6.2.2:

> A TCP implementation MUST include a SWS avoidance algorithm in the receiver (MUST-39).

> The suggested SWS avoidance algorithm for the receiver is to keep RCV.NXT+RCV.WND fixed until the reduction satisfies:
>
> RCV.BUFF - RCV.USER - RCV.WND >= min( Fr * RCV.BUFF, Eff.snd.MSS )

## Reproduction

Test inside `mod test` in src/tcp/mod.rs of a scratch copy:

```rust
#[test]
fn zz_rx_sws() {
    let mut s = socket_established_with_buffer_sizes(64, 64);
    let data = [0x55u8; 64];
    send!(s, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &data[..], ..SEND_TEMPL });
    recv!(s, [TcpRepr { seq_number: LOCAL_SEQ + 1, ack_number: Some(REMOTE_SEQ + 1 + 64), window_len: 0, ..RECV_TEMPL }]);
    let mut b = [0u8; 1];
    assert_eq!(s.view().recv_slice(&mut b), Ok(1));
    recv(&mut s, Instant::from_millis(0), 1, |_, r| {
        println!("ZZ after 1-byte read: ack={:?} win={}", r.ack_number, r.window_len);
        assert_eq!(r.window_len, 1);
    });
}
```

Output (`cargo test --lib zz_ -- --nocapture`):

```
ZZ after 1-byte read: ack=Some(SeqNumber(-9936)) win=1
test tcp::test::zz_rx_sws ... ok
```

## Suggested fix

Only move the right edge forward when the gain is at least min(capacity / 2, local MSS). Otherwise advertise the window that keeps RCV.NXT+RCV.WND where it was. Apply this both in `window_to_update` and in the window put on every segment.
