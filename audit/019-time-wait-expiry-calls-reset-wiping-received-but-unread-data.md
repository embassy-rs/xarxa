# 019. TIME-WAIT expiry calls reset(), discarding received and ACKed data the application has not read

| | |
|---|---|
| Severity | high |
| Category | correctness |
| Location | [src/tcp/mod.rs:2094](../src/tcp/mod.rs#L2094), [src/tcp/mod.rs:718](../src/tcp/mod.rs#L718), [src/tcp/mod.rs:2845](../src/tcp/mod.rs#L2845), [src/tcp/mod.rs:2872](../src/tcp/mod.rs#L2872) |
| Features | default |
| Verification | reproduced with a test |

## Summary

When the TIME-WAIT timer fires, `dispatch` calls `self.reset()`, which clears `rx_buffer` and `rx_fin_received`. Stream data the application has not read yet is thrown away, although it was ACKed to the peer. `recv` then returns `InvalidState` ("may be truncated") instead of the data followed by `Finished`.

## Details

src/tcp/mod.rs:2094-2097:

```rust
Timer::Close { expires_at } if clock.expired(expires_at) => {
    trace!("TIME-WAIT timer expired");
    self.reset(clock.now());
}
```

src/tcp/mod.rs:725-727, in `reset`:

```rust
self.tx_buffer.clear();
self.rx_buffer.clear();
self.rx_fin_received = false;
```

In TIME-WAIT, `may_recv()` (src/tcp/mod.rs:2746) is still true while the RX buffer holds data, so the data was readable. After the reset, `recv_error_check` (src/tcp/mod.rs:2845) finds `!may_recv()` and `rx_fin_received == false` and returns `InvalidState`. The `recv` doc (src/tcp/mod.rs:2876-2877) promises `Finished` means "The previously received data is complete".

TIME-WAIT lasts `CLOSE_DELAY` = 10 s (src/tcp/mod.rs:382). `close()` is a half-close, so "send request, `close()`, read the response" goes through FIN-WAIT-2 to TIME-WAIT while the response may still sit in the RX ring. The same happens when TIME-WAIT is entered from CLOSING.

By contrast, the LAST-ACK to CLOSED path (src/tcp/mod.rs:1360-1363) only sets the state and clears the tuple, keeping the RX buffer.

## Failure scenario

An HTTP client sends a request and calls `close()`. The server replies with a body and FIN. The app is busy for more than 10 s (writing the previous chunk to flash) before reading the last ring's worth. The TIME-WAIT timer fires in `poll`, the unread bytes are discarded, and `recv` returns `InvalidState`. The server believes the data was delivered.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, in a scratch copy of HEAD:

```rust
#[test]
fn zz_time_wait_discards_unread() {
    let mut s = socket_fin_wait_2();
    send!(s, time 1_000, TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 1), payload: &b"response"[..], ..SEND_TEMPL });
    assert_eq!(s.state, State::TimeWait);
    assert_eq!(s.rx_buffer.len(), 8);
    recv(&mut s, Instant::from_millis(1_000), 1, |_, r| println!("ZZ ack {:?}", r.ack_number));
    recv_nothing(&mut s, Instant::from_millis(11_000));
    println!("ZZ state={:?} rx={}", s.state, s.rx_buffer.len());
    let mut buf = [0u8; 16];
    let r = s.view().recv_slice(&mut buf);
    println!("ZZ recv_slice -> {:?}", r);
    assert_eq!(r, Err(RecvError::InvalidState));
}
```

Output:

```
ZZ ack Some(SeqNumber(-9991))
ZZ state=Closed rx=0
ZZ recv_slice -> Err(InvalidState)
test tcp::test::zz_time_wait_discards_unread ... ok
```

The 8 bytes were ACKed and then lost.

## Suggested fix

On TIME-WAIT expiry, move to Closed and clear the tuple, like the LAST-ACK path, without clearing the RX buffer or `rx_fin_received`. Leave the full reset to `connect` and `accept`.

Related: `is_open()` is false in TIME-WAIT, so `connect()` / `accept()` on such a socket also reset it and discard unread data. That is an explicit user action, and fine.
