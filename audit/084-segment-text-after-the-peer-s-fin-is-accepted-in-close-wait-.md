# 084. Segment text after the peer's FIN is accepted in CLOSE-WAIT, CLOSING and LAST-ACK and delivered to the application

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/tcp/mod.rs:1357](../src/tcp/mod.rs#L1357), [src/tcp/mod.rs:1350](../src/tcp/mod.rs#L1350), [src/tcp/mod.rs:1360](../src/tcp/mod.rs#L1360), [src/tcp/mod.rs:1527](../src/tcp/mod.rs#L1527) |
| Features | default |
| Verification | reproduced with a test |

## Summary

After the peer's FIN, RCV.NXT is past the FIN, so a data segment at the new RCV.NXT passes the window check. The CLOSE-WAIT, CLOSING and LAST-ACK arms fall through to payload processing. The bytes land in the RX ring and `recv` returns them, even after it already reported `Finished`.

## Details

src/tcp/mod.rs:1357:

```rust
(State::CloseWait, TcpControl::None) => {}
```

The `(State::Closing, TcpControl::None)` arm (src/tcp/mod.rs:1350) only checks `ack_of_fin` and falls through too. After the match, the payload goes to the assembler and `rx_buffer.write_unallocated` (src/tcp/mod.rs:1527 onward) with no state check. `remote_seq_no` also advances past the bogus bytes, so the next ACK acknowledges them.

Per state:

- CLOSE-WAIT: affected.
- CLOSING: affected.
- LAST-ACK: affected only when the segment's ACK advances SND.UNA without acking our FIN (partial ACK). A non-advancing ACK returns early through `challenge_ack_reply` (src/tcp/mod.rs:1365) and the payload is dropped.
- TIME-WAIT: not affected. It hits the `_ => return None` arm.

## Failure scenario

A buggy peer, or an in-window injector, sends data after its FIN. The application has seen `RecvError::Finished`, then `can_recv()` turns true and `recv_slice` returns bytes past end of stream.

## RFC reference

RFC 9293 §3.10.7.4, seventh step (process the segment text):

> CLOSE-WAIT STATE, CLOSING STATE, LAST-ACK STATE, TIME-WAIT STATE: This should not occur since a FIN has been received from the remote side. Ignore the segment text.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, scratch copy of HEAD:

```rust
#[test]
fn zz_f1_close_wait_data_after_fin() {
    let mut s = socket_close_wait();
    s.rx_fin_received = true;
    let mut buf = [0u8; 16];
    assert_eq!(s.view().recv_slice(&mut buf), Err(RecvError::Finished));
    let _ = send(&mut s, Instant::ZERO, &TcpRepr { seq_number: REMOTE_SEQ + 1 + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &b"evil"[..], ..SEND_TEMPL });
    let r1 = s.view().recv_slice(&mut buf);
    assert_eq!(r1, Err(RecvError::Finished), "bytes after FIN delivered");
}
```

A second test sent the same segment to `socket_last_ack` (duplicate ACK, then partial ACK) and to `socket_closing`. `cargo test --lib zz_f1 -- --nocapture`:

```
recv before: Err(Finished)
rx_len=4 can_recv=true
recv after: Ok(4) [101, 118, 105, 108]  -> assertion failed
last-ack (dup ack) rx_len=0
last-ack (partial ack) rx_len=4
closing rx_len=4
```

## Suggested fix

After ACK processing, drop the payload when `rx_fin_received` is set (CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT). Reply with at most an ACK.
