# 085. LAST-ACK returns early on any ACK that doesn't advance SND.UNA, dropping window updates and duplicate ACKs

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1365](../src/tcp/mod.rs#L1365), [src/tcp/mod.rs:2661](../src/tcp/mod.rs#L2661), [src/tcp/mod.rs:6773](../src/tcp/mod.rs#L6773) |
| Features | default |
| Verification | reproduced with a test |

## Summary

In LAST-ACK, an ACK that neither acks our FIN nor advances SND.UNA returns a challenge ACK before the send-window update, duplicate-ACK counting and the `remote_last_ts` refresh. `close()` in CLOSE-WAIT goes to LAST-ACK with data still queued. So a server that writes its response and then closes ignores the peer's window updates and never fast-retransmits for the rest of the response.

## Details

`close()` moves CLOSE-WAIT straight to LAST-ACK (src/tcp/mod.rs:2661):

```rust
State::CloseWait => self.inner_mut().set_state(State::LastAck),
```

src/tcp/mod.rs:1360:

```rust
(State::LastAck, TcpControl::None) => {
    if ack_of_fin {
        ...
        self.set_state(State::Closed);
        self.tuple = None;
    } else if ack_len == 0 {
        // Duplicate ACK; our FIN has not been acknowledged.
        // Per RFC 9293 (3.10.7.4), send a challenge ACK.
        return self.challenge_ack_reply(now, repr);
    }
```

The window update (src/tcp/mod.rs:1380) and the duplicate-ACK logic (src/tcp/mod.rs:1418) come after this return. A pure window update always has `ack_len == 0`, so it is lost. Duplicate ACKs never reach fast retransmit, so each loss costs an RTO. The early return also sends a rate-limited challenge ACK in reply to every duplicate ACK.

The comment's RFC basis does not exist. RFC 9293 calls for challenge ACKs for RST, SYN and unacceptable ACKs, not for duplicate ACKs. The stall is bounded: the zero-window probe timer (1 s, doubling up to 60 s) sends a 1-byte probe whose ACK advances SND.UNA and is processed normally.

The behaviour is deliberate and tested: `test_last_ack_ack_not_of_fin` (src/tcp/mod.rs:6728) and `test_last_ack_duplicate_ack_challenge_ack` (src/tcp/mod.rs:6773).

## Failure scenario

HTTP-style server: the client sends its request and half-closes. The server writes a large response and calls `close()`. The socket is in LAST-ACK for the whole response. If the peer's window closes, its window-open ACK is ignored and the sender waits for the probe timer, up to 60 s per interval. Any loss waits for the RTO instead of fast retransmit.

## RFC reference

RFC 9293 §3.10.7.4, fifth step. LAST-ACK:

> The only thing that can arrive in this state is an acknowledgment of our FIN.

ESTABLISHED, which the other states build on:

> If the ACK is a duplicate (SEG.ACK =< SND.UNA), it can be ignored. ...
> If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated.

Neither requires a challenge ACK for a duplicate ACK.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, scratch copy of HEAD. `zz_collect` is a local helper that dispatches and collects the sent segments.

```rust
#[test]
fn zz_f2_last_ack_window_update_dropped() {
    let mut s = socket_close_wait();
    s.view().set_nagle_enabled(false);
    s.remote_win_len = 0;
    s.view().send_slice(b"abcdef").unwrap();
    s.view().close();
    assert_eq!(s.state, State::LastAck);
    let _ = zz_collect(&mut s, Instant::from_millis(0));
    let reply = send(&mut s, Instant::from_millis(10), &TcpRepr { seq_number: REMOTE_SEQ + 1 + 1, ack_number: Some(LOCAL_SEQ + 1), window_len: 256, ..SEND_TEMPL });
    assert_eq!(s.remote_win_len, 256, "window update ignored in LAST-ACK");
}
```

Output:

```
t=0 sent [] timer=ZeroWindowProbe { expires_at: 1000, delay: 1000 }
reply=Some(TcpRepr{seq 10001, ack -9999, ...}) remote_win_len=0
t=20 sent [] deadline=1000
assertion failed: left 0 right 256
```

The same setup without `close()` (CLOSE-WAIT) prints `win=256 sent [(10001, "abcdef")]`.

## Suggested fix

Remove the early return. Process LAST-ACK ACKs like ESTABLISHED (window update, duplicate ACKs) and move to CLOSED only on `ack_of_fin`. Update the two tests above.
