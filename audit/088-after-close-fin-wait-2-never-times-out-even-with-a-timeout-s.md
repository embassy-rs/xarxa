# 088. After close(), FIN-WAIT-2 never times out, even with a timeout set

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1618](../src/tcp/mod.rs#L1618), [src/tcp/mod.rs:2041](../src/tcp/mod.rs#L2041), [src/tcp/mod.rs:2651](../src/tcp/mod.rs#L2651) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`timeout_armed()` is false in FIN-WAIT-2 unless keep-alive is on or there is unsent data. Once our FIN is ACKed, the socket waits for the peer's FIN forever. `is_open()` stays true, so `connect` and `accept` refuse to reuse it (`InvalidState`). The `set_timeout` doc says idle connections never time out, but `close()` does not say the socket may never finish, and the socket reuse model in DESIGN.md §7 relies on it finishing. This is a missing timer and a doc gap, not an RFC violation.

## Details

src/tcp/mod.rs:1618-1626:

```rust
fn timeout_armed(&self) -> bool {
    match self.state {
        State::Closed | State::TimeWait => false,
        State::SynSent | State::SynReceived | State::FinWait1 | State::Closing | State::LastAck => true,
        State::Established | State::FinWait2 | State::CloseWait => {
            !self.tx_buffer.is_empty() || self.keep_alive.is_some()
        }
    }
}
```

src/tcp/mod.rs:2041, dispatch sends nothing in FIN-WAIT-2:

```rust
State::FinWait2 | State::TimeWait => {}
```

There is no FIN-WAIT-2 timer. Linux uses `tcp_fin_timeout` (60 s) for orphaned FIN-WAIT-2 sockets.

Workarounds today: enable keep-alive, which arms the timeout in FIN-WAIT-2, or `abort()` from the application.

## Failure scenario

An embedded HTTP server with N pre-created sockets. A client reads the response, ACKs the server's FIN, and never sends its own FIN. The server socket stays in FIN-WAIT-2 and is never reusable. N such clients deny service permanently. An idle client can already pin an ESTABLISHED socket, so the main impact is on applications that treat `close()` as fire-and-forget.

## Reproduction

Test inside `mod test` in src/tcp/mod.rs of a scratch copy:

```rust
#[test]
fn zz_f4_fin_wait_2_never_times_out() {
    let mut s = socket_established();
    s.view().set_timeout(Some(Duration::from_secs(10)));
    s.view().close();
    let _ = zz_collect(&mut s, Instant::from_millis(0)); // FIN
    let _ = send(&mut s, Instant::from_millis(10), &TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 1), ..SEND_TEMPL });
    assert_eq!(s.state, State::FinWait2);
    let mut t = Instant::from_millis(20);
    for _ in 0..20 { let _ = zz_collect(&mut s, t); t = s.deadline; }
    assert!(s.view().is_open());
    assert_eq!(s.state, State::Closed);
}
```

Output:

```
[(10001, [], Fin)]
after following deadlines: t=1728000020 state=FIN-WAIT-2 -> assertion left FinWait2 right Closed
```

## Suggested fix

Arm the timeout in FIN-WAIT-2 once `close()` has been called, or add a default FIN-WAIT-2 timer that moves the socket to CLOSED. Document on `close()` how long the socket can stay open.
