# 093. connect()/accept() on a socket in TIME-WAIT discard TIME-WAIT, including for the identical 4-tuple

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:2549](../src/tcp/mod.rs#L2549), [src/tcp/mod.rs:704](../src/tcp/mod.rs#L704), [src/tcp/mod.rs:2583](../src/tcp/mod.rs#L2583), [src/tcp/mod.rs:2634](../src/tcp/mod.rs#L2634), [src/tcp/mod.rs:382](../src/tcp/mod.rs#L382) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`is_open()` is false in TIME-WAIT, so `connect` and `accept` `reset()` the socket and drop its TIME-WAIT state. `tuple_in_use` skips the socket's own index, so reconnecting the same socket to the same remote from the same fixed local port succeeds at once, with an ISN that is not constrained to be above the old SND.NXT. Separately, TIME-WAIT lasts only `CLOSE_DELAY` = 10 s, not 2×MSL, for every socket. Neither is documented in README.md or DESIGN.md.

## Details

src/tcp/mod.rs:704:

```rust
fn is_open(&self) -> bool {
    match self.state {
        State::Closed => false,
        State::TimeWait => false,
        _ => true,
    }
}
```

src/tcp/mod.rs:2549 (`accept` at 2634 has the same check):

```rust
if self.is_open() {
    return Err(ConnectError::InvalidState);
}
```

src/tcp/mod.rs:2583:

```rust
.any(|(i, s)| i != index && s.binding == binding && s.tuple == Some(Tuple { local, remote }))
```

src/tcp/mod.rs:382:

```rust
const CLOSE_DELAY: Duration = Duration::from_millis(10_000);
```

Another socket connecting to the same tuple still gets `InUse`, because the TIME-WAIT socket keeps its tuple. Only reuse of the same socket bypasses the check. With ephemeral ports this rarely matters, since they are random. The documented reuse pattern (N sockets created at startup, accepted into again as each connection ends) ends TIME-WAIT early on every reuse.

## Failure scenario

A client with a fixed local port closes a connection (TIME-WAIT) and calls `connect()` again on the same socket to the same server. It returns `Ok` and sends a SYN with an unrelated ISN while the server may still be in LAST-ACK. The server answers for the old connection, so the new connect stalls or fails. If our last ACK was lost, the peer's retransmitted FIN now gets an RST instead of an ACK. Old duplicates of the first connection can be accepted in the second when the new ISN is below the old sequence space.

## RFC reference

RFC 9293 §3.6:

> When a connection is closed actively, it MUST linger in the TIME-WAIT state for a time 2xMSL (Maximum Segment Lifetime) (MUST-13). However, it MAY accept a new SYN from the remote TCP endpoint to reopen the connection directly from TIME-WAIT state (MAY-2), if it:
>
> (1) assigns its initial sequence number for the new connection to be larger than the largest sequence number it used on the previous connection incarnation, and ...

RFC 9293 §3.10.1 (OPEN call, functional description, not itself normative):

> TIME-WAIT STATE
> * Return "error: connection already exists".

## Reproduction

Test in `mod test` of src/tcp/mod.rs (scratch copy):

```rust
#[test]
fn zz_time_wait_reconnect_same_tuple() {
    let mut s = socket_time_wait(false);
    let old_snd_nxt = s.remote_last_seq;
    let r = s.view().connect(REMOTE_END, LOCAL_END);
    println!("ZZ connect from TIME-WAIT same tuple -> {:?}, state={:?}, new isn={:?} old snd.nxt={:?}",
        r, s.state, s.local_seq_no, old_snd_nxt);
    assert_eq!(r, Ok(()));
    assert_eq!(s.state, State::SynSent);
}
```

Output:

```
ZZ connect from TIME-WAIT same tuple -> Ok(()), state=SynSent, new isn=SeqNumber(10000) old snd.nxt=SeqNumber(10002)
test tcp::test::zz_time_wait_reconnect_same_tuple ... ok
```

In the test build the ISN is fixed at 10000. It landed below the old SND.NXT, which shows nothing constrains it.

## Suggested fix

Reject a same-tuple `connect` from TIME-WAIT with `InUse` unless the new ISN is above the old SND.NXT (RFC 6191 style), or treat TIME-WAIT as open for `connect`/`accept` and give the user a way to wait for it. Document the shortened TIME-WAIT, or raise `CLOSE_DELAY` to 2×MSL.
