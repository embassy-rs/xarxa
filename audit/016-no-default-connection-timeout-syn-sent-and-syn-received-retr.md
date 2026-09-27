# 016. No default retransmission limit: SYN-SENT, SYN-RECEIVED and data retransmissions go on forever

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1630](../src/tcp/mod.rs#L1630), [src/tcp/mod.rs:628](../src/tcp/mod.rs#L628), [src/tcp/mod.rs:2355](../src/tcp/mod.rs#L2355), [src/tcp/listener.rs:28](../src/tcp/listener.rs#L28) |
| Features | default |
| Verification | reproduced with a test |

## Summary

A TCP socket's `timeout` defaults to `None`, and `timed_out()` never fires without one. There is no retransmission counter either. So with default settings the stack never gives up on a connection: a `connect` to a black-holed host stays in SYN-SENT forever, an accepted SYN whose client never answers keeps the socket in SYN-RECEIVED forever, and an established connection whose peer vanished retransmits forever. Listener backlog entries never expire. RFC 9293 lets the application choose R2 = infinity, but makes a finite R2 the procedure.

## Details

src/tcp/mod.rs:1630:

```rust
fn timed_out(&self, clock: &mut Clock) -> bool {
    if !self.timeout_armed() {
        return false;
    }
    match (self.remote_last_ts, self.timeout) {
        (Some(remote_last_ts), Some(timeout)) => clock.expired(remote_last_ts + timeout),
        (_, _) => false,
    }
}
```

src/tcp/mod.rs:628, in `TcpSocketState::new`:

```rust
timeout: None,
```

`reset()` keeps the timeout, so a reused socket keeps whatever the user set, and `None` if the user set nothing.

`RttEstimator::on_rto` (src/tcp/mod.rs:343) doubles the RTO up to `RTTE_MAX_RTO` (60 s, src/tcp/mod.rs:256) and counts nothing. Retransmission continues every 60 s indefinitely.

`PendingSyn` (src/tcp/listener.rs:28) holds no timestamp, so a queued SYN sits in the backlog until it is accepted or replaced.

The `set_timeout` doc (src/tcp/mod.rs:2355-2369) describes when a set timeout aborts, but does not say the default is `None` or that a socket without one never gives up. DESIGN.md and the README do not mention R2.

Mitigation that already exists: a spoofed on-link source fails neighbor resolution, and the resulting host-unreachable aborts SYN-RECEIVED. Off-link spoofed sources are not covered.

## Failure scenario

1. Firmware calls `connect()` to a server behind a firewall that drops SYNs, and awaits Established. The socket stays in SYN-SENT. An embassy-net connect future never resolves.
2. A heap-less server pre-creates N sockets and accepts every token, the pattern DESIGN.md §7 recommends. An attacker sends N SYNs from spoofed off-link addresses. Each accepted socket sits in SYN-RECEIVED retransmitting SYN|ACKs every 60 s forever. No legitimate client is served again unless the application set a timeout.
3. The peer powers off mid-transfer with data queued. The socket stays Established and retransmits forever. A task awaiting `send` or `recv` never sees an error.

## RFC reference

RFC 9293 §3.8.3:

> The following procedure MUST be used to handle excessive retransmissions of data segments (MUST-20):
> ...
> (c) When the number of transmissions of the same segment reaches a threshold R2 greater than R1, close the connection.
>
> (d) An application MUST (MUST-21) be able to set the value for R2 for a particular connection. For example, an interactive application might set R2 to "infinity", giving the user control over when to disconnect.

> The value of R2 SHOULD correspond to at least 100 seconds (SHLD-11).

> SYN retransmissions MUST be handled in the general way just described for data retransmissions, including notification of the application layer.

> R2 for a SYN segment MUST be set large enough to provide retransmission of the segment for at least 3 minutes (MUST-23).

MUST-21 is met by `set_timeout`. The default is R2 = infinity, which the RFC treats as an application choice, not the stack's default.

## Reproduction

Tests in `mod test` of src/tcp/mod.rs, in a scratch copy of HEAD. `zz_collect` dispatches the socket at time `t` and returns the emitted segments.

```rust
#[test]
fn zz_f5_syn_sent_forever() {
    let mut s = socket();
    s.local_seq_no = LOCAL_SEQ;
    s.view().connect(REMOTE_END, LOCAL_END.port).unwrap();
    let mut t = Instant::from_millis(0); let mut syns = 0;
    while t < Instant::from_secs(7200) {
        syns += zz_collect(&mut s, t).iter().filter(|p| p.2 == TcpControl::Syn).count();
        assert!(s.deadline > t); t = s.deadline;
    }
    assert_eq!(s.state, State::Closed);
}

#[test]
fn zz_f5b_syn_received_forever() {
    let mut s = socket_syn_received();
    let mut t = Instant::from_millis(0); let mut n = 0;
    while t < Instant::from_secs(7200) { n += zz_collect(&mut s, t).len(); t = s.deadline; }
    assert_eq!(s.state, State::Closed);
}
```

Output:

```
125 SYNs, state SYN-SENT -> assertion failed (left SynSent)
125 SYN|ACKs, state SYN-RECEIVED -> assertion failed (left SynReceived)
```

## Suggested fix

- Give SYN-SENT and SYN-RECEIVED a finite default R2: at least 3 minutes (MUST-23), or a retransmission count like Linux's `tcp_syn_retries` / `tcp_synack_retries`.
- Give data retransmission a finite default R2 too (at least 100 s per SHLD-11).
- Document the default in `set_timeout` and `timeout`.
- Age out listener backlog entries after a few seconds. The client retransmits its SYN anyway.
