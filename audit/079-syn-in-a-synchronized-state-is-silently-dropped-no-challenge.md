# 079. SYN in a synchronized state is silently dropped: no challenge ACK and no RST, so half-open connections never recover

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:1039](../src/tcp/mod.rs#L1039), [src/tcp/mod.rs:1373](../src/tcp/mod.rs#L1373), [src/stack.rs:1511](../src/stack.rs#L1511) |
| Features | default |
| Verification | reproduced with a test |

## Summary

A SYN without ACK hits the `(_, _, None) => return None` arm of the ACK check before any sequence or SYN handling. An in-window SYN|ACK falls into the `_ => "unexpected packet"` arm and is also dropped. Only an out-of-window SYN|ACK gets a challenge ACK. A peer that rebooted and reconnects on the same 4-tuple gets no reply, and the stale connection is never torn down.

## Details

src/tcp/mod.rs:1039, which runs for every state except SYN-SENT, SYN-RECEIVED included:

```rust
// Every packet after the initial SYN must be an acknowledgement.
(_, _, None) => {
    debug!("expecting an ACK");
    return None;
}
```

src/tcp/mod.rs:1373, where an in-window SYN|ACK ends up:

```rust
_ => {
    debug!("unexpected packet {}", repr);
    return None;
}
```

The comment at mod.rs:1186-1190 says "a SYN in a synchronized state is a challenge ACK situation (RFC 5961 4.2)". Only a SYN|ACK that fails the window check reaches that code.

The listener never sees the SYN either. `process_tcp` stops at the first connected socket matching the 4-tuple (src/stack.rs:1511-1523) and returns.

With the defaults (no keep-alive, no timeout), a stale ESTABLISHED socket lingers indefinitely. It holds a socket and blocks the 4-tuple.

## Failure scenario

1. A xarxa server holds an idle connection. The client reboots and reconnects from the same source port (common for embedded clients with deterministic ports, or behind port-preserving NAT). Every SYN is dropped. The client's connect times out. Without the challenge ACK, the client never sends the RST that would clear the stale socket.
2. The server closed first and is in TIME-WAIT. A client reconnecting on the same 4-tuple has its SYNs dropped until TIME-WAIT expires. With the client's SYN backoff, the reconnect is delayed.

## RFC reference

RFC 9293 §3.10.7.4, fourth check, synchronized states:

> RFC 5961 recommends that in these synchronized states, if the SYN bit is set, irrespective of the sequence number, TCP endpoints MUST send a "challenge ACK" to the remote peer:
>
> <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

> For implementations that do not follow RFC 5961, the original behavior described in RFC 793 follows in this paragraph. If the SYN is in the window it is an error: send a reset, ...

> If the SYN is not in the window, this step would not be reached and an ACK would have been sent in the first step (sequence number check).

The "if the ACK bit is off, drop the segment and return" rule is the fifth step, after the SYN check. The code applies it first.

## Reproduction

Added to `mod test` in src/tcp/mod.rs, in a scratch copy:

```rust
#[test]
fn audit_syn_in_established_dropped() {
    let mut s = socket_established();
    send!(s, TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ + 1 + 30, ack_number: None, ..SEND_TEMPL }, None);
    assert_eq!(s.state, State::Established);
    send!(s, TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ + 1 + 300000, ack_number: None, ..SEND_TEMPL }, None);
    assert_eq!(s.state, State::Established);
    send!(s, TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL }, None);
    assert_eq!(s.state, State::Established);
    recv_nothing!(s);
}
```

`cargo test --lib audit_ -- --nocapture --test-threads=1`:

```
test tcp::test::audit_syn_in_established_dropped ... ok
```

The test passing shows that none of the three SYNs gets a reply and the following dispatch sends nothing.

## Suggested fix

Before the ACK-required check, handle a SYN (with or without ACK, in or out of window) in synchronized states by returning `challenge_ack_reply` (rate-limited) and dropping the segment. TIME-WAIT may instead accept a new SYN, as RFC 9293 allows.
