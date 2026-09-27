# 082. In-window RST with a non-exact sequence number resets the connection (RFC 5961 §3 only half implemented)

| | |
|---|---|
| Severity | medium |
| Category | security |
| Location | [src/tcp/mod.rs:1247](../src/tcp/mod.rs#L1247), [src/tcp/mod.rs:1007](../src/tcp/mod.rs#L1007), [src/tcp/mod.rs:1117](../src/tcp/mod.rs#L1117), [src/tcp/mod.rs:1156](../src/tcp/mod.rs#L1156) |
| Features | default |
| Verification | reproduced with a test |

## Summary

Out-of-window RSTs are dropped, with a comment citing RFC 5961 §3.2. But any RST whose sequence number falls anywhere in the receive window closes the connection. RFC 5961 requires an exact match with RCV.NXT and a challenge ACK otherwise. A blind reset needs about 2^32/RCV.WND guesses instead of about 2^32.

## Details

The ACK check lets any RST through (src/tcp/mod.rs:1007):

```rust
// Any other RST need only have a valid sequence number.
(_, TcpControl::Rst, _) => (),
```

A zero-length segment is accepted anywhere in the window (src/tcp/mod.rs:1117):

```rust
(true, false) => {
    if window_start <= segment_start && segment_start < window_end {
        true
```

The state match then closes the socket (src/tcp/mod.rs:1247):

```rust
(_, TcpControl::Rst) => {
    trace!("received RST");
    self.set_state(State::Closed);
    self.tuple = None;
    return None;
}
```

Nothing compares `repr.seq_number` with `window_start`. The out-of-window drop at src/tcp/mod.rs:1156 cites "RFC 9293 (3.10.7.4) and RFC 5961 (3.2)", and the RFC 5961 §5.2 ACK check and the §7 challenge-ACK throttle are implemented. Only checks 2 and 3 of §3.2 are missing.

RFC 9293 makes the RFC 5961 mitigation optional. So this is not a base-spec violation. It is hardening that the code claims but only half implements.

## Failure scenario

An off-path attacker who knows the 4-tuple (a known server port plus a guessed ephemeral port) sends RSTs spaced one receive window apart. With a 64 KiB window, about 65536 packets reset the connection. Small embedded windows raise the cost proportionally.

## RFC reference

RFC 9293 §3.10.7.4:

> For stacks implementing the protection described in RFC 5961, the three checks below apply ...
>
> 2) If the RST bit is set and the sequence number exactly matches the next expected sequence number (RCV.NXT), then TCP endpoints MUST reset the connection ...
>
> 3) If the RST bit is set and the sequence number does not exactly match the next expected sequence value, yet is within the current receive window, TCP endpoints MUST send an acknowledgment (challenge ACK)

Also RFC 5961 §3.2.

## Reproduction

Test in `mod test` of src/tcp/mod.rs, scratch copy of HEAD:

```rust
#[test]
fn zzv_rst_inwindow_nonexact() {
    let mut s = socket_established();
    let r = send(&mut s, Instant::ZERO, &TcpRepr { control: TcpControl::Rst, seq_number: REMOTE_SEQ + 1 + 30, ack_number: None, ..SEND_TEMPL });
    println!("reply {:?} state {}", r, s.state);
    assert_eq!(s.state, State::Established);
}
```

`cargo test --lib zzv_ -- --nocapture`:

```
reply None state CLOSED
assertion `left == right` failed
  left: Closed
 right: Established
```

## Suggested fix

In synchronized states, close only when `repr.seq_number == window_start`. For any other in-window RST, return `challenge_ack_reply(now, repr)`, which already has the RFC 5961 §7 throttle.
