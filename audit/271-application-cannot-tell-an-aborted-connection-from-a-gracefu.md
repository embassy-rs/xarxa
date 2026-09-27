# 271. Application cannot tell an aborted connection from a graceful close after a FIN was received (MUST-12)

| | |
|---|---|
| Severity | low |
| Category | api |
| Location | [src/tcp/mod.rs:1247](../src/tcp/mod.rs#L1247), [src/tcp/mod.rs:2845](../src/tcp/mod.rs#L2845) |
| Features | default |
| Verification | reproduced with a test |

## Summary
An RST and a normal close both end in `State::Closed` with no reason recorded. `recv` answers only from `rx_fin_received`. So once the peer's FIN has arrived (CLOSE-WAIT, CLOSING, LAST-ACK), an abort by RST looks exactly like a graceful close. Before a FIN the cases differ (`InvalidState` vs `Finished`), so the gap is limited to the post-FIN states.

## Details
src/tcp/mod.rs:1247
```rust
(_, TcpControl::Rst) => {
    trace!("received RST");
    self.set_state(State::Closed);
    self.tuple = None;
    return None;
}
```
src/tcp/mod.rs:2845 `recv_error_check` returns `Finished` if `rx_fin_received`, else `InvalidState`. `send` returns `InvalidState` in both cases.

## Failure scenario
The client sends a request after the server's FIN (CLOSE-WAIT) and closes. The server resets instead of taking it. The client sees `Finished` and then `Closed`, same as a successful exchange, and assumes delivery.

## RFC reference
RFC 9293 §3.6: "If the local TCP connection is closed by the remote side due to a FIN or RST received from the remote side, then the local application MUST be informed whether it closed normally or was aborted (MUST-12)."

## Reproduction
Test in the `src/tcp/mod.rs` test module:
```rust
#[test]
fn vv_f10_rst_in_last_ack_indistinguishable() {
    let mut a = socket_last_ack();
    send!(a, TcpRepr { control: TcpControl::Rst, seq_number: REMOTE_SEQ + 1 + 1, ack_number: None, ..SEND_TEMPL });
    let mut b = socket_last_ack();
    send!(b, TcpRepr { seq_number: REMOTE_SEQ + 1 + 1, ack_number: Some(LOCAL_SEQ + 1 + 1), ..SEND_TEMPL });
    let mut buf = [0u8; 4];
    let ra = a.view().recv_slice(&mut buf);
    let rb = b.view().recv_slice(&mut buf);
    assert!(a.state != b.state || ra != rb);
}
```
Output: both `state=CLOSED recv=Err(InvalidState)`, assertion fails. The `socket_last_ack` fixture does not set `rx_fin_received`. With a real FIN both would return `Finished`. Either way the outcomes are identical.

## Suggested fix
Record the close reason (reset, timed out, normal) and expose it through an error variant or an accessor.
