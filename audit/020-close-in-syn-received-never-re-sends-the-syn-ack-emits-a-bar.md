# 020. close() in SYN-RECEIVED drops the SYN from sequence space: no SYN|ACK retransmission, no FIN, and the ACK of the SYN is taken as the ACK of the FIN

| | |
|---|---|
| Severity | high |
| Category | correctness |
| Location | [src/tcp/mod.rs:2660](../src/tcp/mod.rs#L2660), [src/tcp/mod.rs:980](../src/tcp/mod.rs#L980), [src/tcp/mod.rs:1213](../src/tcp/mod.rs#L1213), [src/tcp/mod.rs:1320](../src/tcp/mod.rs#L1320), [src/tcp/mod.rs:2003](../src/tcp/mod.rs#L2003) |
| Features | default (`tcp-listener`) |
| Verification | reproduced with a test |

## Summary

`close()` in SynReceived moves the socket straight to FinWait1. From then on, `dispatch` only takes the data/FIN path, which never emits a SYN, and `process` counts the SYN's sequence slot as the FIN's. If the SYN|ACK was already sent, no FIN ever goes out, the client's handshake ACK moves us to FIN-WAIT-2, and the client stays ESTABLISHED without ever seeing a FIN. If the SYN|ACK was lost or never sent, we retransmit bare FINs at seq = ISS forever and the client can never connect.

## Details

src/tcp/mod.rs:2660:

```rust
State::SynReceived | State::Established => self.inner_mut().set_state(State::FinWait1),
```

src/tcp/mod.rs:980-985, the SYN is no longer counted:

```rust
let (sent_syn, sent_fin) = match self.state {
    State::SynSent | State::SynReceived => (true, false),
    State::FinWait1 | State::LastAck | State::Closing => (false, true),
```

src/tcp/mod.rs:1213-1223:

```rust
let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);
...
if sent_fin && self.tx_buffer.len() + 1 == ack_len {
    ack_len -= 1;
    trace!("received ACK of FIN");
    ack_of_fin = true;
}
```

With an empty TX buffer, the client's ACK of our SYN (ack = ISS+1) gives `ack_len == 1`, so `ack_of_fin` is set and (FinWait1, None) moves to FinWait2 (src/tcp/mod.rs:1320-1324).

In `dispatch`, FinWait1 goes to the data arm (src/tcp/mod.rs:2003). After the SYN|ACK was sent, `flight_size()` is 1 and `tx_len` is 0. `data_control(1, 0)` (src/tcp/mod.rs:1946) returns `None` because `offset + len != tx_len`, so the loop breaks and nothing is sent. A FIN at seq = ISS only appears when `remote_last_seq == local_seq_no`: after an RTO rewind (src/tcp/mod.rs:1851), or when `close()` came before the first dispatch. That FIN has no SYN bit, so a client in SYN-SENT drops it. The SYN|ACK is never sent again.

The existing `test_syn_received_close` (src/tcp/mod.rs:4209) only asserts the state.

## Failure scenario

A server accepts a token and then closes the socket before the handshake finishes, to reject a client or on shutdown.

- SYN|ACK already sent: nothing goes out. The client's ACK moves our socket to FIN-WAIT-2. The client is ESTABLISHED and waits forever for data or a FIN. Our socket stays in FIN-WAIT-2 and is never reusable.
- `close()` before the first poll, or SYN|ACK lost: we send bare FIN|ACKs at seq = ISS at 1 s, 3 s, 7 s, 15 s ... The client never receives a SYN|ACK and its `connect` never completes. With no timeout set (016) our socket retransmits forever.

## RFC reference

RFC 9293 §3.4:

> the SYN is considered to occur before the first actual data octet of the segment in which it occurs, while the FIN is considered to occur after the last actual data octet in a segment in which it occurs. ... When a SYN is present, then SEG.SEQ is the sequence number of the SYN.

RFC 9293 §3.10.4, CLOSE call, SYN-RECEIVED STATE:

> If no SENDs have been issued and there is no pending data to send, then form a FIN segment and send it, and enter FIN-WAIT-1 state; otherwise, queue for processing after entering ESTABLISHED state.

That assumes the SYN stays in sequence space and is still retransmitted. The FIN comes after it, at ISS+1.

## Reproduction

Tests in `mod stack_test` of src/tcp/mod.rs, in a scratch copy of HEAD:

```rust
#[test] #[cfg(feature = "tcp-listener")]
fn zz_v_synrecv_close_after_synack() {
    // listen, SYN in, accept token into socket h, set_ack_delay(None), poll -> SYN|ACK out
    stack.tcp_socket(h).close();
    stack.poll(Instant::from_millis(10));
    assert_eq!(driver.tx.borrow().len(), 0);
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(20));
    // poll at returned deadlines until t=100 s, counting FINs
    assert_eq!(stack.tcp_socket(h).state(), State::FinWait2);
    assert_eq!(fins, 0);
}

#[test] #[cfg(feature = "tcp-listener")]
fn zz_v_synrecv_close_before_poll() {
    // listen, SYN in, accept token into socket h, close() immediately
    // poll at returned deadlines until t=20 s, print every segment
    assert!(segs > 0); assert_eq!(synacks, 0);
}
```

Output:

```
after close: frames=0
state after peer ACK: FinWait2
final state FinWait2, fins=0
ok
t=0 seg syn=false ack=true fin=true seq=10000
t=1000 seg syn=false ack=true fin=true seq=10000
t=3000 seg syn=false ack=true fin=true seq=10000
t=7000 seg syn=false ack=true fin=true seq=10000
t=15000 seg syn=false ack=true fin=true seq=10000
segs=5 synacks=0
ok
```

## Suggested fix

Keep the SYN in sequence space while it is unacked. Options:

- Stay in SynReceived with a "close pending" flag, and move to FinWait1 once the ACK of the SYN arrives.
- Make FinWait1 dispatch resend the SYN|ACK while the SYN is unacked, and place the FIN at ISS+1.
- Simplest: turn `close()` in SynReceived into an abort (RST).
