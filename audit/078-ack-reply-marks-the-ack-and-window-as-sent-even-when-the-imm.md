# 078. ack_reply marks the ACK and window as sent before the reply is transmitted, so a dropped immediate ACK is never retried

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:883](../src/tcp/mod.rs#L883), [src/tcp/mod.rs:1604](../src/tcp/mod.rs#L1604), [src/tcp/mod.rs:1536](../src/tcp/mod.rs#L1536), [src/tcp/mod.rs:1655](../src/tcp/mod.rs#L1655), [src/stack.rs:1520](../src/stack.rs#L1520), [src/stack.rs:1550](../src/stack.rs#L1550) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`ack_reply` sets `remote_last_ack` and `remote_last_win` as if the reply had gone out. `process()` only returns the reply. `Stack::transmit_tcp_reply` then drops it silently when there is no route, the pool is empty, or the device refuses it. Afterwards `ack_to_transmit()` is false, so `dispatch` never sends that ACK. The immediate ACKs for out-of-order data and for the segment that fills a hole are lost, and the peer waits for its RTO.

## Details

src/tcp/mod.rs:882 (in `ack_reply`):

```rust
reply_repr.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
self.remote_last_ack = reply_repr.ack_number;
...
reply_repr.window_len = self.scaled_window();
self.remote_last_win = reply_repr.window_len;
```

src/tcp/mod.rs:1600, the immediate ACK on out-of-order data or a hole fill:

```rust
if !self.assembler.is_empty() || !assembler_was_empty {
    // Note that we change the transmitter state here.
    // This is fine because xarxa assumes that it can always transmit zero or one
    // packets for every packet it receives.
    trace!("ACKing incoming segment");
    Some(self.ack_reply(now, repr))
```

The "too many holes" path at mod.rs:1536 and `challenge_ack_reply` (mod.rs:911) do the same.

src/stack.rs:1550:

```rust
fn transmit_tcp_reply(&mut self, arrival: IfaceHandle, repr: &TcpRepr<'_>, src_addr: IpAddr, dst_addr: IpAddr) {
    let Some((route, checksum_caps)) = self.route_reply(arrival, &dst_addr) else {
        return;
    };
    let Some(buf) = crate::tcp::build_tcp_packet(repr, &src_addr, &dst_addr, &checksum_caps) else {
        return;
    };
    self.transmit_reply(&route, buf, src_addr, dst_addr, IpProtocol::Tcp, 64);
}
```

`transmit_reply` is best-effort and drops the packet if the device refuses it. The ACK delay timer is left as it was. src/tcp/mod.rs:1655:

```rust
fn ack_to_transmit(&self) -> bool {
    if let Some(remote_last_ack) = self.remote_last_ack {
        remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
```

This is false after `ack_reply`, so nothing is due. `dispatch` holds a segment back with the socket untouched when the pool or device refuses it (DESIGN §4 "Backpressure"). This path changes socket state first.

## Failure scenario

An RX burst with loss exhausts the pool or fills the device. The retransmission that fills the hole arrives. `process()` returns an ACK covering all buffered data and records it as sent. The reply is dropped. The peer, with its window full, gets no ACK. It waits for its RTO (1 s or more, backed off) and retransmits, and only that retransmission produces a new `ack_reply`. The transfer stalls for about one peer RTO each time. It is not a permanent hang.

## Reproduction

Added to `mod stack_test` in src/tcp/mod.rs, in a scratch copy:

```rust
#[test]
#[cfg(feature = "tcp-listener")]
fn audit_stack_immediate_ack_dropped_never_retried() {
    let (mut stack, driver) = stack();
    let lh = stack.add_tcp_listener().unwrap();
    stack.tcp_listener(lh).listen(LOCAL_PORT).unwrap();
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(0));
    let token = stack.tcp_listener(lh).accept().unwrap();
    let h = stack.add_tcp_socket(1024, 1024).unwrap();
    stack.tcp_socket(h).accept(token).unwrap();
    stack.poll(Instant::from_millis(0));
    driver.tx.borrow_mut().clear();
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(1));
    assert_eq!(stack.tcp_socket(h).state(), State::Established);
    driver.room.set(Some(0));
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { seq_number: REMOTE_SEQ + 1 + 5, ack_number: Some(LOCAL_SEQ + 1), payload: b"world", ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(2));
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: b"hello", ..SEND_TEMPL }));
    let d = stack.poll(Instant::from_millis(3));
    println!("deadline after hole fill = {:?}", d);
    driver.room.set(None);
    let mut acked = false;
    for t in [4u32, 10, 100, 500, 1000, 5000, 60000] {
        stack.poll(Instant::from_millis(t));
        for mut f in driver.tx.borrow_mut().drain(..) {
            parse_tx(&mut f, |tcp| { if tcp.ack_number() == REMOTE_SEQ + 1 + 10 { acked = true; } });
        }
    }
    assert!(acked, "cumulative ACK for the filled hole was never sent");
}
```

Output:

```
deadline after hole fill = Instant { millis: 86400003 }
panicked at src/tcp/mod.rs:12634:9:
cumulative ACK for the filled hole was never sent
```

No poll sends the ACK once the device has room, and the returned deadline is a day out.

## Suggested fix

Do not update `remote_last_ack`, `remote_last_win` or the SACK history in `ack_reply`. Either return the repr and have the caller call `ack_sent` only after a successful transmit, or, for the non-challenge cases, set `AckDelayTimer::Immediate` and let `dispatch` send the ACK in the same poll with its normal `NoBuffer`/device backpressure handling.
