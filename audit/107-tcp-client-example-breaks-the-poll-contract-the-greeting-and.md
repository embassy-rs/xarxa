# 107. tcp_client example breaks the poll contract: the greeting and the FIN are queued after poll and sit until the next deadline (up to a day)

| | |
|---|---|
| Severity | low |
| Category | hang-stall |
| Location | [examples/tcp_client.rs:86](../examples/tcp_client.rs#L86), [examples/tcp_client.rs:96](../examples/tcp_client.rs#L96), [examples/tcp_client.rs:114](../examples/tcp_client.rs#L114), [examples/tcp_client.rs:118](../examples/tcp_client.rs#L118) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The loop polls once, then calls `send_slice` (greeting) and `close()`, then sleeps until the deadline from that earlier poll. TCP egress only happens in `poll`. So the greeting and the FIN wait until an unrelated packet arrives or the old deadline passes. For an idle established socket that deadline is one day. The library works as designed. The bug is in the example, which users may copy.

## Details
examples/tcp_client.rs:
```rust
// :86
let deadline = stack.poll(Instant::now());
// :96
socket.send_slice(b"Hello over TCP from xarxa!\n").unwrap();
// :114
socket.close();
// :118-119
let timeout = deadline - Instant::now();
wait(fd, Some(timeout.into())).unwrap();
```
DESIGN §7 states the contract: poll after operating on a socket. `tcp_server.rs` polls again before sleeping (line 115) and does not have this problem.

The header says "Closing `nc` (ctrl-C) closes the connection and exits the client." That can take up to 24 h. The greeting stall ends as soon as the peer sends anything, since that triggers a poll. The FIN stall after the peer closes has no such rescue. On TAP the deadline after the handshake is the neighbor entry expiry (about 60 s); this was not measured.

## Failure scenario
Run `cargo run --example tcp_client -- --tun tun0` against `nc -l 1234`. The greeting does not show up in nc until the user types something. Press ctrl-C in nc. The client ACKs the FIN and calls `close()`, but its FIN is not sent and the client does not exit for up to a day.

## Reproduction
Added to `mod stack_test` in src/tcp/mod.rs (scratch copy, IP medium):
```rust
#[test]
fn verify_tcp_client_example_loop_stalls() {
    let (mut stack, driver) = stack();
    let h = stack
        .add_tcp_socket_with_bufs(vec![0; 4096].leak(), vec![0; 4096].leak())
        .unwrap();
    stack
        .tcp_socket(h)
        .connect(SocketAddr::new(REMOTE_ADDR.into(), REMOTE_PORT), LOCAL_PORT)
        .unwrap();
    let _ = stack.poll(Instant::from_millis(0));
    let mut frame = driver.tx.borrow_mut().remove(0);
    let mut iss = TcpSeqNumber(0);
    parse_tx(&mut frame, |tcp| { assert!(tcp.syn()); iss = tcp.seq_number(); });
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
        control: TcpControl::Syn, seq_number: REMOTE_SEQ, ack_number: Some(iss + 1), ..SEND_TEMPL
    }));
    let deadline = stack.poll(Instant::from_millis(10));
    driver.tx.borrow_mut().clear();
    let mut s = stack.tcp_socket(h);
    assert_eq!(s.state(), State::Established);
    s.send_slice(b"Hello over TCP from xarxa!\n").unwrap();
    println!("deadline after handshake = {:?}", deadline);
    assert!(driver.tx.borrow().is_empty());
    let d2 = stack.poll(Instant::from_millis(11));
    println!("second poll deadline = {:?}, tx frames = {}", d2, driver.tx.borrow().len());
    driver.tx.borrow_mut().clear();
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
        control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1, ack_number: Some(iss + 1 + 27), ..SEND_TEMPL
    }));
    let deadline = stack.poll(Instant::from_millis(30));
    driver.tx.borrow_mut().clear();
    let mut s = stack.tcp_socket(h);
    s.close();
    println!("state after close = {:?}, deadline = {:?}", s.state(), deadline);
    assert!(driver.tx.borrow().is_empty());
    assert!(deadline.as_millis() > 86_000_000);
}
```
Output:
```
deadline after handshake = Instant { millis: 86400010 }
second poll deadline = Instant { millis: 211 }, tx frames = 1
state after close = LastAck, deadline = Instant { millis: 86400030 }
test result: ok. 1 passed
```

## Suggested fix
Poll again after the socket operations and sleep on that deadline, as tcp_server.rs does.
