# 001. TCP: SYN-SENT socket panics in last_scaled_window (SeqNumber underflow) when the handshake completes with remote_last_win == 0

| | |
|---|---|
| Severity | critical |
| Category | panic |
| Location | [src/tcp/mod.rs:697](../src/tcp/mod.rs#L697), [src/tcp/mod.rs:1286](../src/tcp/mod.rs#L1286), [src/tcp/mod.rs:1018](../src/tcp/mod.rs#L1018), [src/tcp/mod.rs:744](../src/tcp/mod.rs#L744), [src/tcp/mod.rs:1705](../src/tcp/mod.rs#L1705), [src/wire/tcp.rs:66](../src/wire/tcp.rs#L66), [src/stack.rs:886](../src/stack.rs#L886) |
| Features | default |
| Verification | reproduced with a test |

## Summary

When a SYN-SENT socket accepts the peer's SYN or SYN|ACK, it sets `remote_last_ack` to the peer's ISN but leaves `remote_last_win` alone. If `remote_last_win` is 0 at that point, the next dispatch computes `last_ack + 0 - (ISN + 1)` in `last_scaled_window`, and `SeqNumber - SeqNumber` panics. The panic is unconditional, so release builds crash too. It is reachable from the network (our SYN held back by a busy device or an empty pool, then a bare SYN from the peer) and from the API (a zero-capacity RX buffer). This was the only crash the fuzzer found. All 33 artifacts have this root cause.

## Details

src/tcp/mod.rs:692-697
```rust
fn last_scaled_window(&self) -> Option<u16> {
    let last_ack = self.remote_last_ack?;
    let next_ack = self.remote_seq_no + self.rx_buffer.len();

    let last_win = (self.remote_last_win as usize) << self.remote_win_shift;
    let last_win_adjusted = last_ack + last_win - next_ack;
```

src/wire/tcp.rs:63-68 is a plain `panic!`, not a debug assert:
```rust
fn sub(self, rhs: SeqNumber) -> usize {
    let result = self.0.wrapping_sub(rhs.0);
    if result < 0 {
        panic!("attempt to subtract sequence numbers with underflow")
    }
```

The code assumes `next_ack <= last_ack + last_win`. The SYN-SENT handler breaks it.

src/tcp/mod.rs:1284-1286
```rust
self.remote_seq_no = repr.seq_number + 1;
self.remote_last_seq = self.local_seq_no + 1;
self.remote_last_ack = Some(repr.seq_number);
```

After this, `next_ack = last_ack + 1`, so `last_win_adjusted = last_win - 1`. `remote_last_win` is 0 after `reset()` (line 744) and is only set by `ack_sent()` (line 1705), when a segment actually goes out. So it is 0 here in two cases:

1. Our SYN never left. `connect()` was followed by a dispatch that the device held back (`Blocked`) or the pool held back (`Blocked::NoBuffer`). A held-back segment leaves the socket untouched, by design. Then a bare SYN arrives. The simultaneous-open arm accepts it with no ACK or sequence check:

   src/tcp/mod.rs:1018
   ```rust
   (State::SynSent, TcpControl::Syn, None) => (),
   ```
   The peer needs only the 4-tuple, not our ISN. This can be a real simultaneous open, or an attacker who knows or guesses the local port while the device is congested or the pool is drained. The pool can be drained remotely (see 004). Line 1285 also sets `remote_last_seq = local_seq_no + 1` although our SYN was never sent. The fuzz artifacts use the SYN|ACK variant: the harness ISN is deterministic, so the corpus SYN|ACK carries the right ACK number although our SYN was held back.
2. The socket has a zero-capacity RX buffer: `add_tcp_socket(0, n)` or `add_tcp_socket_with_bufs(&mut [], ..)`. Neither rejects it. Their docs (src/stack.rs:879, 908) list only the 1 GiB panic. Our SYN goes out with win=0, `ack_sent` records 0, and any normal SYN|ACK then triggers the panic.

The call path is `Stack::poll` -> `dispatch` (line 2069) -> `ack_due` (line 1644) -> `window_to_update` (line 1691) -> `last_scaled_window` (line 697). `window_to_update` runs in SYN-SENT, SYN-RECEIVED and ESTABLISHED. The `new_win > 0` guard in `window_to_update` is evaluated after `last_scaled_window`, so it does not help.

In the simultaneous-open case the panic happens in the same poll that receives the SYN. The device does not need to free up first.

Backtrace from the release fuzz build (every artifact):
```
panicked at src/wire/tcp.rs:66:13: attempt to subtract sequence numbers with underflow
 2: <SeqNumber as Sub>::sub            src/wire/tcp.rs:66
 3: TcpSocketState::last_scaled_window  src/tcp/mod.rs:697
 4: TcpSocketState::window_to_update    src/tcp/mod.rs:1691
 5: TcpSocketState::ack_due             src/tcp/mod.rs:1644
 6: TcpSocketState::dispatch            src/tcp/mod.rs:2069
 7: Stack::poll                         src/stack.rs:1173
```
Trace of the minimized artifact, last TCP events: `state=CLOSED=>SYN-SENT`, `sending SYN`, `interface has no room for segment to 192.168.1.2, holding it back`, `received SYN|ACK`, `state=SYN-SENT=>ESTABLISHED`, then the panic.

## Failure scenario

- Network: the app calls `connect(remote:80, 40000)` while the driver's TX ring is full or the pool is empty, so the SYN is held back. A SYN from remote:80 to port 40000 arrives. The socket moves to SYN-RECEIVED with `remote_last_ack = ISN` and `remote_last_win = 0`. The same `Stack::poll` panics. The firmware crashes.
- API: the app creates a send-only socket with `add_tcp_socket(0, 4096)` and connects. The server answers with a normal SYN|ACK. The next `Stack::poll` panics. This is deterministic with a conforming peer.

## Reproduction

Whole-stack tests, added to `mod stack_test` in src/tcp/mod.rs in a scratch copy of HEAD:

```rust
#[test]
fn audit_stack_simultaneous_open_syn_held_back() {
    let (mut stack, driver) = stack();
    driver.room.set(Some(0));
    let h = stack.add_tcp_socket(1024, 1024).unwrap();
    stack.tcp_socket(h).connect((REMOTE_ADDR, REMOTE_PORT), LOCAL_PORT).unwrap();
    stack.poll(Instant::from_millis(0));
    assert!(driver.tx.borrow().is_empty());
    assert_eq!(stack.tcp_socket(h).state(), State::SynSent);
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(1)); // panics
}

#[test]
fn audit_stack_zero_rx_buffer() {
    let (mut stack, driver) = stack();
    let h = stack.add_tcp_socket(0, 1024).unwrap();
    stack.tcp_socket(h).connect((REMOTE_ADDR, REMOTE_PORT), LOCAL_PORT).unwrap();
    stack.poll(Instant::from_millis(0));
    let mut frame = driver.tx.borrow_mut().remove(0);
    parse_tx(&mut frame, |tcp| { assert!(tcp.syn()); assert_eq!(tcp.window_len(), 0); });
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ack_number: Some(LOCAL_SEQ + 1), ..SEND_TEMPL }));
    stack.poll(Instant::from_millis(1)); // panics
}
```

Command: `cargo test --lib audit_ -- --nocapture --test-threads=1`

Output:
```
thread 'tcp::stack_test::audit_stack_simultaneous_open_syn_held_back' panicked at src/wire/tcp.rs:66:13:
attempt to subtract sequence numbers with underflow
thread 'tcp::stack_test::audit_stack_zero_rx_buffer' panicked at src/wire/tcp.rs:66:13:
attempt to subtract sequence numbers with underflow
```

Two socket-level tests (`audit_simultaneous_open_before_syn_sent`, `audit_zero_rx_buffer_syn_ack`) fail the same way. They are in `fuzz-artifacts/tcp-last-scaled-window-unit-tests.patch` in the session scratchpad (`/tmp/claude-1000/-home-dirbaio-embassy-xarxa/ab67066f-af86-4b74-aa62-a0203ff768b9/scratchpad/`). The minimized fuzz input is `fuzz-artifacts/min-tcp-last-scaled-window` in the same place. Replay it with the ported harness in `scratchpad/fuzz/fuzz`:

```
cargo +nightly fuzz run -O -s none stack ../../fuzz-artifacts/min-tcp-last-scaled-window
```

## Suggested fix

- Make `last_scaled_window` saturate: if `next_ack` is past `last_ack + last_win`, treat the adjusted window as 0.
- A fix at line 1286 alone is not enough. In the bare-SYN case our SYN was never sent, `remote_last_seq` is already `local_seq_no + 1` and `remote_last_win` is 0.
- Consider whether line 1018 should accept a simultaneous-open SYN while our own SYN has not been transmitted.
- Reject zero-capacity RX buffers, or document and support them.
