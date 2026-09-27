# 096. TcpSocket::accept does not check for an existing socket with the same 4-tuple, so a retransmitted SYN yields a duplicate socket stuck in SYN-RECEIVED

| | |
|---|---|
| Severity | medium |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:2633](../src/tcp/mod.rs#L2633), [src/tcp/listener.rs:427](../src/tcp/listener.rs#L427), [src/tcp/listener.rs:95](../src/tcp/listener.rs#L95), [src/stack.rs:1511](../src/stack.rs#L1511) |
| Features | default (`tcp-listener`) |
| Verification | reproduced with a test |

## Summary

`TcpListener::accept` removes the SYN from the backlog. Until the token is accepted into a socket, no socket owns the tuple, so a retransmitted SYN is recorded again and produces a second token. `TcpSocket::accept` only checks `is_open()`, so both tokens can be accepted and two sockets end up with the same tuple. Demux always picks the first one. The second never receives anything and retransmits SYN|ACKs until its timeout, which by default never comes.

## Details

src/tcp/listener.rs:427, the pop in `TcpListener::accept`:

```rust
let syn = state.queue.remove(0);
```

After that, a retransmitted SYN finds no connected socket in `process_tcp` and reaches `record_syn` (src/tcp/listener.rs:95) again, which queues a fresh entry.

src/tcp/mod.rs:2633, `TcpSocket::accept`:

```rust
pub fn accept(&mut self, token: AcceptToken) -> Result<(), AcceptError> {
    if self.is_open() {
        return Err(AcceptError::InvalidState);
    }
    let s = self.sockets.get_mut(self.index);
    s.reset(self.tx.inner.now);
    token.start_syn_received(s, self.tx.rand());
    Ok(())
}
```

There is no equivalent of `connect`'s `tuple_in_use` check (src/tcp/mod.rs:2579-2593). `AcceptError` has only `InvalidState`.

src/stack.rs:1511, demux takes the first match in slab order:

```rust
for (_, socket) in self.sockets.tcp.iter_mut() {
    if socket.binding_matches(iface) && socket.accepts(&src_addr, &dst_addr, &tcp_repr) {
```

With real (random) ISNs there is a second outcome, traced in code but not tested because test builds use a fixed ISN. The client ACKs whichever SYN|ACK it saw. If that was the second socket's and the first socket is earlier in the slab, the ACK lands on the first socket. Its SYN-RECEIVED check (src/tcp/mod.rs:1044-1047) fails:

```rust
if ack_number != self.local_seq_no + 1 {
    debug!("unacceptable ACK in response to SYN|ACK");
    return Some(Self::rst_reply(repr));
}
```

The RST carries seq = SEG.ACK, which is the client's RCV.NXT, so the client resets a fresh connection.

## Failure scenario

1. A no-alloc server has N preallocated sockets, all busy. Its accept loop pops a token and waits for a socket to free up.
2. The wait exceeds the client's initial SYN RTO (about 1 s). The client retransmits its SYN and the listener queues a second token for the same tuple.
3. Sockets free up. The loop accepts both tokens into two sockets. Both calls return `Ok`.
4. One socket reaches ESTABLISHED. The other stays in SYN-RECEIVED, sending SYN|ACKs to the client indefinitely and holding a socket. Or, with the other slab order and differing ISNs, the client gets an RST.

Holding a token for a while is an intended pattern: the docs describe storing tokens or sending them to another task.

## Reproduction

Test in `mod stack_test`, run in a scratch copy of the crate:

```rust
#[test]
#[cfg(feature = "tcp-listener")]
fn zz_v_accept_duplicate_tuple() {
    let (mut stack, driver) = stack();
    let lh = stack.add_tcp_listener().unwrap();
    stack.tcp_listener(lh).listen(LOCAL_PORT).unwrap();
    let syn = tcp_packet(&TcpRepr { control: TcpControl::Syn, seq_number: REMOTE_SEQ, ..SEND_TEMPL });
    driver.rx.borrow_mut().push_back(syn.clone());
    stack.poll(Instant::from_millis(0));
    let t1 = stack.tcp_listener(lh).accept().unwrap();
    driver.rx.borrow_mut().push_back(syn);
    stack.poll(Instant::from_millis(1000));
    let t2 = stack.tcp_listener(lh).accept().unwrap();
    let a = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
    let b = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
    assert_eq!(stack.tcp_socket(a).accept(t1), Ok(()));
    assert_eq!(stack.tcp_socket(b).accept(t2), Ok(()));
    stack.poll(Instant::from_millis(1000));
    driver.tx.borrow_mut().clear();
    driver.rx.borrow_mut().push_back(tcp_packet(&TcpRepr {
        seq_number: REMOTE_SEQ + 1,
        ack_number: Some(LOCAL_SEQ + 1),
        ..SEND_TEMPL
    }));
    stack.poll(Instant::from_millis(1001));
    // loop polling at returned deadlines up to t=2_000_000 ms, counting SYN|ACKs
    ...
    assert_eq!(stack.tcp_socket(a).state(), State::Established);
    assert_eq!(stack.tcp_socket(b).state(), State::SynReceived);
    assert!(synacks > 5);
}
```

Output:

```
synacks sent: 2
a=Established b=SynReceived synacks_after=38
ok
```

## Suggested fix

In `TcpSocket::accept`, check the token's tuple and binding against the other sockets, as `connect` does, and reject it (a new `AcceptError` variant) or drop it. Alternatively, have the listener suppress SYNs whose tuple matches a token handed out recently.
