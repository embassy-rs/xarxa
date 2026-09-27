# 227. iface-bind: first-match TCP demux lets an unbound socket shadow a same-tuple bound socket or listener

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:1511](../src/stack.rs#L1511), [src/tcp/mod.rs:2583](../src/tcp/mod.rs#L2583), [src/tcp/listener.rs:343](../src/tcp/listener.rs#L343) |
| Features | `iface-bind`, `tcp-listener` |
| Verification | confirmed against the code |

## Summary
The duplicate check only conflicts on an identical tuple with an identical binding, so an unbound socket and a socket bound to iface A can hold the same 4-tuple. Connected-socket demux takes the first slab match, and an unbound socket matches every interface. Segments arriving on A can go to the unbound socket. A new SYN on A for that tuple is swallowed before the listener step, contradicting the listener doc that the bound listener "wins".

## Details
src/tcp/mod.rs:2583:
```rust
.any(|(i, s)| i != index && s.binding == binding && s.tuple == Some(Tuple { local, remote }))
```
src/stack.rs:1511:
```rust
for (_, socket) in self.sockets.tcp.iter_mut() {
    if socket.binding_matches(iface) && socket.accepts(&src_addr, &dst_addr, &tcp_repr) {
        matched = true;
        reply_repr = socket.process(self.inner.now, &src_addr, &dst_addr, &tcp_repr);
        break;
    }
}
```
UDP and listener demux score a bound match higher. Connected-socket demux does not. The finder reproduced this in a scratch tree: two IP ifaces A and B, both 192.168.1.1/24, an unbound listener and a listener bound to A on port 80. A SYN on B was accepted into an unbound socket. A later SYN on A with the same tuple went to that socket, and the bound listener never saw it.

## Failure scenario
A device bridges two isolated LANs with the same addressing, and the same client IP/port connects on both links. The second link's connection reaches the first link's socket, gets challenge ACKs or RSTs, and never reaches its bound listener.

## Suggested fix
Prefer a bound match over an unbound one in connected-socket demux. Or treat an unbound socket as conflicting with any binding in `tuple_in_use` and `accept`.
