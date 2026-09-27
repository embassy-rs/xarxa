# 228. Immediate ACKs from process() ignore the socket's hop limit and interface binding

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:1550](../src/stack.rs#L1550), [src/stack.rs:2141](../src/stack.rs#L2141), [src/stack.rs:398](../src/stack.rs#L398), [src/tcp/mod.rs:2464](../src/tcp/mod.rs#L2464) |
| Features | default; `iface-bind` for the binding part |
| Verification | confirmed against the code |

## Summary
Replies returned by `TcpSocketState::process` (dup ACKs for out-of-order data, ACKs of out-of-window data, challenge ACKs) go through `transmit_tcp_reply`. It routes with `IfaceBinding::Any` and a fixed hop limit of 64. A socket bound with `bind_to_iface` can send them out of another interface, and a socket with `set_hop_limit` sends them with TTL 64.

## Details
src/stack.rs:1557:
```rust
self.transmit_reply(&route, buf, src_addr, dst_addr, IpProtocol::Tcp, 64);
```
The route comes from `route_reply`, which ends in `self.route(IfaceBinding::Any, dst_addr)` (src/stack.rs:398). The `bind_to_iface` doc at src/tcp/mod.rs:2464 says "A socket bound to an interface only sends and receives packets on it". For IPv6 link-local peers `route_reply` pins the reply to the arrival interface, so the binding leak only affects other destinations.

## Failure scenario
A socket is bound to a VPN interface while the default route goes out Ethernet. Out-of-order data triggers dup ACKs that leave via Ethernet with the VPN source address. Separately, a socket with hop limit 1 sends its dup ACKs with TTL 64.

## Suggested fix
Send socket-generated replies with the socket's binding and hop limit, either by returning both from `process()` or by deferring these ACKs to `dispatch`.
