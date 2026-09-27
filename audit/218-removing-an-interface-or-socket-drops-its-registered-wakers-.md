# 218. Removing an interface or socket drops its registered wakers without waking them

| | |
|---|---|
| Severity | low |
| Category | missed-wake |
| Location | [src/stack.rs:751](../src/stack.rs#L751), [src/stack.rs:815](../src/stack.rs#L815), [src/stack.rs:852](../src/stack.rs#L852), [src/stack.rs:944](../src/stack.rs#L944), [src/stack.rs:983](../src/stack.rs#L983) |
| Features | async (default) |
| Verification | confirmed against the code |

## Summary
`remove_iface` wakes UDP and raw senders blocked on the interface, but drops `IfaceState::waker` without waking it. `remove_udp_socket`, `remove_raw_socket`, `remove_tcp_socket` and `remove_tcp_listener` drop the socket's wakers the same way. A task pending on one of them is never woken.

## Details
`remove_iface` only wakes `tx_waker` of sockets whose `tx_blocked_on == handle`, then calls `self.ifaces.remove(handle.index())`. The socket removals are a bare `.remove(handle.index())`. `WakerRegistration` (src/waker.rs) is `{ waker: Option<Waker> }` with no waking `Drop`.

`Iface::register_waker` (src/iface/mod.rs:471-480) says it is woken when "addresses or routes added or removed". Removal removes all of them. `TcpListener::close` and `TcpSocket::reset` do wake their wakers, so removal is the odd one out.

In embassy-net, removal happens when the owning object is dropped, so a pending future is unlikely there. That keeps this low.

## Failure scenario
Task A awaits accept on listener L, or waits for link up on an interface. Task B calls `remove_tcp_listener(L)` or `remove_iface`. Task A is never woken and leaks. Had it been woken, it would have hit the stale-handle panic or its own teardown path.

## Suggested fix
Call `wake()` on the interface's and socket's registrations before removing them from the slab.
