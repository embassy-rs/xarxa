# 108. Example main loop: packets taken in by the loop's second poll are not handled until the next wake-up

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [examples/tcp_server.rs:115](../examples/tcp_server.rs#L115), [examples/sixlowpan.rs:97](../examples/sixlowpan.rs#L97), [src/stack.rs:1070](../src/stack.rs#L1070) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`tcp_server.rs` polls, services sockets, polls again, then sleeps on the fd until the deadline. The second poll drains the TAP fd. A SYN recorded there adds no deadline and leaves no fd activity, so it waits for an unrelated packet or timer. UDP datagrams queued by the second poll wait the same way. The `Stack::poll` docs don't say that a sync loop must check its sockets after every poll before sleeping.

## Details
examples/tcp_server.rs:76 runs `stack.poll(Instant::now());`, then accept and echo, then:
```rust
// examples/tcp_server.rs:115-119
let deadline = stack.poll(Instant::now());
// ...
let timeout = deadline - Instant::now();
wait(fd, Some(timeout.into())).unwrap();
```
`TunTapDriver::receive` returns `None` only on `WouldBlock` (src/driver_impls/tuntap.rs:226), so the poll empties the fd. DESIGN §7: "Listeners never participate in `poll`'s egress or deadline computation." The sleep can last up to `MAX_POLL_DELAY` on a quiet link. `examples/sixlowpan.rs` uses the same two-poll pattern. `tuntap.rs` and `multicast.rs` poll once per iteration.

The finder saw an 826 ms SYN|ACK delay against a Linux client with a harness using this loop. The verifier did not reproduce the timing. A 300-connection run of the real example did not hit the window, so the effect is timing-dependent.

## Failure scenario
A SYN arrives between the two polls of an iteration, for example right after another connection was serviced. The second poll records it on the listener. The loop sleeps until the next frame or timer. The client retransmits its SYN after 1 s.

## Suggested fix
Use one poll per iteration: poll, service sockets, and loop again right away if any socket operation was done. Add a sentence to the `Stack::poll` docs that poll can make sockets readable or acceptable, so a sync loop must check its sockets after every poll before sleeping.
