# 358. ICMP errors on unconnected UDP sockets can be forged into recv(), undocumented

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/udp.rs:1090](../src/udp.rs#L1090), [src/udp.rs:683](../src/udp.rs#L683) |
| Features | default (`icmp-errors`) |
| Verification | confirmed against the code |

## Summary
Unconnected sockets get ICMP errors by design (DESIGN.md §7). Nothing checks that the socket ever sent to the quoted remote. An off-path host that knows a server port can make the next `recv()` return `Err(IcmpError)` with a remote of its choosing. The public docs do not warn about this.

## Details
src/udp.rs:1090-1093:
```rust
if let Some(index) = demux(sockets, None, &remote.addr, remote.port, &local.addr, local.port) {
    ...
    socket.pending_error = Some((error, remote));
```
src/udp.rs:683 (`recv`) returns it before queued datagrams. The error is one-shot and newest-wins, and queued data is not dropped, so an app that ignores it loses nothing. This complies with RFC 1122 §4.1.3.3 (UDP MUST pass ICMP errors up). `DnsClient` already treats it as non-fatal (src/dns.rs).

## Failure scenario
A server loop `loop { let p = sock.recv()?; ... }` gets one spoofed port-unreachable quoting `our:P -> x:y` and exits.

## Suggested fix
Say on `recv`, `recv_slice` and `take_icmp_error` that on an unconnected socket the error can be forged and should not be treated as fatal. Optionally add an opt-out for unconnected sockets.
