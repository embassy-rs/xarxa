# 292. Spoofed ICMP error quoting source port 0 is stored on an unbound socket and reported after a later bind()

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/udp.rs:258](../src/udp.rs#L258), [src/udp.rs:1084](../src/udp.rs#L1084), [src/udp.rs:516](../src/udp.rs#L516) |
| Features | `icmp-errors`, `udp` (default) |
| Verification | reproduced with a test |

## Summary
The ICMP error demux doesn't exclude port 0. An unbound socket has local port 0 and wildcard filters, so it matches an error quoting source port 0 and gets `pending_error` set. `bind()` doesn't clear it, so the first `recv()` after binding returns an attacker-chosen `IcmpError`. `close()` clears the slot, so this hits never-bound sockets, and closed ones only between close and the next bind.

## Details
src/udp.rs:258 (`match_score`):
```rust
if self.local.port != dst_port {
    return None;
}
```
Normal ingress drops port 0 first (src/udp.rs:1001). The ICMP path does not: `process_icmp_error` (src/udp.rs:1084) demuxes on the quoted port and sets `socket.pending_error = Some((error, remote))`. `bind()` sets `local` and `remote` but not `pending_error`.

## Failure scenario
An off-path attacker sends ICMP port unreachables quoting source port 0 while a socket is unbound. After the next bind, the first `recv` or `take_icmp_error` reports an error for a remote the socket never talked to.

## Reproduction
Added to `src/stack.rs` `mod test`:
```rust
#[test]
fn vv_udp7_stale_icmp_error_after_bind() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    let handle = stack.add_udp_socket().unwrap();
    let quote = ipv4_packet(OUR_V4, REMOTE_V4, IpProtocol::Udp, &udp_datagram(OUR_V4.into(), 0, REMOTE_V4.into(), 53, b"x"));
    let error = icmpv4_error_packet(REMOTE_V4, OUR_V4, Icmpv4Message::DstUnreachable, Icmpv4DstUnreachable::PortUnreachable.into(), &quote);
    inject(&mut stack, &rx, error);
    stack.udp_socket(handle).bind(6000, ListenSocketAddr::UNSPECIFIED).unwrap();
    let r = stack.udp_socket(handle).recv();
    println!("udp7 recv after bind: {:?}", r.as_ref().err());
    assert!(matches!(r, Err(UdpRecvError::Exhausted)), "stale error delivered");
}
```
Output:
```
udp7 recv after bind: Some(IcmpError { error: PortUnreachable, remote: SocketAddr { addr: V4(192.168.1.2), port: 53 } })
panicked: stale error delivered
```

## Suggested fix
Return `None` from demux when `dst_port == 0` (or skip sockets that aren't open), and clear `pending_error` in `bind()`.
