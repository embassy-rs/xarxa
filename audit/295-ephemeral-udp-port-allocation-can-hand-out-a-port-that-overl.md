# 295. Ephemeral UDP port allocation can hand out a port that overlaps an existing socket's filter

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/udp.rs:568](../src/udp.rs#L568), [src/udp.rs:484](../src/udp.rs#L484), [src/udp.rs:1058](../src/udp.rs#L1058) |
| Features | `udp` (default) |
| Verification | reproduced with a test |

## Summary
For port 0, `bind` only avoids ports held by a socket with an identical tuple. An ephemeral wildcard socket can get the same port as a socket bound to a concrete local address, or a connected socket. The most-specific demux then gives the new socket's traffic to the other one, or the reverse. The `bind` doc promises "an unused ephemeral port".

## Details
src/udp.rs:568:
```rust
let in_use = |local: ListenSocketAddr| {
    sockets
        .iter()
        .any(|(i, s)| i != index && s.local == local && s.remote == remote && s.binding == binding)
};

if local.port == 0 {
    local.port = alloc_ephemeral_port(self.tx.rand(), |port| {
        in_use(ListenSocketAddr { addr: local.addr, port })
    })
```
The identical-tuple rule is right for explicit ports. For an ephemeral pick the stack chooses a port that can't work. The chance is about (sockets on a port)/16384 per ephemeral bind: rare but silent.

## Failure scenario
`DnsClient` binds an ephemeral port P. Later the app connects a UDP socket to the same DNS server and also gets P. The connected socket outscores `DnsClient`'s and takes every DNS response. Lookups time out for the lifetime of both sockets.

## Reproduction
Added to `src/stack.rs` `mod test`:
```rust
#[test]
fn vfy_udp8_ephemeral_overlap() {
    let (mut stack, rx, _tx) = test_stack(Medium::Ip);
    let a = stack.add_udp_socket().unwrap();
    let b = stack.add_udp_socket().unwrap();
    stack.inner.rand = Rand::new(7);
    stack.udp_socket(b).bind(0, ListenSocketAddr::UNSPECIFIED).unwrap();
    let p = stack.udp_socket(b).local_addr().port;
    stack.udp_socket(b).close();
    stack.udp_socket(a).bind(SocketAddr::new(OUR_V4.into(), p), ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.inner.rand = Rand::new(7);
    stack.udp_socket(b).bind(0, ListenSocketAddr::UNSPECIFIED).unwrap();
    let pb = stack.udp_socket(b).local_addr().port;
    println!("A port {} B port {}", p, pb);
    let d = udp_datagram(REMOTE_V4.into(), 53, OUR_V4.into(), pb, b"x");
    inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &d));
    println!("A can_recv {} B can_recv {}", stack.udp_socket(a).can_recv(), stack.udp_socket(b).can_recv());
}
```
Output:
```
A port 54192 B port 54192
A can_recv true B can_recv false
```

## Suggested fix
For ephemeral allocation, treat a port as in use if any open socket with the same or a wildcard binding holds it, not only one with an identical tuple.
