# 110. UDP echo examples panic on routine network input: send_slice(...).unwrap() fails for a datagram from source port 0 or from an unroutable source

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [examples/tuntap.rs:78](../examples/tuntap.rs#L78), [examples/sixlowpan.rs:102](../examples/sixlowpan.rs#L102), [src/udp.rs:855](../src/udp.rs#L855) |
| Features | default |
| Verification | confirmed against the code |

## Summary
tuntap and sixlowpan echo each datagram with `socket.send_slice(&data, meta.remote_addr).unwrap()`. Ingress queues datagrams from source port 0, but sending back to port 0 returns `Unaddressable`, so one such datagram crashes the example. An off-link IPv6 source does the same, since tuntap adds no IPv6 default route. The `while let Ok(..) = socket.recv()` loop also stops at `RecvError::IcmpError`, leaving queued datagrams until the next wake-up.

## Details
src/udp.rs:1001 drops only `dst_port == 0`. src/udp.rs:855-860:
```rust
if meta.remote_addr.port == 0 {
    meta.remote_addr.port = remote.port;
}
if !meta.remote_addr.is_specified() {
    return Err(SendError::Unaddressable);
}
```
The example binds the remote as `ListenSocketAddr::UNSPECIFIED`, so `remote.port` is 0 too. `route()` returning `None` for an off-link IPv6 source also yields `Unaddressable`. `DeviceBusy` and `NoBuffer` are documented retry conditions and are unwrapped as well. `recv` reports a pending ICMP error before queued datagrams, which ends the loop at examples/tuntap.rs:73.

## Failure scenario
With the tuntap example running, a host sends a datagram to 192.168.69.1:6969 from source port 0 (`nmap -sU -g 0 -p 6969 192.168.69.1`). The echo returns `Unaddressable` and the example panics. A datagram from 2001:db8::5 does the same.

## Suggested fix
Log and skip send errors. Loop on `recv` until `Exhausted`, logging `IcmpError` and continuing.
