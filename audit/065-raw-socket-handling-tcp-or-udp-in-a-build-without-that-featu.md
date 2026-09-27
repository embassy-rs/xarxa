# 065. Raw socket handling UDP or TCP in a build without that feature still triggers Protocol Unreachable / Parameter Problem

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/stack.rs:1425](../src/stack.rs#L1425), [src/stack.rs:1458](../src/stack.rs#L1458), [src/stack.rs:1755](../src/stack.rs#L1755), [src/stack.rs:1781](../src/stack.rs#L1781), [src/raw.rs:705](../src/raw.rs#L705) |
| Features | `raw-ip` without `udp`, or without `tcp` |
| Verification | reproduced with a test |

## Summary

`stack_wants` always includes UDP and TCP, whatever features are built. In a build without `udp` (or `tcp`), a raw socket bound to that protocol only gets a copy. The packet then falls into the `_` arm, which ignores `handled_by_raw` and sends ICMPv4 Protocol Unreachable or ICMPv6 Parameter Problem code 1. Peers treat these as hard errors.

## Details

src/stack.rs:1425 (IPv4), not cfg-gated:

```rust
let stack_wants = matches!(next_header, IpProtocol::Icmp | IpProtocol::Udp | IpProtocol::Tcp);
```

src/raw.rs:705:

```rust
if stack_wants {
    if let Some(copy) = copy_packet(&buf) {
        socket.rx_enqueue(copy);
    }
    return Some((buf, true));
}
```

The `IpProtocol::Udp` and `IpProtocol::Tcp` arms of the match are behind `#[cfg(feature = "udp")]` and `#[cfg(feature = "tcp")]`. Without them the packet reaches `_` (src/stack.rs:1457), which calls `transmit_icmpv4_error(.., ProtoUnreachable)`. `handled_by_raw` is only read by `process_udp`. IPv6 has the same shape: `stack_wants` at src/stack.rs:1755, and the `_` arm at 1780 sends Parameter Problem, unrecognized next header.

For a protocol the stack really does not know (for example SCTP), `stack_wants` is false, the raw socket takes the buffer and no error is sent. So the outcome depends on the feature set.

Side effect: each such packet costs an extra pool buffer and a copy. The socket misses the packet when the pool is empty, although nothing else wanted it.

## Failure scenario

Firmware built with `raw-ip` but without `tcp` runs a small TCP on a raw socket bound to protocol 6. Each segment from the peer reaches the socket, and the stack also sends Protocol Unreachable. The peer aborts the connection. With `udp` off and a UDP protocol on a raw socket, a Linux peer gets ECONNREFUSED (IPv4) or EPROTO (IPv6).

## RFC reference

RFC 1122 §3.2.2.1:

> A host SHOULD generate Destination Unreachable messages with code: 2 (Protocol Unreachable), when the designated transport protocol is not supported

Here the protocol is supported, by the raw socket.

## Reproduction

Standalone test module appended to src/stack.rs in a scratch copy, gated `#[cfg(all(test, feature = "medium-ip", feature = "ipv4", feature = "ipv6", feature = "raw-ip", not(feature = "udp")))]`. It sets up an IP-medium iface with 192.168.1.1/24 and fdaa::1/64, binds a raw socket to `RawMode::Ip { version: None, protocol: Some(IpProtocol::Udp) }`, and injects a 9-byte UDP datagram from 192.168.1.2, then one from fdaa::2.

`cargo test --lib --no-default-features --features std,alloc,log,medium-ip,ipv4,ipv6,raw-ip,icmp-errors zz_raw -- --nocapture`:

```
v4: raw got: true, tx (proto,type,code): [(1, 3, 2)]
v6: raw got: true, tx (nh,type,code): [(58, 4, 1)]
```

The original report also reproduced the TCP case, with `udp` on and `tcp` off (`--features std,alloc,log,medium-ethernet,medium-ip,ipv4,ipv6,raw-ethernet,raw-ip,udp,icmp-errors`). A raw socket was bound to protocol 6 and a TCP segment was injected. The socket got the segment and the stack sent ICMP type 3 code 2 quoting it.

## Suggested fix

Put the `Udp` and `Tcp` terms of `stack_wants` behind `cfg(feature = "udp")` and `cfg(feature = "tcp")`, in both `process_ipv4` and `process_ipv6`. Then the raw socket consumes the packet and no error is sent. Optionally also skip the error in the `_` arm when `handled_by_raw` is set.
