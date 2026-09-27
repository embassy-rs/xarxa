# 100. No ICMPv6 error rate limiting: every datagram to a closed UDP port triggers a Port Unreachable

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/stack.rs:2090](../src/stack.rs#L2090), [src/udp.rs:1036](../src/udp.rs#L1036), [src/stack.rs:2050](../src/stack.rs#L2050) |
| Features | default (`ipv6`) |
| Verification | confirmed against the RFC text |

## Summary

`transmit_icmpv6_error` has no rate limiter, and there is none anywhere in src/. Every unmatched unicast UDP datagram produces one ICMPv6 Port Unreachable. The same applies to every other ICMPv6 error the stack originates: parameter problem for unknown next headers and hop-by-hop options, and destination unreachable after failed neighbor resolution. RFC 4443 makes limiting a MUST.

## Details

src/udp.rs:1036-1044, in `process_udp`, called for every unmatched datagram unless a raw socket took a copy:

```rust
IpAddr::V6(_) => self.transmit_icmpv6_error(
    iface,
    &mut buf,
    Icmpv6Message::DstUnreachable,
    Icmpv6DstUnreachable::PortUnreachable.into(),
    0,
    false,
),
```

src/stack.rs:2090, `transmit_icmpv6_error`, only filters on addresses before routing, building and transmitting:

```rust
if !src_addr.x_is_unicast() {
    return;
}
if dst_addr.is_multicast() && !allow_multicast_dst {
    return;
}
```

Impact is limited. The error is about the size of the offending packet, so amplification is at most 1:1. Errors are best-effort and dropped when the pool or device is full, so socket traffic keeps its guarantee. Under a flood they still take pool buffers and TX room, and they reflect traffic at a spoofed source.

For IPv4 (`transmit_icmpv4_error`, src/stack.rs:2050), RFC 1122 §4.1.3.1 makes Port Unreachable a SHOULD and rate limiting optional, so that side is not a violation.

## Failure scenario

An attacker floods the device with UDP datagrams to closed ports, with a spoofed IPv6 source. The device sends one ICMPv6 error per datagram to the victim, consuming pool buffers and device queue space at the flood rate.

## RFC reference

RFC 4443 §2.4(f):

> Finally, in order to limit the bandwidth and forwarding costs incurred by originating ICMPv6 error messages, an IPv6 node MUST limit the rate of ICMPv6 error messages it originates.

> A recommended method for implementing the rate-limiting function is a token bucket

> The rate-limiting parameters SHOULD be configurable.

## Suggested fix

Add a small stack-global token bucket checked in `transmit_icmpv6_error`, so it covers every ICMPv6 error, with configurable rate and burst. Optionally apply it to `transmit_icmpv4_error` too.
