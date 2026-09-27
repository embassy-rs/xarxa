# 251. ICMPv6 errors are not capped to the egress interface's IP MTU, so they are dropped on small-MTU links

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/stack.rs:2893](../src/stack.rs#L2893), [src/stack.rs:2119](../src/stack.rs#L2119), [src/stack.rs:2670](../src/stack.rs#L2670) |
| Features | `medium-ieee802154` without `sixlowpan-fragmentation` |
| Verification | confirmed against the code |

## Summary
`build_icmpv6_error` sizes its quote by the IPv6 minimum MTU and the buffer tailroom only. The route, with its `ip_mtu`, is already known but not used. On an 802.15.4 interface without `sixlowpan-fragmentation`, `ip_mtu` is about 100 bytes, and `transmit_ip` drops any larger IPv6 packet. So port unreachable and parameter problem errors quoting more than about 50 bytes never go out.

## Details
src/stack.rs:2893:
```rust
let quote_len = orig
    .len()
    .min(IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMP_ERROR_HEADER_LEN)
    .min(reply.tailroom() - ICMP_ERROR_HEADER_LEN);
```
src/stack.rs:2119 calls it after `route_reply` without passing `route.ip_mtu`.

src/stack.rs:2670: `if total_ip_len > iface.ip_mtu()` drops IPv6 with "IPv6 fragmentation support is unimplemented".

src/sixlowpan.rs:38-48, without fragmentation: `(link_mtu + IPV6_HEADER_LEN).saturating_sub(IEEE802154_MAX_HEADER_LEN + IPHC_MAX_EMITTED_LEN)`.

Small `PACKET_BUF_SIZE` is not affected: the tailroom cap matches the buffer-derived `ip_mtu` clamp. Ethernet or IP links below 1280 are not valid IPv6 links (RFC 8200 §5), so 802.15.4 is the realistic case.

## Failure scenario
802.15.4 build without `sixlowpan-fragmentation`. A peer sends a UDP datagram with a few dozen bytes of payload to a closed port. The port unreachable error exceeds `ip_mtu` and is dropped. The peer never learns the port is closed.

## Suggested fix
Pass `route.ip_mtu` into `build_icmpv6_error` and add `.min(ip_mtu.saturating_sub(IPV6_HEADER_LEN + ICMP_ERROR_HEADER_LEN))` to the quote length.
