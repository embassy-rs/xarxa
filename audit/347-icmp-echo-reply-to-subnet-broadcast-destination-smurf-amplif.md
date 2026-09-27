# 347. Echo requests to an IPv4 broadcast address are answered by default

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/stack.rs:1585](../src/stack.rs#L1585), [src/stack.rs:6826](../src/stack.rs#L6826) |
| Features | `ipv4`, `icmp-ping-reply` (default) |
| Verification | confirmed against the code |

## Summary
`process_icmpv4` answers echo requests sent to the limited or subnet broadcast, from the interface's unicast address. This is intentional and covered by `test_icmpv4_echo_reply_to_broadcast`. Multicast echo requests are not answered. RFC 1122 makes discarding these a MAY, so this is not a violation. Linux defaults to ignoring them (`icmp_echo_ignore_broadcasts=1`).

## Details
src/stack.rs:1585:
```rust
let dst_is_broadcast = iface.is_broadcast_v4(dst_addr);
if dst_addr.x_is_unicast() && !dst_is_broadcast {
    dst_addr
} else if dst_is_broadcast {
    match iface.ipv4_addr() {
        Some(addr) => addr,
        None => return,
    }
} else {
    return;
}
```
Amplification is weak. Each host sends one reply of the request's size. Routers do not forward directed broadcasts by default, so the attacker must be on-link, where it could flood the victim directly.

## Failure scenario
An on-link attacker sends an echo request to the subnet broadcast with the victim's source address. Every xarxa host on the segment replies to the victim.

## RFC reference
RFC 1122 §3.2.2.6: "An ICMP Echo Request destined to an IP broadcast or IP multicast address MAY be silently discarded."

## Suggested fix
Optionally stop answering broadcast echo requests by default, or make it configurable.
