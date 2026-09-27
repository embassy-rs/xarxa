# 224. Raw Ethernet sockets get copies, not moves, of ethertypes the build cannot process

| | |
|---|---|
| Severity | low |
| Category | feature-gating |
| Location | [src/stack.rs:1264](../src/stack.rs#L1264), [src/raw.rs:651](../src/raw.rs#L651) |
| Features | `raw-ethernet` with only one of `ipv4`/`ipv6` |
| Verification | confirmed against the code |

## Summary
`stack_wants` always includes ARP, IPv4 and IPv6, with no cfg. In an ipv4-only build IPv6 frames are still copied to a matching raw socket, and the original is then dropped. The same holds for ARP and IPv4 in an ipv6-only build. The copy costs a second pool buffer, and with an empty pool the socket misses a frame nothing else wanted.

## Details
src/stack.rs:1264:
```rust
let stack_wants = matches!(
    ethertype,
    EthernetProtocol::Arp | EthernetProtocol::Ipv4 | EthernetProtocol::Ipv6
);
```
src/raw.rs:651 copies when `stack_wants` is set and returns the original. The match at src/stack.rs:1274-1283 gates Arp/Ipv4 on `ipv4` and Ipv6 on `ipv6`, so in a reduced build the original falls to `_ => {}`. DESIGN §7 says anything the stack does not process moves into the socket zero-copy.

## Failure scenario
Build with `medium-ethernet,ipv4,raw-ethernet`. A raw socket is bound to ethertype 0x86DD. Each IPv6 frame is copied into a fresh buffer and the original dropped. Under pool pressure the copy fails and the frame is lost.

## Suggested fix
Gate each ethertype in `stack_wants` the same way as the match arms.
