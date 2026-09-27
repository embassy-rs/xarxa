# 210. Unicast 802.15.4 frames never request a MAC ACK

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/sixlowpan.rs:590](../src/sixlowpan.rs#L590), [src/sixlowpan.rs:846](../src/sixlowpan.rs#L846) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`dispatch_ieee802154` and `dispatch_ieee802154_frag` set `ack_request: false` on every frame, unicast included. Radios only retransmit frames with AR set. A fragmented datagram is lost if any one fragment is lost, and recovery falls to TCP's RTO.

## Details
src/sixlowpan.rs:590 and src/sixlowpan.rs:846
```rust
ack_request: false,
```
There is no knob. A driver would have to parse and rewrite the frame control field to get AR. Broadcast (0xffff) frames must not request ACKs, unicast ones can.

## Failure scenario
At 5% frame loss, a 1280-byte datagram split into 13 fragments is lost about 49% of the time (1 - 0.95^13).

## RFC reference
RFC 4944 §2: "In keeping with [RFC3819], it is recommended that IPv6 packets be carried in frames for which acknowledgements are requested so as to aid link-layer recovery."

This is lowercase and non-normative. It is a performance and interop issue, not an RFC violation.

## Suggested fix
Set `ack_request` when the destination is not broadcast, or make it configurable per interface.
