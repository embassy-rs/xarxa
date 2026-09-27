# 247. Neighbor Solicitation source address is chosen from the target, not from the packet that prompted it

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2559](../src/stack.rs#L2559) |
| Features | ipv6 |
| Verification | confirmed against the RFC text |

## Summary
`transmit_ndisc_solicit` selects its source address toward the target. It never sees the parked packet, because `lookup_hardware_addr` and the retransmit path in `poll_neighbor_timers` don't have it. RFC 4861 says the prompting packet's source SHOULD be used. The cost is an extra NS/NA round trip for the peer.

## Details
src/stack.rs:2559:
```rust
let src_addr = iface.get_source_address_ipv6(&target_addr, self.now);
```
The two differ when a socket is bound to, or sends from, an address that selection would not pick.

## Failure scenario
A UDP socket bound to fe80::1 sends to on-link 2001:db8::7. The NS goes out from 2001:db8::1, so the peer caches 2001:db8::1. Its reply to fe80::1 first needs its own NS/NA exchange.

## RFC reference
RFC 4861 §7.2.2: "If the source address of the packet prompting the solicitation is the same as one of the addresses assigned to the outgoing interface, that address SHOULD be placed in the IP Source Address of the outgoing solicitation. Otherwise, any one of the addresses assigned to the interface should be used."

## Suggested fix
Pass the parked packet's source address (from its IP header) into `solicit_neighbor` on the first solicitation, and keep it in the Incomplete entry for retransmissions.
