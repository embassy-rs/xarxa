# 180. Packets parked on neighbor resolution are sent with a SLAAC source address after it became invalid

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:467](../src/iface/slaac.rs#L467), [src/stack.rs:2404](../src/stack.rs#L2404), [src/stack.rs:143](../src/stack.rs#L143) |
| Features | default |
| Verification | confirmed against the code |

## Summary
When a SLAAC prefix's valid lifetime runs out, `sync_slaac_state` removes the address from `ip_addrs` but leaves the pending queue alone. A packet parked with that source goes out once the neighbor resolves, with a source that is no longer assigned. Manual removal and DHCP changes purge the pending queue. SLAAC expiry is the one path that doesn't.

## Details
src/iface/slaac.rs:461-467:
```rust
if !prefixinfo.is_valid(timestamp) {
    if let Some(i) = existing && self.ip_addrs[i].origin == AddrOrigin::Slaac {
        self.ip_addrs.remove(i);
    }
    continue;
}
```
Parked packets hold a fully built IP header. `flush_pending` (src/stack.rs:2404) pops them and calls `transmit_link` verbatim. The weak-host source check exists only at send time (UDP `prepare_datagram`, TCP dispatch). The window is short: resolution takes up to about 3 s.

## Failure scenario
SLAAC address S is in use. The app sends a UDP datagram to an unresolved on-link neighbor N and it parks. The prefix expires within the resolution window. N answers the NS and the datagram goes out with source S. The peer's reply is dropped by our ingress.

## RFC reference
RFC 4862 §5.5.4: "An address (and its association with an interface) becomes invalid when its valid lifetime expires.  An invalid address MUST NOT be used as a source address in outgoing communications and MUST NOT be recognized as a destination on a receiving interface."

## Suggested fix
When `sync_slaac_state` removes an address, drop the parked packets whose IP source is that address, and only those. The same selective purge would fit manual removal better than `purge_iface_link_state`.

A related point to check separately: the original report used an RA with valid lifetime 0 to remove the address at once. RFC 4862 §5.5.3 e) does not let an unauthenticated RA cut the remaining valid lifetime below 2 hours, and slaac.rs has no such handling.
