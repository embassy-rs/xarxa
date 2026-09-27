# 150. When only T2 is given and T2 <= lease/2, T1 equals T2, so RENEWING is skipped

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:440](../src/iface/dhcpv4.rs#L440), [src/iface/dhcpv4.rs:781](../src/iface/dhcpv4.rs#L781) |
| Features | default |
| Verification | confirmed against the code |

## Summary
If the server sends only T2, the client sets T1 = min(lease/2, T2). When T2 <= lease/2, T1 == T2. The first renewal attempt is already a broadcast rebind, and the client never unicasts to its server. The client picks T1 itself, so the RFC 2131 MUST binds it. Impact is small, since the broadcast still reaches the server.

## Details
src/iface/dhcpv4.rs:439-441:
```rust
(None, Some(rebind_duration)) if rebind_duration < lease_duration => {
    ((lease_duration / 2).min(rebind_duration), rebind_duration)
}
```
src/iface/dhcpv4.rs:781:
```rust
state.rebinding |= now >= state.rebind_at;
```
This is true on the first attempt, so the destination is `Ipv4Addr::BROADCAST`.

## Failure scenario
Server sends lease 3600 s and T2 1000 s without T1. The client never renews by unicast and always broadcasts at 1000 s.

## RFC reference
RFC 2131 §4.4.5: "T1 MUST be earlier than T2, which, in turn, MUST be earlier than the time at which the client's lease will expire."

## Suggested fix
When only T2 is given, pick T1 strictly below T2, for example min(lease/2, T2/2).
