# 348. Coverage note: ICMP redirects are ignored, NDISC and RA guards are mostly correct

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/stack.rs:1884](../src/stack.rs#L1884), [src/icmp_error.rs:39](../src/icmp_error.rs#L39) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Not a defect. Recorded as coverage.
- `IcmpError::from_icmpv4` maps Redirect to `None` (src/icmp_error.rs:39), and `process_icmpv6` has no Redirect arm. Redirects cannot change routing.
- NS and NA require hop limit 255 and a link-layer source (src/stack.rs:1884-1893).
- RA requires hop limit 255, a link-layer source, a link-local source and an all-nodes or link-local destination (src/stack.rs:1904-1910).

Two gaps found elsewhere:
- RA validation does not check ICMP Code == 0 (rfc-ipv6-host-checklist-8).
- MLD queries skip the Router Alert check (multicast-11).

## RFC reference
RFC 4861 §6.1.2: "ICMP Code is 0."
