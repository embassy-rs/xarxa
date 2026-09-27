# 350. IPv6 flow label is always zero

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/stack.rs:2832](../src/stack.rs#L2832) |
| Features | `ipv6` |
| Verification | confirmed against the RFC text |

## Summary
`push_ipv6_header` always writes flow label 0. RFC 6437 allows this. Labelling flows is only RECOMMENDED, and only helps flow-label-based ECMP and load balancing. Not a violation.

## Details
src/stack.rs:2832:
```rust
packet.set_flow_label(0);
```

## RFC reference
RFC 6437 §3: "It is therefore RECOMMENDED that source hosts support the flow label by setting the flow label field for all packets of a given flow to the same value chosen from an approximation to a discrete uniform distribution." ... "A source node that does not otherwise set the flow label MUST set its value to zero."

## Suggested fix
Optionally set a 20-bit hash of the 5-tuple and a per-stack random key for TCP and UDP.
