# 323. Uncompressed IPv6 dispatch (0x41) is dropped, and the gap is not documented

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/wire/sixlowpan/mod.rs:44](../src/wire/sixlowpan/mod.rs#L44) |
| Features | default (`medium-ieee802154`) |
| Verification | confirmed against the code |

## Summary
`SixlowpanPacket::dispatch` accepts only FRAG1/FRAGN and IPHC. A frame with the RFC 4944 IPv6 dispatch (`01 000001`, uncompressed header) returns `Malformed` and `process_sixlowpan` drops it. The same holds inside a FRAG1. Mesh (`10xxxxxx`) and BC0 frames are dropped too, but those are optional, mesh-network-only features. README lists neither the features nor the gap.

## Details
src/wire/sixlowpan/mod.rs:44-58:
```rust
if raw[0] >> 3 == DISPATCH_FIRST_FRAGMENT_HEADER || raw[0] >> 3 == DISPATCH_FRAGMENT_HEADER {
    Ok(Self::FragmentHeader)
} else if raw[0] >> 5 == DISPATCH_IPHC_HEADER {
    Ok(Self::IphcHeader)
} else {
    Err(Malformed)
}
```

## Failure scenario
A peer or injector tool sends dispatch 0x41 followed by a plain IPv6 header. xarxa drops every such frame silently.

## RFC reference
RFC 4944 §5.1 Figure 2:
> 01  000001 | IPv6       - Uncompressed IPv6 Addresses

> IPv6: Specifies that the following header is an uncompressed IPv6 header [RFC2460].

RFC 4944 §11 (mesh): "The functionality in this section MUST only be used in a mesh-enabled" network.

## Suggested fix
Handle 0x41 by stripping the dispatch byte and passing the rest to `process_ipv6`, both for whole frames and FRAG1 payloads. Otherwise list it in README "Not yet implemented".
