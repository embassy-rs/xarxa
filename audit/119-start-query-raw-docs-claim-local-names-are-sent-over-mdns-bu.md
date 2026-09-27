# 119. start_query_raw docs say .local names use mDNS, but the caller's `mdns` argument decides, and the name is not validated

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/dns.rs:271](../src/dns.rs#L271), [src/dns.rs:281](../src/dns.rs#L281) |
| Features | `dns`, `mdns` |
| Verification | confirmed against the code |

## Summary
The doc says "With the `mdns` feature, names ending in `.local` are sent with multicast DNS." `start_query_raw` never looks at the name and stores the caller's `mdns` argument as is. It also does no wire-format validation, so `InvalidName` is never returned and a malformed name is sent verbatim, never matches a reply, and only fails by timeout.

## Details
src/dns.rs:271:
```rust
    /// With the `mdns` feature, names ending in `.local` are sent with multicast DNS.
```
src/dns.rs:281, the only check is length:
```rust
        let name = Vec::from_slice(raw_name).map_err(|_| StartQueryError::NameTooLong)?;
```
The `.local` detection exists only in `start_query` (src/dns.rs:240).

## Failure scenario
`start_query_raw(b"\x07printer\x05local\x00", Type::A, MulticastDns::Disabled)` goes to the unicast servers. A name with no terminating zero is sent as a malformed query and times out on every server.

## Suggested fix
Say in the doc that the `mdns` argument decides. Validate the name (labels 1..=63 bytes, zero terminator at the end, no compression pointers) and return `InvalidName`.
