# 312. IpAddr::prefix_len doc says it counts leading zeroes, it counts leading ones

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ip.rs:167](../src/wire/ip.rs#L167), [src/wire/ipv4.rs:48](../src/wire/ipv4.rs#L48), [src/wire/ipv6.rs:127](../src/wire/ipv6.rs#L127) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The public doc of `IpAddr::prefix_len` says the result is "the number of leading zeroes". Both implementations count the leading one bits of a contiguous mask. `255.255.255.0` returns `Some(24)`.

## Details
src/wire/ip.rs:166-167:
```rust
/// If `self` is a CIDR-compatible subnet mask, return `Some(prefix_len)`,
/// where `prefix_len` is the number of leading zeroes. Return `None` otherwise.
```
The implementations (ipv4.rs:75-97, ipv6.rs:198-220) increment `prefix_len` per 1 bit until the first 0, and return `None` if a 1 follows. The private trait docs at ipv4.rs:48 and ipv6.rs:127 carry the same sentence.

Duplicate of the first bullet of x-docs-sockets-25.

## Suggested fix
Say "the number of leading one bits".
