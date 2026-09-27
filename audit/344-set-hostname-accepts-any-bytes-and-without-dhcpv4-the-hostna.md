# 344. set_hostname checks only length, and the hostname feature does not imply dhcpv4

| | |
|---|---|
| Severity | info |
| Category | api |
| Location | [src/stack.rs:588](../src/stack.rs#L588), [src/stack.rs:132](../src/stack.rs#L132), [Cargo.toml:118](../Cargo.toml#L118) |
| Features | `hostname` (with or without `dhcpv4`) |
| Verification | confirmed against the code |

## Summary
`set_hostname` checks only that the name is at most 63 bytes. Spaces, dots, underscores, non-ASCII and NUL are accepted and sent verbatim in DHCP option 12. The `hostname` feature does not imply `dhcpv4`, but the docs say the name is sent to the DHCP server. Without `dhcpv4` the name is only readable back through `Stack::hostname()`. No RFC MUST is violated. This is hardening and documentation.

## Details
src/stack.rs:588:
```rust
pub fn set_hostname(&mut self, hostname: &str) -> Result<(), crate::error::HostnameTooLong> {
    if hostname.len() > HOSTNAME_MAX_LEN {
        return Err(crate::error::HostnameTooLong);
    }
```
The 63-byte cap is the single-label limit (RFC 1035 §2.3.4). Option 12 may carry a qualified name, so a valid FQDN over 63 bytes is refused while invalid labels are accepted.

The internal getter the DHCP client reads exists only with both features (src/stack.rs:132, `#[cfg(all(feature = "dhcpv4", feature = "hostname"))]`). Cargo.toml:118 is `hostname = []`.

## Failure scenario
The application calls `set_hostname("Living Room Sensor")`. A DHCP server doing DDNS rejects or rewrites the name, and the device never resolves by that name.

## RFC reference
RFC 2132 §3.14: "The name may or may not be qualified with the local domain name ... See RFC 1035 for character set restrictions."

## Suggested fix
Validate LDH labels (each 1..=63, total <= 255), or document that the name is sent verbatim. Make `hostname` imply `dhcpv4`, or document that without it the name is only stored.
