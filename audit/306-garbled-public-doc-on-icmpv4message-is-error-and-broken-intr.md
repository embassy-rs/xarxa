# 306. Garbled doc on Icmpv4Message::is_error, broken link in Icmpv4Packet::check_len

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/icmpv4.rs:38](../src/wire/icmpv4.rs#L38), [src/wire/icmpv4.rs:166](../src/wire/icmpv4.rs#L166), [src/wire/icmpv4.rs:202](../src/wire/icmpv4.rs#L202) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`is_error` says "Malformed messages must never be sent in response to another error message". It should say error messages. `check_len` links to a nonexistent `set_header_len`. The echo accessors document panics that cannot happen after `check_len`.

## Details
src/wire/icmpv4.rs:37-39:
```rust
/// RFC 1122 §3.2.2 lists the error message types. Everything else is a query or
/// informational message. Malformed messages must never be sent in response to
/// another error message.
```
src/wire/icmpv4.rs:166 and 171 reference `[set_header_len]: #method.set_header_len`. No such method exists. `check_len` only checks `len >= 8`.

The echo ident/seq getters and setters (lines 202, 211, 267, 276) say they "may panic if this packet is not an echo request or reply packet". Bytes 4..8 always exist after `check_len`, whatever the type. They can only panic on a short buffer from `new_unchecked`.

## Suggested fix
Say "Error messages". Remove the `set_header_len` sentence and link. Reword the Panics sections to the short-buffer case.
