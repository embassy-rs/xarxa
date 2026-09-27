# 289. Urgent data unsupported, although the code comment claims this is standards-compliant

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/repr.rs:95](../src/tcp/repr.rs#L95), [src/tcp/repr.rs:267](../src/tcp/repr.rs#L267) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
URG and the urgent pointer are ignored on receive, and emit always writes urgent pointer 0. There is no API to learn about or send urgent data. The code comment calls this standards-compliant, but RFC 9293 requires support (MUST-30, MUST-32, MUST-33). README.md and DESIGN.md don't list it as unimplemented.

## Details
src/tcp/repr.rs:95:
```rust
// The URG flag and the urgent field is ignored. This behavior is standards-compliant,
```
src/tcp/repr.rs:267:
```rust
packet.set_urgent_at(0);
```

## Failure scenario
A telnet or FTP peer sends urgent data for an interrupt (IAC DM). The application gets the bytes inline with no signal and can't find the synch point.

## RFC reference
RFC 9293 §3.8.5: "new applications SHOULD NOT employ the TCP urgent mechanism (SHLD-13). However, TCP implementations MUST still include support for the urgent mechanism (MUST-30)." And: "A TCP implementation MUST (MUST-32) inform the application layer asynchronously whenever it receives an urgent pointer ... The TCP implementation MUST (MUST-33) provide a way for the application to learn how much urgent data remains to be read".

## Suggested fix
Fix the comment and list urgent data under "Not yet implemented" in README.md. Optionally expose the urgent pointer.
