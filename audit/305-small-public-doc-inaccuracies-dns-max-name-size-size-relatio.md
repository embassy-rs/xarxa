# 305. DNS public doc inaccuracies: DNS_MAX_NAME_SIZE, parse_name pointers, Record::parse errors

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/dns.rs:184](../src/wire/dns.rs#L184), [src/wire/dns.rs:409](../src/wire/dns.rs#L409), [src/config.rs:182](../src/config.rs#L182) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Three public doc comments do not match the code.

## Details
- `Packet::parse_name` (src/wire/dns.rs:184) says "Pointers are only allowed to point backwards". The first pointer is only checked against `packet.len() <= ptr`, so it may point forward. Later pointers must precede the previous target (`packet = &packet[..ptr]`). Loops are still impossible.
- `Record::parse` (src/wire/dns.rs:409) lists `Malformed` for "the buffer is too short, or the class is not IN". It also returns `Malformed` when A rdata is not 4 bytes or AAAA rdata is not 16 bytes (src/wire/dns.rs:375, 379). mDNS records with the cache-flush bit (class 0x8001) also fail the class check, which may surprise mDNS users.
- `DNS_MAX_NAME_SIZE` (src/config.rs:182) says a name "takes one byte more than its dotted form". The query builder strips a trailing dot, then writes a length byte per label and a 0x00 terminator. "rust-lang.org" (13 chars) is 15 bytes. The wire form is two bytes longer than a dotted name without a trailing dot.

## Failure scenario
A 254-character dotted name without a trailing dot encodes to 256 bytes and returns `NameTooLong`, while the doc suggests it fits. The real limit is 253 characters.

## Suggested fix
Reword the three comments. List the rdata-length error on `Record::parse`.
