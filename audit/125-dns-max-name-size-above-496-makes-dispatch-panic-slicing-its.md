# 125. DNS_MAX_NAME_SIZE above 496 makes dispatch panic slicing its 512-byte buffer

| | |
|---|---|
| Severity | low |
| Category | panic |
| Location | [src/dns.rs:590](../src/dns.rs#L590), [build.rs](../build.rs) |
| Features | default (`dns`), with `XARXA_DNS_MAX_NAME_SIZE` set above 496 |
| Verification | confirmed against the code |

## Summary
`dispatch` builds the query in a 512-byte array and slices it by the name length. The cargo features cap `DNS_MAX_NAME_SIZE` at 255, but build.rs accepts any `XARXA_DNS_MAX_NAME_SIZE` from the environment. A value above 496 plus a long enough name panics in `DnsClient::poll`.

## Details
src/dns.rs:589-590:
```rust
let mut payload = [0u8; 512];
let payload = &mut payload[..HEADER_LEN + question.buffer_len()];
```
`buffer_len()` is `name.len() + 4` and `HEADER_LEN` is 12. gen_config.py declares `max=255`, but build.rs does not enforce it for env values.

## Failure scenario
Build with `XARXA_DNS_MAX_NAME_SIZE=600` and call `start_query_raw` with a 550-byte name. The next `DnsClient::poll` panics.

## Suggested fix
Reject values above 255 in build.rs, or size the buffer from `DNS_MAX_NAME_SIZE`.
