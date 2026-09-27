# 118. .local detection is case-sensitive, so "host.LOCAL" goes to the unicast DNS servers

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/dns.rs:240](../src/dns.rs#L240), [src/dns.rs:638](../src/dns.rs#L638) |
| Features | `mdns` (default) |
| Verification | reproduced with a test |

## Summary
`start_query` uses mDNS only when the last label is exactly `b"local"`. `printer.LOCAL` or `printer.Local` go to the configured unicast servers, which RFC 6762 forbids, and leak the local name upstream. Related: `name_eq` compares names case-sensitively, so an answer whose name differs in case from the question is ignored.

## Details
src/dns.rs:240:
```rust
        if name.split(|&c| c == b'.').next_back().unwrap() == b"local" {
```
`name_eq` (src/dns.rs:638) compares label bytes exactly. DNS names compare case-insensitively (RFC 1035 §2.3.3).

## Failure scenario
A hostname `NAS.LOCAL` from a config UI is sent to 8.8.8.8 instead of over mDNS, and fails. Separately, a responder that answers `ESP32.local` to a query for `esp32.local` has its records skipped and the query times out.

## RFC reference
RFC 6762 §3: "Any DNS query for a name ending with ".local." MUST be sent to the mDNS IPv4 link-local multicast address 224.0.0.251 (or its IPv6 equivalent FF02::FB)."

RFC 1035 §2.3.3: comparisons "are done in a case-insensitive manner".

## Reproduction
Added to `mod test` in src/stack.rs in a scratch copy:
```rust
#[test]
#[cfg(all(feature = "mdns", feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
fn vdns_uppercase_local() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
    let q = dns.start_query(&mut stack, "printer.LOCAL", Type::A).unwrap();
    let _ = stack.poll(Instant::ZERO);
    let _ = dns.poll(&mut stack);
    println!("UPPER sent: {:?}", /* dst addr/port of frames in tx */);
    let q2 = dns.start_query(&mut stack, "printer.local", Type::A).unwrap();
    let _ = dns.poll(&mut stack);
    println!("lower sent: {:?}", /* ... */);
}
```
`cargo test --lib vdns_ -- --nocapture`:
```text
UPPER sent: [(V4(192.168.1.2), 53)]
lower sent: [(V6(ff02::fb), 5353)]
```

## Suggested fix
Use `eq_ignore_ascii_case(b"local")`. Compare labels with `eq_ignore_ascii_case` in `name_eq`.
