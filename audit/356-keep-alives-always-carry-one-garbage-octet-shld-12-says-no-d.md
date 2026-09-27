# 356. Keep-alives always carry one garbage octet, and the comment misstates RFC 1122

| | |
|---|---|
| Severity | info |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:2086](../src/tcp/mod.rs#L2086), [src/tcp/mod.rs:2076](../src/tcp/mod.rs#L2076) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
Keep-alives are sent with `payload: b"\x00"` at SND.NXT-1, and this is not configurable. RFC 9293 and RFC 1122 say a keep-alive SHOULD carry no data, with the garbage octet as a configurable MAY. The comment "(RFC 1122 says we should do this)" says the opposite. SHOULD deviation (SHLD-12). Peers ACK both forms.

## Details
src/tcp/mod.rs:2084-2087:
```rust
send(TcpRepr {
    seq_number: self.remote_last_seq - 1,
    payload: b"\x00",
    ..repr
})?;
```

## RFC reference
RFC 9293 §3.8.4: "An implementation SHOULD send a keep-alive segment with no data (SHLD-12); however, it MAY be configurable to send a keep-alive segment containing one garbage octet (MAY-6), for compatibility with erroneous TCP implementations." RFC 1122 §4.2.3.6 says the same.

## Suggested fix
Send an empty segment at SND.NXT-1 and fix the comment.
