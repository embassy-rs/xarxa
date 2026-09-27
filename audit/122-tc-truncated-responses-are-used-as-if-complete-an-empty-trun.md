# 122. TC (truncated) responses are used as if complete; an empty truncated answer fails the query

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/dns.rs:507](../src/dns.rs#L507), [src/wire/dns.rs:53](../src/wire/dns.rs#L53) |
| Features | default (`dns`) |
| Verification | confirmed against the RFC text |

## Summary
`process()` never looks at `Flags::TRUNCATED`, which is defined but unused. A truncated response with partial answers completes the query with a partial address list. One with no usable answers sets `Failure` instead of trying the next server. There is no TCP fallback.

## Details
The header checks are only opcode, QR and qdcount. No EDNS0 is sent, so servers cap UDP responses at 512 bytes. src/dns.rs:507-511:
```rust
q.set_state(if addresses.is_empty() {
    State::Failure
} else {
    State::Completed(CompletedQuery { addresses })
});
```

## Failure scenario
A name with a long CNAME chain gives a response over 512 bytes. The server replies TC=1 with an empty answer section. `get_query_result` returns `Failed`, although a retry over TCP or elsewhere would resolve it.

## RFC reference
RFC 1035 §4.2.1 only defines the bit: "Longer messages are truncated and the TC bit is set in the header."

RFC 6762 §18.5 (legacy unicast responses to an ephemeral-port querier): "In legacy unicast response messages, the TC bit has the same meaning as in conventional Unicast DNS: it means that the response was too large to fit in a single packet, so the querier SHOULD reissue its query using TCP in order to receive the larger response."

## Suggested fix
Treat a TC response with no usable address as a server failure and move to the next server. Document that truncated answers may be partial.
