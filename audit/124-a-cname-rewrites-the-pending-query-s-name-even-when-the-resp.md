# 124. A CNAME rewrites the pending query's name even when the response is rejected; a failed copy leaves an unterminated name on the wire

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/dns.rs:496](../src/dns.rs#L496), [src/dns.rs:651](../src/dns.rs#L651) |
| Features | default (`dns`) |
| Verification | reproduced with a test |

## Summary
`copy_name` overwrites `pq.name` in place while the answer section is still being walked. If a later record is malformed (`break 'queries`), the query stays Pending with the CNAME target as its name, and retransmissions ask for that. If `copy_name` fails partway, `pq.name` is left without a terminator and every retransmission carries a malformed question.

## Details
src/dns.rs:496-498:
```rust
if copy_name(&mut pq.name, p.parse_name(name)).is_err() {
    ...
    break 'queries;
```
src/dns.rs:655-661:
```rust
dest.truncate(0);
for label in name {
    let label = label?;
    dest.push(label.len() as u8).map_err(|_| crate::error::Malformed)?;
    dest.extend_from_slice(label).map_err(|_| crate::error::Malformed)?;
}
```
An error returns with `dest` half-filled. Malformed records later in the answer section (lines 454, 467) also `break 'queries` and leave the query Pending with the rewritten name. An unterminated name never matches in `name_eq`, so the query can only end by timing out on every server.

## Failure scenario
A resolver returns one slightly malformed response: a CNAME chain with a bad trailing record. The client stops asking for the user's name, retransmits a different or malformed question to every server, and fails after 10 s per server.

## Reproduction
Scratch test in `mod test` of src/stack.rs:
```rust
let question = b"\x07example\x03com\x00\x00\x01\x00\x01";
let cname: &[u8] = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x0a\x04evil\x03org\x00";
let bad: &[u8] = b"\x04evil\x03org\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x03\x01\x02\x03";
// inject response(txid, rcode 0, question, [cname, bad]); dns.poll; stack.poll(1s); dns.poll
// then new query, CNAME rdata b"\x04evil\x09org\x00" (rdlen 9); dns.poll; stack.poll(2s); dns.poll
```
Output:
```
after cname+bad: Err(Pending)
retransmit payload: [04, 65, 76, 69, 6c, 03, 6f, 72, 67, 00, 00, 01, 00, 01]
after bad cname: Err(Pending)
retransmit payload2: [04, 65, 76, 69, 6c, 00, 01, 00, 01]
```

## Suggested fix
Follow CNAMEs in a local buffer and write `pq.name` only once the response is accepted. Or keep the original name for retransmissions and track the current target separately.
