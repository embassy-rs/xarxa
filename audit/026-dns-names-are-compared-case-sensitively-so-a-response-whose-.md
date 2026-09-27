# 026. DNS names are compared case-sensitively, so an answer whose name differs only in case fails the query

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/dns.rs:642](../src/dns.rs#L642), [src/dns.rs:435](../src/dns.rs#L435), [src/dns.rs:459](../src/dns.rs#L459), [src/dns.rs:240](../src/dns.rs#L240) |
| Features | default (`dns`; `mdns` for the `.local` check) |
| Verification | reproduced with a test |

## Summary

`name_eq` compares labels byte for byte. An answer record whose owner name differs from the queried (or CNAME target) name only in ASCII case is skipped. If no other record matches, the query ends as `Failed` although the response holds the address. A question name that differs in case makes the response be ignored, and the query times out. The `.local` suffix check is case-sensitive too.

## Details

src/dns.rs:642, in `name_eq`:

```rust
Some((&len, rest)) if len as usize == label.len() && rest.get(..label.len()) == Some(label) => {
```

`name_eq` is used for the question check and for every answer record.

src/dns.rs:435-440, question mismatch leaves the query pending:

```rust
match name_eq(&p, question.name, &pq.name) {
    Ok(true) => {}
    Ok(false) => {
        trace!("question name mismatch");
        break;
    }
```

src/dns.rs:459-463, answer mismatch skips the record:

```rust
match name_eq(&p, r.name, &pq.name) {
    Ok(true) => {}
    Ok(false) => {
        trace!("answer name mismatch: {:?}", r);
        continue;
    }
```

With no address collected, src/dns.rs:507-511 sets `State::Failure`.

src/dns.rs:240, `.local` detection:

```rust
if name.split(|&c| c == b'.').next_back().unwrap() == b"local" {
```

So `host.LOCAL` goes to unicast DNS instead of mDNS.

In plain unicast DNS this is often hidden. Most servers compress the answer owner name as a pointer to the question, which carries the query's case. It shows with uncompressed or differently cased owner names: mDNS legacy-unicast answers that use the responder's registered name, and mixed-case CNAME chains.

## Failure scenario

- `start_query("dario-macbook.local", A)` against a responder registered as `Dario-MacBook.local`. The legacy unicast response carries `Dario-MacBook.local A 192.168.1.20`. The record is skipped and `get_query_result` returns `GetQueryResultError::Failed`.
- Query `www.example.com`. The response has `www.example.com CNAME Web.Example.COM` and `web.example.com A 5.6.7.8`. The A record fails `name_eq` against the copied CNAME target. Result: `Failed`.

## RFC reference

RFC 1035 §2.3.3:

> For all parts of the DNS that are part of the official protocol, all comparisons between character strings (e.g., labels, domain names, etc.) are done in a case-insensitive manner.

> Name servers and resolvers must compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII with zero parity.

## Reproduction

Added to `src/stack.rs` `mod test` in a scratch copy of HEAD:

```rust
fn vdns_run(qname: &str, answers: &[u8], ancount: u16) -> Result<Vec<IpAddr>, GetQueryResultError> {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
    let query = dns.start_query(&mut stack, qname, Type::A).unwrap();
    let _ = stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
    let sent = tx.borrow_mut().remove(0);
    let src_port = u16::from_be_bytes([sent[20], sent[21]]);
    let mut dnsmsg = sent[28..].to_vec();
    dnsmsg[2] = 0x81; dnsmsg[3] = 0x80;
    dnsmsg[6..8].copy_from_slice(&ancount.to_be_bytes());
    dnsmsg.extend_from_slice(answers);
    let datagram = udp_datagram(REMOTE_V4.into(), 53, OUR_V4.into(), src_port, &dnsmsg);
    inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &datagram));
    let _ = dns.poll(&mut stack);
    dns.get_query_result(query).map(|v| v.iter().copied().collect())
}
// vname() encodes an uncompressed name, vrr_a() an A RR with TTL 60.
#[test] fn v_dns_case() {
    vdns_run("example.com", &vrr_a("example.com", [1,2,3,4]), 1);   // Ok
    vdns_run("example.com", &vrr_a("Example.com", [1,2,3,4]), 1);   // Failed
    // www.example.com CNAME Web.Example.COM ; web.example.com A 5.6.7.8  -> Failed
    vdns_run("EXAMPLE.com", &vrr_a("example.com", [1,2,3,4]), 1);   // Failed
}
```

`cargo test --lib v_dns_case -- --nocapture`:

```
same case: Ok([V4(1.2.3.4)])
answer case differs: Err(Failed)
cname case differs: Err(Failed)
query upper, answer lower: Err(Failed)
```

## Suggested fix

Compare labels with `eq_ignore_ascii_case` in `name_eq`. Use `eq_ignore_ascii_case(b"local")` for the mDNS suffix check.
