# 023. SERVFAIL/REFUSED/FORMERR from the first server fails the whole query instead of trying the next server

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/dns.rs:507](../src/dns.rs#L507), [src/dns.rs:415](../src/dns.rs#L415), [src/dns.rs:554](../src/dns.rs#L554) |
| Features | default (`dns`) |
| Verification | reproduced with a test |

## Summary

Only NXDOMAIN gets its own handling. Any other non-zero RCODE falls through to answer parsing, finds no addresses, and sets the query to `Failure`. The other configured servers are never asked. A broken server that answers fast with an error fails every lookup, more reliably than a dead one would.

## Details

src/dns.rs:507-511:

```rust
                    q.set_state(if addresses.is_empty() {
                        State::Failure
                    } else {
                        State::Completed(CompletedQuery { addresses })
                    });
```

A SERVFAIL, REFUSED, NOTIMP or FORMERR response that echoes the question passes the question checks. With ANCOUNT=0, `addresses` stays empty and the query fails. `server_idx` only advances in `dispatch` when the per-server timeout expires (src/dns.rs:554-563), so no other server gets a chance.

The NXDOMAIN branch at src/dns.rs:415-419 runs before the question type and name checks. So a spoofed NXDOMAIN with a matching txid fails the query without echoing the question (see also 022).

## Failure scenario

Servers are [192.168.1.2, 192.168.1.3]. The first answers SERVFAIL because of a temporary upstream or DNSSEC validation failure, or REFUSED because it is misconfigured. The second would answer fine. Every lookup fails at once with `Err(Failed)`, and only one packet is ever sent.

## RFC reference

Neither text is a MUST. This is a robustness and interop issue.

RFC 1034 §5.3.3:

> 3. Send them queries until one returns a response.

> d. if the response shows a servers failure or other bizarre contents, delete the server from the SLIST and go back to step 3.

RFC 1035 §7.3:

> A name server will occasionally not have a current copy of a zone which it should have according to some NS RRs.  The resolver should simply remove the name server from the current SLIST, and continue.

## Reproduction

Test in `src/stack.rs` `mod test`, scratch copy of the crate, using the `vdns_sent`/`vdns_response` helpers from 022:

```rust
#[test]
#[cfg(all(feature = "dns", feature = "medium-ip", feature = "ipv4"))]
fn v_dns_servfail_does_not_try_next_server() {
    use crate::dns::{DnsClient, GetQueryResultError};
    use crate::wire::dns::Type;
    const OTHER_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 3);
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4), IpAddr::V4(OTHER_V4)]).unwrap();
    let q = dns.start_query(&mut stack, "example.com", Type::A).unwrap();
    stack.poll(Instant::ZERO);
    let _ = dns.poll(&mut stack);
    let (sport, txid) = vdns_sent(&tx.borrow()[0]);
    let resp = vdns_response(txid, 2, &["example", "com"], None);
    let udp = udp_datagram(REMOTE_V4.into(), 53, OUR_V4.into(), sport, &resp);
    inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &udp));
    let _ = dns.poll(&mut stack);
    let n = tx.borrow().len();
    let r = dns.get_query_result(q);
    assert_eq!(r, Err(GetQueryResultError::Failed));
    assert_eq!(n, 1);
}
```

Output:

```
servfail result Err(Failed), frames sent 1
test ok
```

## Suggested fix

For any RCODE other than NoError and NXDomain, move to the next server right away: bump `server_idx` and reset `retransmit_at`, `delay` and `timeout_at`. Fail only when no servers are left.
