# 022. `DnsClient` accepts any packet from source port 5353, from any address and for every query

| | |
|---|---|
| Severity | medium |
| Category | security |
| Location | [src/dns.rs:363](../src/dns.rs#L363), [src/dns.rs:408](../src/dns.rs#L408), [src/dns.rs:415](../src/dns.rs#L415) |
| Features | `dns` (the port 5353 hole exists without `mdns` too) |
| Verification | reproduced with a test |

## Summary

`accepts()` returns true for any remote whose port is 5353, whatever its address and whatever kind of query is pending. For mDNS this breaks the RFC 6762 §11 MUST to accept only on-link responses. For unicast DNS it means a spoofer never has to fake the configured server's address, so BCP 38 ingress filtering or a firewall rule on the resolver's address no longer helps. The attacker still has to guess the 16-bit txid and the client's port, which is fixed for the client's lifetime (DESIGN §7).

## Details

src/dns.rs:363-365:

```rust
    fn accepts(&self, remote: SocketAddr) -> bool {
        (remote.port == DNS_PORT && self.servers.contains(&remote.addr)) || (remote.port == MDNS_DNS_PORT)
    }
```

After that, `process()` matches a response to a query only by txid (src/dns.rs:410), then question type and name. Nothing checks:
- whether the matched query is an mDNS query (`pq.mdns` is never read in `process`),
- whether the source is on a local subnet or link-local,
- the arrival interface.

The client socket is bound to an ephemeral port and is not a member of the mDNS group, so every response it gets has a unicast destination. RFC 6762 §11 requires the on-link source check for exactly that case.

The NXDOMAIN branch widens this. It runs before the question check, so a blind spoofer only needs the txid and port to fail a lookup, without knowing the name.

src/dns.rs:415-419:

```rust
                    if p.rcode() == Rcode::NXDomain {
                        trace!("rcode NXDomain");
                        q.set_state(State::Failure);
                        continue;
                    }
```

## Failure scenario

1. The device starts a unicast query for `example.com` to 192.168.1.2:53.
2. An attacker at 203.0.113.9, off-link and not a configured server, sends responses from its real address, source port 5353, to the client's port, cycling through txids.
3. The response with the matching txid completes the query with the attacker's addresses (`Ok([6.6.6.6])`), or fails it with NXDOMAIN.

The same works for an mDNS query (`printer.local` sent to ff02::fb): an off-link IPv4 unicast answer from 203.0.113.9:5353 is accepted.

## RFC reference

RFC 6762 §11:

> A host sending Multicast DNS queries to a link-local destination address (including the 224.0.0.251 and FF02::FB link-local multicast addresses) MUST only accept responses to that query that originate from the local link, and silently discard any other response packets.

> For responses received with a unicast destination address in the IP header, the source IP address in the packet is checked to see if it is an address on a local subnet.

## Reproduction

Tests in `src/stack.rs` `mod test`, scratch copy of the crate. `vdns_sent` reads the source port and txid from a sent frame. `vdns_response` builds a response with the given txid, rcode, question, and an optional A answer.

```rust
#[test]
fn v_dns_accepts_offlink_5353_for_unicast_query() {
    let (mut stack, rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
    let q = dns.start_query(&mut stack, "example.com", Type::A).unwrap();
    stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
    let (sport, txid) = vdns_sent(&tx.borrow()[0]);
    let attacker = Ipv4Addr::new(203, 0, 113, 9);
    let resp = vdns_response(txid, 0, &["example", "com"], Some([6, 6, 6, 6]));
    let udp = udp_datagram(attacker.into(), 5353, OUR_V4.into(), sport, &resp);
    inject(&mut stack, &rx, ipv4_packet(attacker, OUR_V4, IpProtocol::Udp, &udp));
    let _ = dns.poll(&mut stack);
    assert_eq!(dns.get_query_result(q).unwrap().as_slice(), &[IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6))]);
}
```

A second test, `v_mdns_accepts_offlink_unicast_answer`, does the same with `DnsClient::new(&mut stack, &[])` and `start_query("printer.local")`. The query goes out over IPv6 to ff02::fb, and the answer comes from 203.0.113.9:5353.

Output:

```
result Ok([V4(6.6.6.6)])
mdns result Ok([V4(6.6.6.6)])
```

Both tests pass.

## Suggested fix

- Accept port 5353 only for queries with `mdns` Enabled, and only from an on-link source: inside a prefix of the arrival interface, or IPv6 link-local.
- Accept port 53 only for non-mDNS queries. Better, match the source to the server the query was sent to.
- Do the question check before acting on NXDOMAIN.
