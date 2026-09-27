# 123. NXDOMAIN response kills a query before the question section is checked; mDNS queries accept NXDOMAIN too

| | |
|---|---|
| Severity | low |
| Category | security |
| Location | [src/dns.rs:415](../src/dns.rs#L415) |
| Features | default (`dns`), `mdns` for the mDNS part |
| Verification | reproduced with a test |

## Summary
A response with a matching txid and RCODE=3 sets the query to `Failure` before its question name and type are checked. Any packet that passes `accepts()` with the right txid can fail a lookup, including a response for another name or a spoof from source port 5353. mDNS queries take the same path, although RFC 6762 says non-zero RCODEs must be ignored.

## Details
src/dns.rs:415-419:
```rust
if p.rcode() == Rcode::NXDomain {
    trace!("rcode NXDomain");
    q.set_state(State::Failure);
    continue;
}
```
`Question::parse` and the type/name checks come after, at line 421. The `continue` also fails any other pending query with the same txid.

## Failure scenario
An off-path attacker sprays NXDOMAIN responses with arbitrary questions from source port 5353 to the client port. Any lookup whose txid matches fails with `Failed`. mDNS responders never send NXDOMAIN, so for an mDNS query such a reply is always bogus.

## RFC reference
RFC 1035 §7.3: "The recommended strategy is to do a preliminary matching using the ID field in the domain header, and then to verify that the question section corresponds to the information currently desired."

RFC 6762 §18.11: "Multicast DNS messages received with non-zero Response Codes MUST be silently ignored."

## Reproduction
Scratch test in `mod test` of src/stack.rs:
```rust
let (mut stack, rx, tx) = test_stack(Medium::Ip);
let mut dns = DnsClient::new(&mut stack, &[IpAddr::V4(REMOTE_V4)]).unwrap();
let port = stack.udp_socket(dns.socket()).local_addr().port;
let q = dns.start_query(&mut stack, "example.com", Type::A).unwrap();
let _ = stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
let txid = /* from sent query */;
let resp = vdns_resp(txid, 3, b"\x05other\x03org\x00\x00\x1c\x00\x01", &[]); // flags 0x81 0x83
let udp = udp_datagram(REMOTE_V4.into(), 53, OUR_V4.into(), port, &resp);
inject(&mut stack, &rx, ipv4_packet(REMOTE_V4, OUR_V4, IpProtocol::Udp, &udp));
let _ = dns.poll(&mut stack);
println!("NXDOMAIN mismatched question result: {:?}", dns.get_query_result(q));
```
Output:
```
NXDOMAIN mismatched question result: Err(Failed)
```

## Suggested fix
Check the NXDOMAIN rcode only after the question name and type match. For mDNS queries, ignore responses with a non-zero RCODE.
