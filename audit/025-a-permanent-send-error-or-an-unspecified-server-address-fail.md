# 025. A permanent send error or an unspecified server address fails the query without trying the next server

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/dns.rs:617](../src/dns.rs#L617), [src/dns.rs:572](../src/dns.rs#L572), [src/dns.rs:536](../src/dns.rs#L536) |
| Features | `dns`; `mdns` + `ipv4` + `ipv6` for the mDNS case (all default) |
| Verification | reproduced with a test |

## Summary

In `dispatch`, a permanent error from `send_slice` (`Unaddressable`, `InvalidState`, `BufferFull`, ...) and an unspecified server address both set the query to `Failure` right away. `server_idx` is not advanced, so the next server or address family is never tried. A mixed-family server list on a single-family network fails every lookup at once. mDNS over IPv6 never falls back to IPv4.

## Details

src/dns.rs:572-576:

```rust
                if servers[pq.server_idx].is_unspecified() {
                    trace!("invalid unspecified DNS server addr.");
                    q.set_state(State::Failure);
                    continue;
                }
```

src/dns.rs:611-624:

```rust
                match stack.udp_socket(self.socket).send_slice(payload, dst) {
                    Ok(()) => {}
                    Err(e @ (SendError::NoBuffer | SendError::DeviceBusy)) => {
                        // Transient errors: treat it as packet loss, the retransmit timer retries.
                        trace!("send to {} failed: {:?}. Will retry.", dst, e);
                    }
                    Err(e) => {
                        // Permanent errors: fail the query.
                        let _: SendError = e;
                        trace!("send to {} failed: {:?}. Query failed.", dst, e);
                        q.set_state(State::Failure);
                        continue;
                    }
                }
```

For mDNS, the list is `[MDNS_IPV6_ADDR, MDNS_IPV4_ADDR]` when both families are compiled in (src/dns.rs:535-541). With no IPv6 address on the interface, the send to ff02::fb returns `Unaddressable` and the query fails.

Scope:
- The mDNS case needs an interface with no IPv6 source: IP medium, or an address table with no room for the link-local. Ethernet interfaces have a link-local address. There the query waits the 10 s timeout on IPv6 before trying IPv4 instead (see 024).
- A single-server config also fails at once when the send hits `Unaddressable` because routing is not up yet, for example before DHCP installs a default route. The query does not retry. That may or may not be intended.

## Failure scenario

- `DnsClient::new(&mut stack, &[v6_dns, v4_dns])` on an IPv4-only network: every query returns `Failed` at once, 0 packets sent.
- Servers `[0.0.0.0, 192.168.1.2]`: same.
- `start_query("printer.local")` on a PPP/TUN (IP medium) interface with only IPv4, default features: `Failed` at once, although 224.0.0.251 would work. The same code built with only `ipv4` resolves the name.

## Reproduction

Tests in `src/stack.rs` `mod test`, scratch copy of the crate:

```rust
#[test]
#[cfg(all(feature = "dns", feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
fn v_dns_unaddressable_first_server_fails_query() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let v6 = Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 0x8888);
    let mut dns = DnsClient::new(&mut stack, &[IpAddr::V6(v6), IpAddr::V4(REMOTE_V4)]).unwrap();
    let q = dns.start_query(&mut stack, "example.com", Type::A).unwrap();
    stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
    assert_eq!(dns.get_query_result(q), Err(GetQueryResultError::Failed));
    assert_eq!(tx.borrow().len(), 0);
    let mut dns2 = DnsClient::new(&mut stack, &[IpAddr::V4(Ipv4Addr::new(0,0,0,0)), IpAddr::V4(REMOTE_V4)]).unwrap();
    let q2 = dns2.start_query(&mut stack, "example.com", Type::A).unwrap();
    stack.poll(Instant::ZERO); let _ = dns2.poll(&mut stack);
    assert_eq!(dns2.get_query_result(q2), Err(GetQueryResultError::Failed));
    assert_eq!(tx.borrow().len(), 0);
}

#[test]
#[cfg(all(feature = "dns", feature = "mdns", feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
fn v_mdns_no_v6_source_fails_without_v4_fallback() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let h = stack.ifaces().next().map(|(h, _)| h).unwrap();
    stack.iface(h).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    stack.poll(Instant::ZERO); tx.borrow_mut().clear();
    let mut dns = DnsClient::new(&mut stack, &[]).unwrap();
    let q = dns.start_query(&mut stack, "printer.local", Type::A).unwrap();
    stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
    assert_eq!(dns.get_query_result(q), Err(GetQueryResultError::Failed));
    assert_eq!(tx.borrow().len(), 0);
}
```

Output:

```
unaddressable result Err(Failed), frames 0
unspecified result Err(Failed), frames 0
mdns no-v6 result Err(Failed), frames 0
```

All tests pass.

## Suggested fix

On a permanent send error or an unspecified server address, advance `server_idx`, reset the per-server timers, and try the next server in the same pass (a loop). Set `Failure` only when every server is used up.
