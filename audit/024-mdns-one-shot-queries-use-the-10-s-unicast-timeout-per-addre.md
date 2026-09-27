# 024. mDNS one-shot queries use the 10 s unicast timeout per address family, IPv6 first

| | |
|---|---|
| Severity | medium |
| Category | performance |
| Location | [src/dns.rs:536](../src/dns.rs#L536), [src/dns.rs:35](../src/dns.rs#L35), [src/dns.rs:617](../src/dns.rs#L617) |
| Features | `mdns`, `ipv4`, `ipv6` (default) |
| Verification | reproduced with a test |

## Summary

With both IP versions compiled in, the mDNS "server list" is `[ff02::fb, 224.0.0.251]`. It is handled like unicast DNS, with a 10 s `RETRANSMIT_TIMEOUT` per entry. An IPv4-only responder is only asked after 10 s, and a name nobody owns takes 20 s to fail. On an interface with no IPv6 address it is worse: the query fails at once and IPv4 is never tried (the mechanism is in 025). That is why this is medium and not low.

## Details

src/dns.rs:535-541:

```rust
                    MulticastDns::Enabled => &[
                        #[cfg(feature = "ipv6")]
                        MDNS_IPV6_ADDR,
                        #[cfg(feature = "ipv4")]
                        MDNS_IPV4_ADDR,
                    ],
```

src/dns.rs:35:

```rust
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(10_000); // Should generally be 2-10 secs
```

The query goes to ff02::fb at t=0, 1, 3 and 7 s. At 10 s it moves to 224.0.0.251 (10, 11, 13, 17 s), and fails at 20 s. Many embedded mDNS responders listen on IPv4 only. The `mdns` docs do not say that IPv6 is tried first.

IPv4-only interface: `get_source_address_ipv6` returns `Ipv6Addr::LOCALHOST` when the interface has no IPv6 address (src/iface/mod.rs:1066). `send_slice` then rejects `::1` as not ours (src/udp.rs:895) with `Unaddressable`. `dispatch` treats that as permanent (src/dns.rs:617-623) and fails the query with nothing sent.

## Failure scenario

- `start_query("esp32.local", A)` against an IPv4-only responder answers after about 10 s.
- A typo in a `.local` name makes the caller wait 20 s for `Failed`.
- On an IP-medium interface with only an IPv4 address, default features, every `.local` lookup returns `Failed` at once with 0 packets sent.

## RFC reference

RFC 6762 §5.1 (non-normative):

> the query is instead sent to 224.0.0.251:5353 (or its IPv6 equivalent [FF02::FB]:5353). Typically, the timeout would also be shortened to two or three seconds.

## Reproduction

Test in `src/stack.rs` `mod test`, scratch copy of the crate. `vdns_sent` here returns the destinations of the frames sent since the last call.

```rust
#[test]
#[cfg(all(feature = "mdns", feature = "medium-ip", feature = "ipv4", feature = "ipv6"))]
fn vdns_mdns_timing_and_v4only() {
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let mut dns = DnsClient::new(&mut stack, &[]).unwrap();
    let q = dns.start_query(&mut stack, "esp.local", Type::A).unwrap();
    let mut now = Instant::ZERO; let mut log = Vec::new();
    while now <= Instant::from_secs(25) {
        let deadline = stack.poll(now).min(dns.poll(&mut stack));
        for s in vdns_sent(&tx) { log.push((now, s.0)); }
        if !matches!(dns.get_query_result(q), Err(GetQueryResultError::Pending)) { println!("done at {:?}", now); break; }
        now = deadline;
    }
    println!("dual timing: {:?}", log);
    let (mut stack, _rx, tx) = test_stack(Medium::Ip);
    let h = stack.ifaces().next().map(|(h, _)| h).unwrap();
    stack.iface(h).set_ip_addrs([IpCidr::new(OUR_V4.into(), 24)]).unwrap();
    let mut dns = DnsClient::new(&mut stack, &[]).unwrap();
    let q = dns.start_query(&mut stack, "esp.local", Type::A).unwrap();
    let _ = stack.poll(Instant::ZERO); let _ = dns.poll(&mut stack);
    println!("v4only sent: {:?}", vdns_sent(&tx));
    println!("v4only result: {:?}", dns.get_query_result(q));
}
```

Output:

```
done at Instant { millis: 20000 }
dual timing: [(0, ff02::fb), (1000, ff02::fb), (3000, ff02::fb), (7000, ff02::fb), (10000, 224.0.0.251), (11000, 224.0.0.251), (13000, 224.0.0.251), (17000, 224.0.0.251)]
v4only sent: []
v4only result: Err(Failed)
```

## Suggested fix

- Send mDNS queries to both groups at once, or give each family a short timeout of about 2-3 s.
- Use a shorter overall timeout for mDNS.
- Skip a family with no source address instead of failing (see 025).
