# 116. DNS retransmits to one server every 1 s for 10 s before trying the next, and ignores ICMP port unreachable

| | |
|---|---|
| Severity | low |
| Category | performance |
| Location | [src/dns.rs:33](../src/dns.rs#L33), [src/dns.rs:372](../src/dns.rs#L372) |
| Features | default (`dns`) |
| Verification | confirmed against the code |

## Summary
With a dead first server, every lookup waits 10 s before the second server is asked. The dead server gets 4 queries, the first retransmit after 1 s. An ICMP port unreachable for the query is dropped instead of causing failover. Ignoring ICMP is a commented choice, and the RFC text is a recommendation.

## Details
src/dns.rs:33-35:
```rust
const RETRANSMIT_DELAY: Duration = Duration::from_millis(1_000);
const MAX_RETRANSMIT_DELAY: Duration = Duration::from_millis(10_000);
const RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(10_000); // Should generally be 2-10 secs
```
Sends go to server 0 at 0, 1, 3 and 7 s, then server 1 at 10 s. `test_dns_query_timeout` in src/stack.rs asserts this schedule.

src/dns.rs:372-373:
```rust
                // ICMP errors about our queries: the retransmit timer deals with those.
                Err(_) => continue,
```

## Failure scenario
The primary resolver host is up but its DNS daemon crashed, so it answers with port unreachable. Every lookup takes over 10 s and sends 4 queries to that host.

## RFC reference
RFC 1035 §4.2.1, in a list of recommendations: "The client should try other servers and server addresses before repeating a query to a specific address of a server." and "the minimum retransmission interval should be 2-5 seconds."

## Suggested fix
Move to the next server after the first retransmit interval, cycling through the list. Optionally fail over at once on an ICMP error from the current server's address.
