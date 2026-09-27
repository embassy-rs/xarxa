# 117. DnsClient::update_servers with pending queries: old server index carries over, and replies from removed servers are dropped

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/dns.rs:201](../src/dns.rs#L201), [src/dns.rs:565](../src/dns.rs#L565), [src/dns.rs:364](../src/dns.rs#L364) |
| Features | default (`dns`) |
| Verification | confirmed against the code |

## Summary
`update_servers` replaces the server list and leaves pending queries alone. Each keeps `server_idx`, `delay`, `retransmit_at` and `timeout_at`. A query whose index is past the end of the new list fails at the next poll without asking anyone. A query still in range continues against whatever server now sits at that index, with the old backoff and timeout. Replies from a server just removed are rejected. mDNS queries are not affected.

## Details
src/dns.rs:201-208 only overwrites `self.servers`. src/dns.rs:565 in `dispatch`:
```rust
                if pq.server_idx >= servers.len() {
```
marks the query `Failure`. src/dns.rs:364-366:
```rust
    fn accepts(&self, remote: SocketAddr) -> bool {
        (remote.port == DNS_PORT && self.servers.contains(&remote.addr)) || (remote.port == MDNS_DNS_PORT)
    }
```
The doc on `update_servers` says nothing about pending queries.

## Failure scenario
Two servers. A query timed out on the first and is at `server_idx` 1. A DHCP renewal changes the DNS servers and the app calls `update_servers` with one new server. The next `DnsClient::poll` fails the query and the new server is never asked.

## Suggested fix
In `update_servers`, restart pending unicast queries: `server_idx = 0`, reset `delay`, `retransmit_at = now`, clear `timeout_at`. Or document that pending queries may fail.
