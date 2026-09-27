# 285. is_open docs say a non-open socket won't process or dispatch packets, but TIME-WAIT and aborted CLOSED sockets do

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2683](../src/tcp/mod.rs#L2683), [src/tcp/mod.rs:702](../src/tcp/mod.rs#L702), [src/tcp/mod.rs:920](../src/tcp/mod.rs#L920) |
| Features | default |
| Verification | confirmed against the code |

## Summary
`TcpSocket::is_open` says it returns true "if the socket will process incoming or dispatch outgoing packets", and false in CLOSED and TIME-WAIT. A TIME-WAIT socket still matches ingress and ACKs retransmitted FINs. An aborted CLOSED socket still dispatches one RST. So `is_open() == false` does not mean the socket is quiet. This duplicates the `is_open` part of 284.

## Details
The private `is_open` (mod.rs:702-710) returns false for Closed and TimeWait. `accepts()` only excludes Closed. src/tcp/mod.rs:920-923:
```rust
pub(crate) fn accepts(&self, src_addr: &IpAddr, dst_addr: &IpAddr, repr: &TcpRepr) -> bool {
    if self.state == State::Closed {
        return false;
    }
```
Dispatch handles TimeWait in the FinWait2/TimeWait arm (mod.rs:2041) and sends an ACK when due (mod.rs:2069-2072). A Closed socket with a tuple sends an RST (mod.rs:1962-1969).

## Failure scenario
A user assumes a TIME-WAIT socket is inert, and is surprised by traffic from a socket reported as not open. Or they reuse it with `connect` right away (allowed), which cuts TIME-WAIT short without knowing it.

## Suggested fix
Reword: false means the socket can be reused for a new connection. A socket in TIME-WAIT still answers the peer, and an aborted one still sends its RST.
