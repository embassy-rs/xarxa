# 361. Wire wrappers need `&mut [u8]` even for reading, so peeked socket data cannot be parsed without a copy

| | |
|---|---|
| Severity | info |
| Category | api |
| Location | [src/wire/ipv4.rs:228](../src/wire/ipv4.rs#L228), [src/raw.rs:427](../src/raw.rs#L427), [src/udp.rs:718](../src/udp.rs#L718) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The packet wrappers (`Ipv4Packet`, `Ipv6Packet`, `UdpPacket`, `TcpPacket`, ICMP, DNS, DHCP, ...) hold `&'a mut [u8]` and are constructed from `&mut [u8]` only. `RawSocket::peek` and `UdpSocket::peek` return `&[u8]`. So a peeked packet cannot be parsed without copying it first. DESIGN.md §8 specifies read wrappers over `&[u8]` with a separate mutable counterpart.

## Details
src/wire/ipv4.rs:228 and :236:
```rust
pub const fn new_unchecked(buffer: &'a mut [u8]) -> Packet<'a> {
pub fn new_checked(buffer: &'a mut [u8]) -> Result<Packet<'a>, Malformed> {
```
src/raw.rs:427:
```rust
pub fn peek(&self) -> Result<&[u8], RecvError> {
```
src/udp.rs:718:
```rust
pub fn peek(&mut self) -> Result<(&[u8], UdpMetadata), RecvError> {
```
Only `Ipv6ExtHeader` and the TCP/DNS option, question and record parsers take `&[u8]`. `recv()` hands out an owned buffer, so only `peek` is affected.

## Failure scenario
A ping tool wants to check whether the head of a raw socket's queue is its echo reply before dequeuing it. `Ipv4Packet::new_checked(sock.peek()?)` does not compile, so it copies up to 1500 bytes into a scratch buffer.

## Suggested fix
Add read-only wrappers over `&[u8]`, as DESIGN.md §8 describes, or split the getters into a type that only needs a shared borrow.
