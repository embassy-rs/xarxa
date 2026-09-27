# 335. DNS txid comes from the same non-cryptographic PRNG that emits raw TCP ISNs

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/dns.rs:282](../src/dns.rs#L282), [src/rand.rs:23](../src/rand.rs#L23), [src/tcp/mod.rs:782](../src/tcp/mod.rs#L782) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Txids come from the stack-wide PCG-style generator in `rand.rs`, which also produces TCP ISNs as raw outputs. Each output exposes about 32 of the 64 state bits, so two consecutive outputs let an attacker recover the state and predict later txids. This duplicates the known rand.rs:23 finding and only adds the DNS angle.

## Details
src/rand.rs (module doc: "Small non-cryptographic PRNG."):
```rust
let s = self.state.wrapping_mul(M).wrapping_add(A);
self.state = s;
let shift = 29 - (s >> 61);
(s >> shift) as u32
```
src/tcp/mod.rs:782:
```rust
TcpSeqNumber(rand.rand_u32() as i32)
```
src/dns.rs:282:
```rust
let txid = stack.inner.rand.rand_u16();
```
The DNS client port is drawn once at `DnsClient::new`, so predicting it needs outputs from before then. Txid prediction needs the number of draws in between, which an attacker can search by stepping the state forward. The rand.rs module doc does not list DNS txids among its uses.

## Failure scenario
An attacker opens TCP connections to the device, reads the SYN|ACK ISNs, recovers the state, and predicts the next query's txid. A spoofed answer can then be accepted on the first try.

## Suggested fix
Use a CSPRNG (for example ChaCha8 seeded from the user seed) for security-relevant values, or at least hash outputs before exposing them as ISNs.
