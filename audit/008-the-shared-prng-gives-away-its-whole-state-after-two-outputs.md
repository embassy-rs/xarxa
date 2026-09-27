# 008. The shared PRNG gives away its whole state after two outputs, so TCP ISNs, ephemeral ports, DNS txids and DHCP xids are predictable

| | |
|---|---|
| Severity | high |
| Category | security |
| Location | [src/rand.rs:23](../src/rand.rs#L23), [src/tcp/mod.rs:782](../src/tcp/mod.rs#L782), [src/tcp/mod.rs:792](../src/tcp/mod.rs#L792), [src/tcp/listener.rs:239](../src/tcp/listener.rs#L239), [src/stack.rs:502](../src/stack.rs#L502), [src/dns.rs:282](../src/dns.rs#L282), [src/iface/dhcpv4.rs:459](../src/iface/dhcpv4.rs#L459), [src/multicast.rs:571](../src/multicast.rs#L571), [src/stack.rs:519](../src/stack.rs#L519) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`Rand` is a 64-bit LCG whose output is 32 contiguous state bits, picked by the top 3 bits. One output leaves 29 unknown bits per guess of those 3 bits, so two outputs recover the full state in about 2^32 cheap steps (under a second to a few seconds on a PC). Every consumer shares this one stream, and the LCG steps backwards as well as forwards. Once the state is known, every past and future ISN, ephemeral port, DNS txid, DHCP xid and tsval offset follows. A good seed does not help.

## Details

src/rand.rs:23-33
```rust
pub(crate) fn rand_u32(&mut self) -> u32 {
    // sPCG32 from https://www.pcg-random.org/paper.html
    // see also https://nullprogram.com/blog/2017/09/21/
    const M: u64 = 0xbb2efcec3c39611d;
    const A: u64 = 0x7590ef39;

    let s = self.state.wrapping_mul(M).wrapping_add(A);
    self.state = s;

    let shift = 29 - (s >> 61);
    (s >> shift) as u32
}
```

The output is bits `[29-t, 61-t)` of the new state, with `t = s >> 61`. For each of the 8 values of `t`, the unknown bits are the low `29-t` bits plus the `t` bits between `61-t` and 61. That is 29 bits. Step each candidate and compare with a later output: 8 x 2^29 = 2^32 multiply-adds. `M` is odd, so the LCG is invertible.

One stream, `StackInner::rand`, feeds:

- TCP ISN: `random_seq_no` (src/tcp/mod.rs:782), drawn at connect (src/tcp/mod.rs:2594) and accept (src/tcp/listener.rs:239). The raw output is the ISN, with no clock component.
- tsval offset: src/tcp/mod.rs:792, the next draw after the ISN (src/tcp/mod.rs:2596, src/tcp/listener.rs:260).
- Ephemeral ports: `alloc_ephemeral_port` (src/stack.rs:502).
- DNS txid: src/dns.rs:282. The `DnsClient` port is drawn once, at `DnsClient::new`.
- DHCP xid: src/iface/dhcpv4.rs:459. A full 32-bit output, broadcast on the link.
- MLD report delay: src/multicast.rs:571. An on-link host can trigger this draw with queries.
- 6LoWPAN sequence number and tag (src/sixlowpan.rs:69-72), IPv4 fragment id seed (src/fragmentation.rs:159).

How outputs leak:

- Any peer that connects to a listener reads the ISN in the SYN|ACK. Two accepts in a row are 2 draws apart with `tcp-timestamps` (ISN, then tsval offset), 1 without. Other draws in between only add a small search over the gap.
- Any on-link host reads DHCP xids.

The docs present the outputs as unpredictable. `Stack::new` (src/stack.rs:519-521): "`random_seed` seeds the stack's PRNG, which picks TCP initial sequence numbers and ephemeral ports. This should be random, or at least different at every boot." This suggests a boot counter is enough, and the list of uses omits DNS txids, DHCP xids, tsval offsets and fragment ids. The src/rand.rs module doc list also omits DNS and DHCP. The comment on `alloc_ephemeral_port` and DESIGN.md §7 say ports stay unpredictable to off-path attackers.

## Failure scenario

1. The device runs a TCP listener.
2. The attacker connects twice and records the ISNs of both SYN|ACKs.
3. An offline search of about 2^32 steps recovers the PRNG state.
4. The attacker predicts the ISN and ephemeral port of the device's next outgoing connection, or the ISN of the SYN|ACK the device will send to a spoofed trusted source. That allows blind in-window RST or data injection, or completing a spoofed handshake.
5. Stepping the state back gives the `DnsClient` port. Stepping forward gives the next DNS txids. That allows off-path DNS spoofing on the first try.
6. The tsval offset is recovered too, so tsval minus offset gives the uptime the offset was meant to hide.

An on-link attacker can do the same starting from DHCP xids.

## RFC reference

RFC 9293 §3.4.1: "A TCP implementation MUST use the above type of "clock" for clock-driven selection of initial sequence numbers (MUST-8), and SHOULD generate its initial sequence numbers with the expression:

ISN = M + F(localip, localport, remoteip, remoteport, secretkey)

where M is the 4 microsecond timer, and F() is a pseudorandom function (PRF) of the connection's identifying parameters ("localip, localport, remoteip, remoteport") and a secret key ("secretkey") (SHLD-1). F() MUST NOT be computable from the outside (MUST-9), or an attacker could still guess at sequence numbers from the ISN used for some other connection."

RFC 6056 §3.3.1 (Algorithm 1, which `alloc_ephemeral_port` implements): "Note that the output needs to be unpredictable, and typical implementations of POSIX random() function do not necessarily meet this requirement."

## Reproduction

A standalone C program with the exact `M` and `A` constants (not part of the crate test harness). It simulates the accept order ISN1, tsval offset (hidden), ISN2 from seed `0x9e3779b97f4a7c15`, and gives the attacker only ISN1 and ISN2. It enumerates `t` in `0..8` and 29 unknown bits, builds `s = t<<61 | mid<<(61-t) | ISN1<<(29-t) | low`, and keeps `s` if `out(step(step(s))) == ISN2`.

`gcc -O3 -fopenmp pcgbrute.c && time ./pcgbrute 0x9e3779b97f4a7c15`:

```
observed ISN1=3fde8b4d ISN2=9fffe750; true next ISN=2f2ce732
candidate state=d31fef45a6b1f29a (true=d31fef45a6b1f29a) predicts next ISN=2f2ce732
(+4 other candidates)
candidates=5
real 0m0.504s
```

One more observed output removes the false candidates. Independent single-core runs by other auditors took 1.5 to 4 s.

## Suggested fix

- Use a cryptographically secure generator seeded from the user's seed, such as ChaCha8 or SipHash in counter mode. Both are small.
- Derive ISNs as clock + keyed hash of the 4-tuple (RFC 9293 SHLD-1, RFC 6528), so ISNs of different connections are unrelated.
- At minimum, keep ISNs, ports and DNS txids off the stream whose outputs are broadcast (DHCP xid) or visible to any peer.
- Change the `Stack::new` doc to require a high-entropy seed that differs at every boot, and list all uses.
