# 311. Assorted inaccurate public doc comments in wire and TCP

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/wire/ip.rs:167](../src/wire/ip.rs#L167), [src/wire/ipv4.rs:9](../src/wire/ipv4.rs#L9), [src/wire/ipv4.rs:130](../src/wire/ipv4.rs#L130), [src/wire/ndisc.rs:80](../src/wire/ndisc.rs#L80), [src/wire/ndisc.rs:154](../src/wire/ndisc.rs#L154), [src/tcp/mod.rs:2703](../src/tcp/mod.rs#L2703), [src/wire/ndiscoption.rs:232](../src/wire/ndiscoption.rs#L232) |
| Features | default |
| Verification | confirmed against the code |

## Summary
Several public docs state the wrong thing. The ICMPv4 `is_error` and `check_len` items overlap with finding 306.

## Details
- src/wire/ip.rs:167: `prefix_len` is "the number of leading zeroes". The implementation counts leading ones (255.255.255.0 gives 24).
- src/wire/ipv4.rs:9: `MIN_MTU` (576) is "Minimum MTU required of all links supporting IPv4. See [RFC 791 § 3.1]". RFC 791 gives 68 for links and 576 for reassembly, and the quote is in §3.2.
- src/wire/ipv4.rs:130: `from_netmask` rejects 0.0.0.0 with `Malformed`. No `# Errors` section says so.
- src/wire/ndisc.rs:80 and 154: "Neighbor Solicitation flags". R/S/O are Neighbor Advertisement flags (RFC 4861 §4.4).
- src/tcp/mod.rs:2703: `[abort](#method.close)` links to the wrong method.
- src/wire/ndiscoption.rs:232 and 238: `valid_lifetime`/`preferred_lifetime` use `Duration::from_secs`, which saturates at 2^30 ms. 0xffffffff (infinity) reads as about 12.4 days, and the setters cannot write infinity. The cap is a DESIGN.md §4 "Time" decision, but the public docs do not mention it.
- src/wire/icmpv4.rs:38 and 166: see 306.

## RFC reference
RFC 791 §3.2: "Every internet module must be able to forward a datagram of 68 octets without further fragmentation... Every internet destination must be able to receive a datagram of 576 octets".

## Suggested fix
Correct each doc. Add `# Errors` to `from_netmask`. Document the saturation on the lifetime getters and setters.
