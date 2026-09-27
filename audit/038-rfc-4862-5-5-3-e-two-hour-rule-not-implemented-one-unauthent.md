# 038. RFC 4862 two-hour rule not implemented: one spoofed RA with a zero or short valid lifetime removes SLAAC addresses

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/slaac.rs:253](../src/iface/slaac.rs#L253), [src/iface/slaac.rs:202](../src/iface/slaac.rs#L202), [src/iface/slaac.rs:218](../src/iface/slaac.rs#L218), [src/iface/slaac.rs:461](../src/iface/slaac.rs#L461) |
| Features | default (`slaac`) |
| Verification | reproduced with a test |

## Summary

SLAAC applies the advertised valid lifetime as is. A valid lifetime of 0 expires the prefix at once, and a short one overwrites a long remaining lifetime. RA validation only requires hop limit 255 and a link-local source, so any on-link host can remove the node's global SLAAC addresses with one RA. RFC 4862 §5.5.3(e) has a rule for exactly this attack, and xarxa does not implement it.

## Details

src/iface/slaac.rs:260:

```rust
if prefix.valid_lifetime > Duration::ZERO {
    self.add_prefix(&cidr, &prefix, now);
} else {
    self.expire_prefix(&cidr, now);
}
```

src/iface/slaac.rs:208, `add_prefix` overwrites the stored lifetimes:

```rust
*old_info = prefix_info;
```

src/iface/slaac.rs:218, `expire_prefix` sets `valid_until = now` and `preferred_until = now`.

Neither looks at the remaining lifetime. At the next poll, `sync_slaac_state` sees `!prefixinfo.is_valid(timestamp)` (src/iface/slaac.rs:461) and removes the address. TCP connections using it then fail the `has_ip_addr` check in `dispatch` and stop sending. The existing `test_slaac` in src/stack.rs ("A router can withdraw with zero lifetimes", line 3373) asserts this behaviour.

Scope: the rule covers only the address valid lifetime. The preferred lifetime is still reset to the advertised value, so a preferred lifetime of 0 still deprecates the address. RFC 4861 §6.3.4 still allows an on-link prefix (L flag) to be timed out at once. xarxa installs no separate on-link route from the L flag, since the /64 comes from the address CIDR, so today removing the address also removes on-linkness.

## Failure scenario

1. The node holds 2001:db8::X/64 with 86400 s valid lifetime.
2. An on-link attacker sends one RA from any fe80:: source, hop limit 255, with PIO 2001:db8::/64, A=1, valid=0, preferred=0. Valid=1 s has the same effect.
3. At the next poll the address is removed. Connections using it stall.
4. The address comes back only at the real router's next RA, up to MaxRtrAdvInterval (600-1800 s) later. Repeating the RA keeps it away.

## RFC reference

RFC 4862 §5.5.3(e):

> 1. If the received Valid Lifetime is greater than 2 hours or greater than RemainingLifetime, set the valid lifetime of the corresponding address to the advertised Valid Lifetime.
>
> 2. If RemainingLifetime is less than or equal to 2 hours, ignore the Prefix Information option with regards to the valid lifetime, unless the Router Advertisement from which this option was obtained has been authenticated (e.g., via Secure Neighbor Discovery [RFC3971]). [...]
>
> 3. Otherwise, reset the valid lifetime of the corresponding address to 2 hours.
>
> The above rules address a specific denial-of-service attack in which a bogus advertisement could contain prefixes with very small Valid Lifetimes.

## Reproduction

Added to the `mod test` of src/iface/slaac.rs:

```rust
#[test]
fn vfy_two_hour_rule() {
    let mut slaac = Slaac::new(SlaacConfig::default(), Instant::ZERO);
    let now = Instant::from_millis(1);
    let mut p = PREFIX;
    p.valid_lifetime = Duration::from_secs(86400);
    p.preferred_lifetime = Duration::from_secs(3600);
    advertise(&mut slaac, VALID, Some(p), now);
    let other = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x66);
    let mut z = p; z.valid_lifetime = Duration::ZERO; z.preferred_lifetime = Duration::ZERO;
    slaac.process_advertisement(&other, NdiscRouterFlags::empty(), Duration::ZERO, Some(z).into_iter(), now);
    let valid_until = slaac.prefix[0].1.valid_until;
    std::println!("valid_until after spoofed 0: {:?}", valid_until);
    assert!(valid_until >= now + Duration::from_secs(7200), "valid lifetime cut below 2h");
}
```

Output:

```
valid_until after spoofed 0: Instant { millis: 1 }
panicked: valid lifetime cut below 2h
```

## Suggested fix

When the prefix is already in the table, compute the new `valid_until` per §5.5.3(e):

- advertised > 2 h or advertised > remaining: use advertised.
- else remaining <= 2 h: keep the current value.
- else: 2 h.

Apply this to a valid lifetime of 0 too, instead of `expire_prefix`. Always take the preferred lifetime from the RA. Update the "withdraw with zero lifetimes" expectation in `test_slaac`.
