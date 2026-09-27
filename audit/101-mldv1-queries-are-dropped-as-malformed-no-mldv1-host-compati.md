# 101. MLDv1 queries are dropped as malformed: no MLDv1 host compatibility mode

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/wire/icmpv6.rs:296](../src/wire/icmpv6.rs#L296), [src/wire/icmpv6.rs:228](../src/wire/icmpv6.rs#L228), [src/stack.rs:1814](../src/stack.rs#L1814), [src/stack.rs:1894](../src/stack.rs#L1894) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`Icmpv6Packet::check_len` requires 28 bytes for an MLD Query. A 24-byte MLDv1 query fails `new_checked` and `process_icmpv6` drops it before it reaches `process_mldv2`. Beyond the wire check, there is no MLDv1 compatibility mode at all: no Older Version Querier Present state, no v1 Reports, no Done messages. RFC 3810 §8.2.1 makes that mode a MUST. MLDv1 queriers and MLDv1-only snooping switches never learn of the host's memberships.

## Details

src/wire/icmpv6.rs:296, in `header_len`:

```rust
Message::MldQuery => field::QUERY_NUM_SRCS.end,
```

That is 28. src/wire/icmpv6.rs:228, in `check_len`:

```rust
if len < field::HEADER_END || len < self.header_len() {
    return Err(Malformed);
}
```

src/stack.rs:1814, at the top of `process_icmpv6`:

```rust
let mut icmp_packet = check!(Icmpv6Packet::new_checked(&mut buf));
```

The `MldQuery` arm at src/stack.rs:1894-1898 is only reached after that. Reports are always MLDv2 reports to ff02::16 (src/multicast.rs:648), which an MLDv1 router ignores.

The public doc of `check_len` says it ensures no accessor will panic. It also rejects a well-formed packet type.

The README lists "MLDv2 (IPv6)" and does not mention the missing v1 compatibility in "Not yet implemented". Neither does DESIGN.md §10 or §11.

Fixing `check_len` alone is not enough. The stack would still need to send v1 Reports (type 131) and Dones (type 132) while a v1 querier is present.

## Failure scenario

1. The link's only querier, or its snooping switch, speaks MLDv1 only. This is still found on older and cheaper managed switches.
2. It sends 24-byte general queries. xarxa drops every one of them and never re-reports.
3. After the Multicast Listener Interval the switch prunes the host's groups: mDNS ff02::fb, application groups, and possibly the solicited-node groups.
4. If solicited-node groups are pruned, Neighbor Solicitations stop reaching the host and IPv6 connectivity breaks.

## RFC reference

RFC 3810 §8.1:

> MLDv1 Query: length = 24 octets
> MLDv2 Query: length >= 28 octets
> Query messages that do not match any of the above conditions (e.g., a Query of length 26 octets) MUST be silently ignored.

RFC 3810 §8.2.1:

> In order to be compatible with MLDv1 routers, MLDv2 hosts MUST operate in version 1 compatibility mode.  MLDv2 hosts MUST keep state per local interface regarding the compatibility mode of each attached link.

## Reproduction

Test in `mod test` of src/multicast.rs, in a scratch copy of HEAD:

```rust
#[test]
fn v5_mldv1_query_ignored() {
    let mut b = [0u8; 24]; b[0] = 130;
    println!("new_checked(24-byte MLDv1 query) is_err = {}", Icmpv6Packet::new_checked(&mut b[..]).is_err());
    let medium = Medium::Ethernet;
    let (mut stack, rx, tx, _link) = test_stack(medium);
    let timestamp = Instant::ZERO;
    stack.poll(timestamp); recv_mld(medium, &tx);
    let q2 = mld_query(REMOTE_LL, IPV6_LINK_LOCAL_ALL_NODES, Ipv6Addr::UNSPECIFIED, 0);
    inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, q2, timestamp);
    let n2 = recv_all(medium, &tx).len();
    println!("packets sent for MLDv2 query: {}", n2);
    let mut q1 = mld_query(REMOTE_LL, IPV6_LINK_LOCAL_ALL_NODES, Ipv6Addr::UNSPECIFIED, 0);
    q1.truncate(IPV6_HEADER_LEN + 24);
    Ipv6Packet::new_unchecked(&mut q1[..]).set_payload_len(24);
    Icmpv6Packet::new_unchecked(&mut q1[IPV6_HEADER_LEN..]).fill_checksum(&REMOTE_LL, &IPV6_LINK_LOCAL_ALL_NODES);
    let d = inject(&mut stack, &rx, medium, EthernetProtocol::Ipv6, q1, timestamp);
    let d = stack.poll(d);
    let n1 = recv_all(medium, &tx).len();
    println!("packets sent for MLDv1 query: {} (deadline {:?})", n1, d);
    assert!(n2 > 0);
    assert!(n1 > 0, "MLDv1 query was not answered");
}
```

`cargo test --lib v5_mldv1 -- --nocapture`:

```
new_checked(24-byte MLDv1 query) is_err = true
packets sent for MLDv2 query: 1
packets sent for MLDv1 query: 0 (deadline Instant { millis: 172800000 })
panicked: MLDv1 query was not answered
```

## Suggested fix

- Accept 24-byte queries in `check_len` and treat them as MLDv1 (RFC 3810 §8.1). Silently ignore other lengths below 28.
- Keep a per-interface Older Version Querier Present timer on the `Clock`.
- While it runs, send MLDv1 Reports (type 131) to the group and Done (type 132) to ff02::2.

Or, at minimum, list the missing MLDv1 compatibility in the README "Not yet implemented" section.
