# 240. ARP probes (sender IP 0.0.0.0) and DAD neighbor solicitations for our addresses are never answered

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2201](../src/stack.rs#L2201), [src/stack.rs:1689](../src/stack.rs#L1689) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`process_arp` drops any ARP whose sender protocol address is not unicast. 0.0.0.0 is not unicast, so an ARP Probe for one of our addresses gets no reply. The prober concludes the address is free. The IPv6 counterpart has the same effect: a DAD NS (source `::`) never reaches `process_ndisc_solicit`.

## Details
src/stack.rs:2200:
```rust
// Discard packets with non-unicast source addresses.
if !source_protocol_addr.x_is_unicast() || !source_hardware_addr.is_unicast() {
    debug!("arp: non-unicast source address");
    return;
}
```
`Ipv4Addr::x_is_unicast` excludes the unspecified address (src/wire/ipv4.rs:64). The `in_same_network` check at src/stack.rs:2206 would reject it too. Both run before the reply to a REQUEST.

src/stack.rs:1689:
```rust
if !src_addr.x_is_unicast() {
    // Discard packets with non-unicast source addresses.
    debug!("non-unicast source address");
    return;
}
```
`Ipv6Addr::x_is_unicast` excludes `::` (src/wire/ipv6.rs:132), so a DAD NS is dropped in `process_ipv6`.

Linux answers both (the `sip == 0` special case in `arp_process`, and the DAD case in `ndisc_recv_ns`).

## Failure scenario
xarxa holds 192.168.1.50. A DHCP server with an overlapping pool offers 192.168.1.50 to a laptop. The laptop ARP-probes it (SPA 0.0.0.0), gets no answer, and configures it. Both hosts now break each other's traffic. On IPv6, another node's DAD for our address succeeds in the same way. The xarxa DHCP server also relies on clients detecting conflicts (DESIGN §10).

## RFC reference
RFC 826, packet reception: "?Am I the target protocol address? Yes: ... ?Is the opcode ares_op$REQUEST? (NOW look at the opcode!!) Yes: Swap hardware and protocol fields, putting the local hardware and protocol addresses in the sender fields. Set the ar$op field to ares_op$REPLY. Send the packet to the (new) target hardware address".

RFC 3927 §2.2.1: "The 'sender IP address' field MUST be set to all zeroes ... An ARP Request constructed this way with an all-zero 'sender IP address' is referred to as an \"ARP Probe\"."

RFC 2131 §2.2: "the client SHOULD probe the newly received address, e.g., with ARP."

RFC 4861 §7.2.4: "If the source of the solicitation is the unspecified address, the node MUST set the Solicited flag to zero and multicast the advertisement to the all-nodes address."

The explicit duty to defend against ARP Probes is in RFC 5227, which is not in `rfcs/` and was not checked. For IPv4 no MUST in `rfcs/` is violated. The IPv6 case is a MUST.

## Reproduction
Test in `src/stack.rs` `mod test`, scratch copy of HEAD:
```rust
#[test]
fn vfy_f4_arp_probe() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    let probe = arp_request_from(OTHER_HW, Ipv4Addr::UNSPECIFIED);
    inject(&mut stack, &rx, probe);
    println!("F4: {} frames after ARP probe", tx.borrow().len());
    assert!(tx.borrow().is_empty());
    inject(&mut stack, &rx, arp_request_from(OTHER_HW, REMOTE_V4));
    assert_eq!(tx.borrow().len(), 1);
}
```
Output:
```
F4: 0 frames after ARP probe
ok
```
The IPv6 path was confirmed by reading the code only.

## Suggested fix
- ARP: when SPA is 0.0.0.0, the op is REQUEST and the target is ours, skip the cache fill and the same-network check but still send the reply to the sender hardware address. Swapping fields literally gives TPA 0.0.0.0, which is what Linux sends. The prober only looks at the SPA.
- IPv6: let an NS with source `::` through `process_ipv6`, skip the SLLA cache fill, and answer with an NA to ff02::1 with S=0.
