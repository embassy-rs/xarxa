# 239. ARP ignores packets not targeted at us, so the merge step never runs: gratuitous ARP and MAC changes are not picked up

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:2189](../src/stack.rs#L2189) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`process_arp` returns before touching the cache unless the target protocol address is ours. The RFC 826 merge step, which updates an existing entry from any ARP whose sender is in the table, never runs. Gratuitous ARP after a failover or NIC swap is ignored, and we keep sending to the old MAC until the entry goes Stale (up to 60 s).

## Details
src/stack.rs:2189:
```rust
// Only process ARP packets for us.
if !iface.has_ip_addr(target_protocol_addr.into()) {
    return;
}
```
`reset_expiry_if_existing` only refreshes an entry whose MAC matches, so IP traffic from the new MAC does not fix it. A gateway is never the IP source of routed traffic anyway.

## Failure scenario
A VRRP/CARP gateway or an HA pair without a virtual MAC fails over and announces the new MAC with gratuitous ARP. xarxa blackholes traffic to that neighbor for up to 60 s.

## RFC reference
RFC 826: "If the pair <protocol type, sender protocol address> is already in my translation table, update the sender hardware address field of the entry with the new information in the packet and set Merge_flag to true. ?Am I the target protocol address?"
RFC 1122 §2.3.2.1 IMPLEMENTATION (1): the timeout "should be restarted when the cache entry is 'refreshed' (by observing the source fields, regardless of target address, of an ARP broadcast from the system in question)".

## Reproduction
Test in the `mod test` module of src/stack.rs (scratch copy):
```rust
#[test]
fn vt_gratuitous_arp() {
    let (mut stack, rx, tx) = test_stack(Medium::Ethernet);
    inject(&mut stack, &rx, arp_request_from(OTHER_HW, REMOTE_V4));
    tx.borrow_mut().clear();
    let new_hw = EthernetAddress([2,0,0,0,0,0x33]);
    let mut g = arp_request_from(new_hw, REMOTE_V4);
    ArpPacket::new_unchecked(&mut g[ETHERNET_HEADER_LEN..]).set_target_protocol_addr(&REMOTE_V4.octets());
    inject(&mut stack, &rx, g);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(5555, ListenSocketAddr::UNSPECIFIED).unwrap();
    stack.udp_socket(udp).send_slice(b"hi", (REMOTE_V4, 1000)).unwrap();
    let tx = tx.borrow();
    let mut frame = tx.last().unwrap().clone();
    let dst = EthernetFrame::new_unchecked(&mut frame[..]).dst_addr();
    println!("VT10 dst={}", dst);
    assert_eq!(dst, OTHER_HW);
}
```
Output: `VT10 dst=02-00-00-00-00-02`, test passes (the old MAC is still used).

## Suggested fix
Before the target check, update an existing entry for (iface, sender IP) with the sender MAC when the sender is unicast. Keep creating new entries only when we are the target.
