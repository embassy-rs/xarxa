# 234. MLD query reception checks deviate from RFC 3810: no Router Alert check, nonzero Code rejected, specific queries only accepted at the group address

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/stack.rs:1896](../src/stack.rs#L1896), [src/multicast.rs:559](../src/multicast.rs#L559), [src/multicast.rs:584](../src/multicast.rs#L584) |
| Features | default |
| Verification | confirmed against the RFC text |

## Summary
Three deviations in MLD query handling:
- Router Alert presence is never required.
- A nonzero ICMPv6 Code drops the query, but receivers must ignore Code.
- A specific query is only processed when sent to the group itself, not to ff02::1 or our unicast address.

Real queriers send specific queries to the group, with Code 0 and Router Alert, so impact is small.

## Details
src/stack.rs:1896:
```rust
Icmpv6Message::MldQuery if hop_limit == 1 && src_addr.is_link_local() => self
```
`process_hop_by_hop` skips RouterAlert (src/stack.rs:2939) and does not report it.

src/multicast.rs:559:
```rust
if icmp_packet.msg_code() != 0 {
```
src/multicast.rs:584:
```rust
if self.has_multicast_group(mcast_addr.into()) && dst_addr == mcast_addr {
```

## Failure scenario
A querier or debug tool sends a Multicast Address Specific Query to the host's link-local unicast address. xarxa ignores it, and the router may prune the group. Queries without Router Alert, which a compliant host drops, are acted on.

## RFC reference
RFC 3810 §6.2: "the node checks if the source address of the message is a valid link-local address, if the Hop Limit is set to 1, and if the Router Alert option is present in the Hop-By-Hop Options header of the IPv6 packet. If any of these checks fails, the packet is dropped."
§5.1.1 Code: "Initialized to zero by the sender; ignored by receivers."
§5.1.15: "a node MUST accept and process any Query whose IP Destination Address field contains *any* of the addresses (unicast or multicast) assigned to the interface on which the Query arrives."

## Suggested fix
Have the HBH walk report Router Alert (MLD) presence and require it for MldQuery. Remove the Code check. Accept specific queries sent to the group, ff02::1, or any address of the interface.
