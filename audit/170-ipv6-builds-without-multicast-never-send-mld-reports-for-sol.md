# 170. IPv6 builds without `multicast` never send MLD reports for solicited-node groups

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/mod.rs:708](../src/iface/mod.rs#L708), [src/stack.rs:692](../src/stack.rs#L692), [src/lib.rs:50](../src/lib.rs#L50) |
| Features | ipv6 without multicast |
| Verification | confirmed against the RFC text |

## Summary
Solicited-node groups are only joined, and so reported with MLD, with the `multicast` feature. Without it the stack accepts solicited-node traffic but never announces it. An MLD-snooping switch may then stop forwarding neighbor solicitations to the device, and address resolution toward it fails.

## Details
src/iface/mod.rs:709-716, in `config_changed` (and the same in `add_iface`, src/stack.rs:692-698):
```rust
#[cfg(all(feature = "multicast", any(feature = "medium-ethernet", feature = "medium-ieee802154"), feature = "ipv6"))]
if self.has_link_layer() {
    self.update_solicited_node_groups();
}
```
Without `multicast` there is no `multicast` module at all (src/lib.rs:50-51), so no MLD is ever sent. Ingress still accepts solicited-node destinations and the NIC filter is programmed, so plain switches work.

The feature split is a size choice. The `multicast` doc in Cargo.toml does not say that IPv6 address resolution depends on it on snooping networks.

## Failure scenario
`medium-ethernet,ipv6,udp` build on a switch with MLD snooping. After the membership timeout, NS to ff02::1:ffXX:XXXX is no longer flooded to the device's port. Peers can't resolve it.

## RFC reference
RFC 4861 §7.2.1: "When a multicast-capable interface becomes enabled, the node MUST join the all-nodes multicast address on that interface, as well as the solicited-node multicast address corresponding to each of the IP addresses assigned to the interface. ... Joining the solicited-node multicast address is done using a Multicast Listener Discovery such as [MLD] or [MLDv2] protocols."

The MUST is on joining. The MLD mechanism is stated descriptively.

## Suggested fix
Send a minimal MLD report for solicited-node groups without `multicast`, or document in the `ipv6`/`multicast` feature docs that NDISC needs `multicast` on MLD-snooping networks.
