# 184. join/leave_multicast_group docs: IPv4 reports wait for an address, and a leave with no address is never sent

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/multicast.rs:157](../src/multicast.rs#L157), [src/multicast.rs:173](../src/multicast.rs#L173), [src/multicast.rs:276](../src/multicast.rs#L276), [src/multicast.rs:528](../src/multicast.rs#L528) |
| Features | default |
| Verification | confirmed against the code |

## Summary
The docs of `join_multicast_group` and `leave_multicast_group` say the membership or the leave is reported "from the next `Stack::poll`". For IPv4, a join stays pending until the interface has an IPv4 address. A leave issued with no IPv4 address removes the group and sends nothing. A leave or join also goes unreported if the pool is empty.

## Details
src/multicast.rs:269-276, a Joining IPv4 group is only reported with an address:
```rust
let has_ipv4_addr = self.ipv4_addr().is_some();
...
IpAddr::V4(_) => has_ipv4_addr,
```
The join is not lost: it goes out at the first poll after an address appears ("Keep joins pending across DHCP restart").

src/multicast.rs:528-529, the leave packet needs an address and a buffer:
```rust
let iface_addr = self.ipv4_addr()?;
let mut pkt = PacketBuf::try_new()?;
```
The Leaving arm dispatches only on `Some` and then does `self.multicast.groups.swap_remove(i)` unconditionally (line 310). Likewise a join sets `GroupState::Joined` (line 293) even when no report was built.

## Failure scenario
- The app joins 239.1.1.1 before DHCP binds. Nothing is reported until the lease arrives.
- The lease is lost, then the app leaves the group. No Leave is sent. The router keeps forwarding the group until its membership timeout (about 260 s).

Leaving without a report is legal, so the consequence is small.

## Suggested fix
Document that IPv4 reports need an IPv4 address and that a leave without one is not reported. Or keep the group Leaving until the leave can be sent.
