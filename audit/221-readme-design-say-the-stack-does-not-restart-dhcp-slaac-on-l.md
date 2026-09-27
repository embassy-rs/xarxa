# 221. README/DESIGN say the stack does not restart DHCP/SLAAC on link-up, but poll does

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/stack.rs:1125](../src/stack.rs#L1125), [README.md:141](../README.md#L141), [DESIGN.md:491](../DESIGN.md#L491) |
| Features | default |
| Verification | confirmed against the code |

## Summary
On a Down to Up link edge, `Stack::poll` resets the DHCPv4 client (dropping the lease and address), restarts SLAAC and rejoins multicast groups. README "Not yet implemented" and DESIGN §4/§10 say the stack does not act on carrier. The `Iface::restart_dhcpv4` and `restart_slaac` docs (src/iface/mod.rs:532, 555) already say poll does it, so README and DESIGN are the stale ones.

## Details
src/stack.rs:1125-1141:
```rust
let link_state = iface.driver.link_state();
if link_state != iface.last_link_state {
    ...
    if link_state == crate::driver::LinkState::Up {
        #[cfg(feature = "dhcpv4")]
        iface.dhcpv4_reset(&mut self.inner);
        // slaac.restart(now), multicast.rejoin()
    }
}
```
README.md:141: "Acting on link state: skipping down interfaces on egress routing, restarting DHCP/SLAAC on link-up." DESIGN.md §4 says restarting DHCP/SLAAC on link-up is future work.

Flushing the interface's neighbor cache on link-up (DESIGN §10) is not done, so that part is still accurate.

## Failure scenario
A user reads the README and assumes a cable reseat keeps the lease. In fact the address is dropped at the next poll and DHCP restarts from DISCOVER. Or the user adds their own restart, doubling the RS burst.

## Suggested fix
Update README and DESIGN §4/§10: DHCP restart, SLAAC restart and multicast rejoin on link-up are implemented. Routing around down links and the neighbor flush are not.
