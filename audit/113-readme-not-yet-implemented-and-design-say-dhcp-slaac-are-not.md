# 113. README and DESIGN say DHCP/SLAAC are not restarted on link-up, but Stack::poll does it

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [README.md:141](../README.md#L141), [src/stack.rs:1126](../src/stack.rs#L1126), [src/stack.rs:682](../src/stack.rs#L682), [src/iface/mod.rs:533](../src/iface/mod.rs#L533), [src/iface/mod.rs:557](../src/iface/mod.rs#L557) |
| Features | default |
| Verification | confirmed against the code |

## Summary
README "Not yet implemented" lists "restarting DHCP/SLAAC on link-up". DESIGN §4 says the stack "only reports" carrier, and §10 lists it as future work. `Stack::poll` does act on the Down to Up edge: it resets the DHCP client, restarts SLAAC and re-sends multicast reports. The `Iface::restart_dhcpv4` and `restart_slaac` docs already say poll does this. Skipping down interfaces on egress is still unimplemented.

## Details
src/stack.rs:1126-1141:
```rust
                if link_state != iface.last_link_state {
                    iface.last_link_state = link_state;
                    ...
                    if link_state == crate::driver::LinkState::Up {
                        #[cfg(feature = "dhcpv4")]
                        iface.dhcpv4_reset(&mut self.inner);
                        #[cfg(feature = "slaac")]
                        if let Some(slaac) = iface.slaac.as_mut() {
                            slaac.restart(self.inner.now);
                        }
                        #[cfg(feature = "multicast")]
                        iface.multicast.rejoin();
                    }
```
`dhcpv4_reset` removes the leased address and default route at once. src/stack.rs:682 starts `last_link_state` at `Down`, so the first poll with the link up also takes this path.

## Failure scenario
A user reads the README and adds their own link-up handling that calls `restart_dhcpv4`. The lease is dropped and rediscovered twice per bounce. Or the user expects a lease to survive a cable wiggle, and instead the address and default route disappear until a new DISCOVER/OFFER/REQUEST/ACK completes.

## Suggested fix
Reduce the README item to "skipping down interfaces on egress routing". Update DESIGN §4 and §10. Document the link-up behavior on `Stack::poll` and `Iface::set_dhcpv4`.
