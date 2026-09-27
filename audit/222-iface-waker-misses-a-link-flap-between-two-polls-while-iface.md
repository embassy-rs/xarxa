# 222. Iface waker misses a link flap between two polls, while Iface::link_state() reads the driver live

| | |
|---|---|
| Severity | low |
| Category | missed-wake |
| Location | [src/stack.rs:1125](../src/stack.rs#L1125), [src/iface/mod.rs:313](../src/iface/mod.rs#L313), [src/iface/mod.rs:480](../src/iface/mod.rs#L480) |
| Features | async (default) |
| Verification | confirmed against the code |

## Summary
The interface waker and the link-up restart fire only when `poll` sees `driver.link_state()` differ from `last_link_state`, sampled once per poll. `Iface::link_state()` reads the driver live. If the link goes Up, Down, Up between two polls, a task that read Down and waits for Up is never woken, and the DHCP/SLAAC restart is skipped.

## Details
src/iface/mod.rs:313-315:
```rust
pub fn link_state(&mut self) -> LinkState {
    self.state_mut().driver.link_state()
}
```
src/stack.rs:1125-1128:
```rust
let link_state = iface.driver.link_state();
if link_state != iface.last_link_state {
    iface.last_link_state = link_state;
    iface.waker.wake();
```
`register_waker` says it "is woken when the link goes up or down". The only wake is inside this edge check. The flap has to finish within one poll interval.

## Failure scenario
A Wi-Fi roam. The driver reports Down. Before the runner polls, an app task reads `link_state()` == Down, registers the iface waker and waits. The driver reports Up again. The runner polls, sees Up == Up, and wakes nobody. DHCP is not restarted either, although the link may be on a different network.

## Suggested fix
Make `Iface::link_state()` return `last_link_state`, the value the waker is keyed on. Or let drivers report edges or a change counter.
