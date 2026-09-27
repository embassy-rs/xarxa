# 168. config_generation and the interface waker miss manual and expired route changes, and MAC changes in IPv4-only builds

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/iface/mod.rs:474](../src/iface/mod.rs#L474), [src/iface/mod.rs:708](../src/iface/mod.rs#L708), [src/iface/mod.rs:345](../src/iface/mod.rs#L345), [src/stack.rs:795](../src/stack.rs#L795), [src/stack.rs:1226](../src/stack.rs#L1226) |
| Features | default |
| Verification | reproduced with a test |

## Summary
`Iface::register_waker` promises a wake when routes are "added or removed, whether by hand or by DHCPv4 or SLAAC". Routes changed through `Stack::routes_mut()`, routes removed by expiry in `poll`, and `routes.purge_iface` never bump `config_generation` or wake the waker. In a build without `ipv6`, `set_hardware_addr` does not bump it either.

## Details
The generation is only bumped in `IfaceState::config_changed`.

src/iface/mod.rs:719:
```rust
self.config_generation = self.config_generation.wrapping_add(1);
```

src/iface/mod.rs:474:
```rust
/// [`config_generation`](Self::config_generation) changes: addresses or routes
/// added or removed, whether by hand or by DHCPv4 or SLAAC.
```

src/stack.rs:795 hands out the table directly. No `Routes` method can reach an interface:
```rust
pub fn routes_mut(&mut self) -> &mut Routes {
```

src/stack.rs:1226, in `poll`, with no `config_changed`:
```rust
self.inner.routes.remove_expired(clock.now());
```

Only DHCP and SLAAC route changes call `config_changed`.

In `set_hardware_addr` (src/iface/mod.rs:350) the whole invalidate block is under `#[cfg(all(any(medium-ethernet, medium-ieee802154), feature = "ipv6"))]`. An IPv4-only build changes the MAC with no generation bump.

## Failure scenario
A task waits on the interface waker for "address plus default route". The application sets the address, then calls `stack.routes_mut().add_default_ipv4_route(..)`. The waiter is not woken for the route and sleeps until some unrelated change. The same happens when a route with an expiry runs out.

## Reproduction
`stack` module test harness, scratch copy:
```rust
let g = stack.iface(h).config_generation();
stack.routes_mut().add_default_ipv4_route(REMOTE_V4, h).unwrap();
std::println!("gen before {} after {}", g, stack.iface(h).config_generation());
```
Output: `gen before 7 after 7`. A registered iface waker got 0 wakes.

## Suggested fix
Either narrow the docs to routes installed by DHCPv4/SLAAC, or make manual and expired route changes bump the owning interface's generation. Call `config_changed` in `set_hardware_addr` in all builds.
