# 105. 9 of 10 examples do not build with their declared required-features: `alloc` is missing

| | |
|---|---|
| Severity | low |
| Category | feature-gating |
| Location | [Cargo.toml:528](../Cargo.toml#L528), [src/stack.rs:625](../src/stack.rs#L625), [src/stack.rs:885](../src/stack.rs#L885) |
| Features | default |
| Verification | reproduced with a test |

## Summary
Every `[[example]]` except `tcp_client` calls `Stack::add_iface(Box<...>)`, which is gated on `alloc`. `tcp_server` and `sixlowpan` also call `add_tcp_socket`, gated on `tcp` + `alloc`. None of the `required-features` lists include `alloc`. They only build because `alloc` is a default feature.

## Details
src/stack.rs:625-626:
```rust
#[cfg(feature = "alloc")]
pub fn add_iface(&mut self, driver: alloc::boxed::Box<dyn Driver + 'd>)
```
src/stack.rs:885:
```rust
#[cfg(all(feature = "tcp", feature = "alloc"))]
```
Callers of `add_iface(Box::new(driver))`: tuntap.rs:46, tcp_server.rs:49, dhcp.rs:37, dhcp_server.rs:35, ping.rs:68, dns.rs:57, sixlowpan.rs:71, multicast.rs:46, multicast6.rs:51. Callers of `add_tcp_socket(4096, 4096)`: tcp_server.rs:82, sixlowpan.rs:108. `tcp_client` uses `add_iface_borrowed` and `add_tcp_socket_with_bufs` (tcp_client.rs:61, 77).

CI only runs `cargo build --examples` with default features (ci.py:208), so the declared sets are never checked.

## Reproduction
```
$ cargo build --example tuntap --no-default-features --features std,log,medium-ethernet,medium-ip,ipv4,ipv6,udp
error[E0599]: no method named `add_iface` found for struct `Stack<'d>` --> examples/tuntap.rs:46:23

$ cargo build --example tcp_server --no-default-features --features std,log,medium-ethernet,medium-ip,ipv4,ipv6,tcp-listener
error[E0599]: no method named `add_iface` (examples/tcp_server.rs:49:23)
error[E0599]: no method named `add_tcp_socket` (examples/tcp_server.rs:82:32)

$ cargo build --example tcp_client --no-default-features --features std,log,medium-ethernet,medium-ip,ipv4,ipv6,tcp
Finished

$ cargo build --example tuntap --no-default-features --features std,log,medium-ethernet,medium-ip,ipv4,ipv6,udp,alloc
Finished
```
The other six examples were not built one by one. They make the same `add_iface` call.

## Suggested fix
Add `"alloc"` to `required-features` of tuntap, tcp_server, ping, dns, sixlowpan, dhcp, dhcp_server, multicast and multicast6. Add a CI step that builds each example with only its required-features.
