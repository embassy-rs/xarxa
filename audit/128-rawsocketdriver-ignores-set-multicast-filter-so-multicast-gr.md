# 128. RawSocketDriver ignores set_multicast_filter, so the host NIC can filter out groups the stack joins

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/driver_impls/raw_socket.rs:193](../src/driver_impls/raw_socket.rs#L193) (Driver impl), [src/driver_impls/raw_socket.rs:104](../src/driver_impls/raw_socket.rs#L104) (socket setup) |
| Features | default |
| Verification | plausible, not demonstrated |

## Summary
`RawSocketDriver` keeps the no-op default `set_multicast_filter`. Its AF_PACKET socket is not promiscuous and adds no `PACKET_MR_MULTICAST` or `PACKET_MR_ALLMULTI` membership. On a physical NIC, multicast groups that only xarxa wants (solicited-node groups of xarxa's own IPv6 addresses, groups the app joins) can be dropped by the hardware filter.

## Details
The socket is opened and bound with no membership setsockopt. There is no `PROMISC`, `MEMBERSHIP` or `ALLMULTI` anywhere in `src/driver_impls`.

src/driver_impls/raw_socket.rs:104:
```rust
let lower = libc::socket(
    libc::AF_PACKET,
    libc::SOCK_RAW | libc::SOCK_NONBLOCK,
    protocol.to_be() as i32,
);
```

The Driver contract says filtering out wanted traffic is not acceptable.

xarxa-driver/src/lib.rs:321:
```rust
/// receive all multicast. Losing filter efficiency is fine, filtering out
/// traffic the network stack wants is not.
fn set_multicast_filter(&mut self, addrs: &[[u8; 6]]) {
```

veth and tap do no multicast filtering, so tests on them do not show this. Some NICs use hash filters that may let these frames through by chance.

## Failure scenario
RawSocketDriver on a physical NIC. xarxa has 2001:db8::1234, the host does not. A neighbor sends an NS to ff02::1:ff00:1234. The NIC drops it because the host kernel never joined that group. xarxa never answers and the address is unreachable. Same for an mDNS group (224.0.0.251) if the host does not run avahi.

## Suggested fix
Implement `set_multicast_filter` with `PACKET_ADD_MEMBERSHIP` / `PACKET_DROP_MEMBERSHIP` (`PACKET_MR_MULTICAST`) per address, diffing against the previous list. Simpler: add one `PACKET_MR_ALLMULTI` membership at open.
