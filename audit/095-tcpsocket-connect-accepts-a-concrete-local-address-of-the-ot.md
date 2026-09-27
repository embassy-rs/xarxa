# 095. TcpSocket::connect accepts a concrete local address of the other family, not ours, or with no route, and the socket sits in SYN-SENT forever sending nothing

| | |
|---|---|
| Severity | medium |
| Category | correctness |
| Location | [src/tcp/mod.rs:2561](../src/tcp/mod.rs#L2561), [src/tcp/mod.rs:2533](../src/tcp/mod.rs#L2533), [src/tcp/mod.rs:1887](../src/tcp/mod.rs#L1887), [src/stack.rs:444](../src/stack.rs#L444), [src/iface/mod.rs:1062](../src/iface/mod.rs#L1062) |
| Features | default |
| Verification | reproduced with a test |

## Summary

With a concrete local address, `connect` skips `get_source_address`, which is the only place a route is checked. It also skips the IP version check and never checks that the address is ours. It returns `Ok`, and every dispatch drops the SYN. With the default `timeout` of `None` the socket stays in SYN-SENT forever with nothing on the wire. The docs promise `Unaddressable` when there is no route, and the same remote with `local = 0` does return it.

## Details

src/tcp/mod.rs:2561:

```rust
let local_ip = match local.concrete_addr() {
    Some(addr) => addr,
    None => {
        if let Some(version) = local.version()
            && version != remote.addr.version()
        {
            return Err(ConnectError::Unaddressable);
        }
        self.tx
            .get_source_address(binding, &remote.addr)
            .ok_or(ConnectError::Unaddressable)?
    }
};
```

The doc at src/tcp/mod.rs:2533 says `Unaddressable` is returned if "there is no route to the remote address, the interface the route goes out of has no address to send from, or `local` is an unspecified address of the other IP version". A concrete address is not covered.

At dispatch, src/tcp/mod.rs:1887:

```rust
let route = if cx.has_ip_addr(tuple.local.addr) {
    cx.route(self.binding, &tuple.remote.addr)
} else {
    debug!(...);
    None
};
```

A local address that is not ours, or an unroutable remote, gives `None` and the segment is dropped at emit. A family mismatch with a route is dropped in `TxContext::transmit_ip` (src/stack.rs:444, "cannot transmit, address family mismatch"). The retransmit timer never gives up without a user timeout.

Related, confirmed in the code but not tested: for an IPv6 remote, `get_source_address_ipv6` falls back to `Ipv6Addr::LOCALHOST` when the interface has no IPv6 address (src/iface/mod.rs:1062-1067). So "the interface ... has no address to send from" never yields `Unaddressable` for IPv6, even with `local = 0`, once a route exists.

## Failure scenario

The application pins a source address from config (a static IP that DHCP later replaced, or a typo), passes its IPv4 address while connecting to an AAAA result, or connects with no default route. `connect` returns `Ok`. No packet is sent and, with no timeout set, the connection waits forever with no error. UDP rejects the equivalent with `Unaddressable` (DESIGN.md §6 "Source addresses").

## Reproduction

Test in `mod stack_test` of src/tcp/mod.rs (scratch copy):

```rust
#[test]
fn zz_v_connect_concrete_local_bad() {
    let cases: [(IpAddr, IpAddr); 3] = [
        (IpAddr::V6("fd00::2".parse().unwrap()), IpAddr::V4(LOCAL_ADDR)),
        (IpAddr::V4(Ipv4Addr::new(8,8,8,8)), IpAddr::V4(LOCAL_ADDR)),
        (IpAddr::V4(REMOTE_ADDR), IpAddr::V4(Ipv4Addr::new(10,0,0,1))),
    ];
    for (remote, local) in cases {
        let (mut stack, driver) = stack();
        let h = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
        assert_eq!(stack.tcp_socket(h).connect((remote, 80), (local, 0)), Ok(()));
        for i in 0..100 { stack.poll(Instant::from_millis(i * 1000)); }
        assert_eq!(driver.tx.borrow().len(), 0);
        assert_eq!(stack.tcp_socket(h).state(), State::SynSent);
    }
    let (mut stack, _d) = stack();
    let h = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
    assert_eq!(
        stack.tcp_socket(h).connect((IpAddr::V4(Ipv4Addr::new(8,8,8,8)), 80), 0),
        Err(ConnectError::Unaddressable)
    );
}
```

Output:

```
connect remote=V6(fd00::2) local=V4(192.168.1.1) -> Ok(())  frames=0 state=SynSent
connect remote=V4(8.8.8.8) local=V4(192.168.1.1) -> Ok(())  frames=0 state=SynSent
connect remote=V4(192.168.1.2) local=V4(10.0.0.1) -> Ok(())  frames=0 state=SynSent
connect 8.8.8.8 with local=0 -> Err(Unaddressable)
ok
```

## Suggested fix

For a concrete local address, reject a version mismatch and route the remote (`self.tx.route(binding, &remote.addr)`), returning `Unaddressable` on failure. Reject a local address not assigned to any interface, as UDP `bind` does, or document that it is allowed. Make IPv6 source selection report "no address" instead of falling back to `::1` for non-loopback destinations.
