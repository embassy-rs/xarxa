# 094. TcpSocket::connect allows broadcast and multicast remote addresses and sends SYNs to them

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/tcp/mod.rs:2552](../src/tcp/mod.rs#L2552), [src/stack.rs:351](../src/stack.rs#L351) |
| Features | default |
| Verification | reproduced with a test |

## Summary

`connect` only rejects port 0 and the unspecified address. A multicast, limited-broadcast or subnet-broadcast remote is accepted, and the next poll transmits a SYN to it. The socket then retransmits it every RTO, forever with the default timeout. RFC 9293 MUST-46 requires rejecting this, and the `connect` docs list no error for it.

## Details

src/tcp/mod.rs:2552:

```rust
if remote.port == 0 || remote.addr.is_unspecified() {
    return Err(ConnectError::Unaddressable);
}
```

Multicast and limited broadcast take the non-unicast branch of `Stack::route` and go out of the first interface.

src/stack.rs:351:

```rust
if !dst_addr.is_unicast() {
    ...
    return candidates.next().map(|(_, iface)| EgressRoute {
        iface: iface.handle,
        next_hop: *dst_addr,
        ip_mtu: iface.ip_mtu(),
    });
}
```

A subnet broadcast (192.168.1.255 on 192.168.1.1/24) is unicast by address class, so it is routed on-link through `in_same_network`. An `is_unicast()` check alone does not catch it.

## Failure scenario

An application passes a configured or DNS-supplied address that is 255.255.255.255, a subnet broadcast, or a group address. `connect` returns `Ok`. The device sends TCP SYNs to the whole link on every RTO and the connection never completes, instead of `connect` failing with `Unaddressable`.

## RFC reference

RFC 9293 §3.9.1.1:

> A TCP implementation MUST reject as an error a local OPEN call for an invalid remote IP address (e.g., a broadcast or multicast address) (MUST-46).

## Reproduction

Test in `mod stack_test` of src/tcp/mod.rs (scratch copy). `dst_of` parses the IPv4 destination of a frame.

```rust
#[test]
fn zz_v_connect_broadcast_multicast() {
    for dst in [Ipv4Addr::new(224,0,0,1), Ipv4Addr::new(255,255,255,255), Ipv4Addr::new(192,168,1,255)] {
        let (mut stack, driver) = stack();
        let h = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
        let r = stack.tcp_socket(h).connect((IpAddr::V4(dst), 80), 0);
        assert_eq!(r, Ok(()));
        stack.poll(Instant::from_millis(0));
        let tx = driver.tx.borrow();
        assert_eq!(tx.len(), 1);
        assert_eq!(dst_of(&tx[0]), dst);
    }
}
```

Output:

```
connect 224.0.0.1 -> Ok(())  frames=1 dst=Some(224.0.0.1)
connect 255.255.255.255 -> Ok(())  frames=1 dst=Some(255.255.255.255)
connect 192.168.1.255 -> Ok(())  frames=1 dst=Some(192.168.1.255)
ok
```

## Suggested fix

Return `Unaddressable` when `!remote.addr.is_unicast()` or when the remote is the broadcast address of any interface (the interface's IPv4 broadcast check). Add the case to the `connect` docs.
