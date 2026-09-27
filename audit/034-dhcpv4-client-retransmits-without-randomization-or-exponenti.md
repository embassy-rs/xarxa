# 034. DHCPv4 client retransmits without randomization or exponential backoff, and restarts discovery instantly

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4.rs:714](../src/iface/dhcpv4.rs#L714), [src/iface/dhcpv4.rs:748](../src/iface/dhcpv4.rs#L748), [src/iface/dhcpv4.rs:313](../src/iface/dhcpv4.rs#L313), [src/iface/dhcpv4.rs:839](../src/iface/dhcpv4.rs#L839), [src/iface/dhcpv4.rs:640](../src/iface/dhcpv4.rs#L640), [src/iface/dhcpv4.rs:452](../src/iface/dhcpv4.rs#L452) |
| Features | `dhcpv4` |
| Verification | reproduced with a test |

## Summary
DISCOVER is resent every fixed 10 s forever. REQUEST uses fixed 5/5/10/10/20 s delays. Nothing is randomized, there is no startup delay, and T1/T2 have no fuzz. The first DISCOVER after start, NAK or lease expiry goes out in the same poll. So many devices booting together retry in lockstep, and a server that NAKs or grants a zero-length lease gets a new DISCOVER/REQUEST at round-trip speed.

## Details
src/iface/dhcpv4.rs:43 and 714:
```rust
const DISCOVER_TIMEOUT: Duration = Duration::from_secs(10);
...
state.retry_at = clock.after(DISCOVER_TIMEOUT);
```

src/iface/dhcpv4.rs:748:
```rust
state.retry_at = clock.after(INITIAL_REQUEST_TIMEOUT * (1u32 << (state.retry as u32 / 2)));
```

`Client::new` sets `retry_at: now` (line 313). `dhcpv4_reset` sets `retry_at: inner.now` (line 839), and `dhcpv4_poll` loops (`continue`) so the DISCOVER goes out in the same poll. An OFFER sets `retry_at: now` (line 640), so the REQUEST goes out in the same poll too.

`parse_ack` computes `let expires_at = now + lease_duration;` (line 452) with no lower bound. A lease time of 0 expires in the same poll and discovery restarts immediately. On the server side, `MIN_LEASE_DURATION` (src/iface/dhcpv4_server.rs:384) only clamps a duration the client asked for. A configured `DhcpServerConfig::lease_duration = Duration::ZERO` is sent as-is, so xarxa's own server can trigger this.

This doesn't busy-loop the stack alone, since each turn needs a server reply. But the rate is bounded only by the RTT.

## Failure scenario
- 200 devices on one segment boot when power returns. All send DISCOVER at 0, 10, 20 s... in exact sync, then synchronized REQUEST retries, then renew at the same T1.
- A server that keeps NAKing (the case `ignore_naks` exists for), or grants lease 0, gets DISCOVER/REQUEST pairs as fast as it answers.

## RFC reference
RFC 2131 §4.1:

> The client MUST adopt a retransmission strategy that incorporates a randomized exponential backoff algorithm to determine the delay between retransmissions. ... the delay before the first retransmission SHOULD be 4 seconds randomized by the value of a uniform random number chosen from the range -1 to +1. ... The retransmission delay SHOULD be doubled with subsequent retransmissions up to a maximum of 64 seconds.

RFC 2131 §4.4.1:

> The client SHOULD wait a random time between one and ten seconds to desynchronize the use of DHCP at startup.

RFC 2131 §4.4.5:

> Times T1 and T2 SHOULD be chosen with some random "fuzz" around a fixed value, to avoid synchronization of client reacquisition.

## Reproduction
Tests added to the test module of src/iface/dhcpv4_server.rs, in a scratch copy of HEAD:
```rust
#[test]
fn vfy_zero_lease_loop() {
    use crate::iface::dhcpv4::DhcpConfig;
    let server_device = TestDevice::new(Medium::Ethernet);
    let mut server_stack = Stack::new(1, at(0));
    let server_iface = server_device.install(&mut server_stack, HardwareAddress::Ethernet(SERVER_HW));
    server_stack.iface(server_iface).add_ip_addr(IpCidr::new(SERVER_IP.into(), 24)).unwrap();
    let mut cfg = test_config();
    cfg.lease_duration = Duration::ZERO;
    server_stack.iface(server_iface).set_dhcpv4_server(Some(cfg)).unwrap();
    let client_device = TestDevice::new(Medium::Ethernet);
    let mut client_stack = Stack::new(2, at(0));
    let client_iface = client_device.install(&mut client_stack, HardwareAddress::Ethernet(CLIENT_HW));
    client_stack.iface(client_iface).set_dhcpv4(Some(DhcpConfig::default())).unwrap();
    let mut client_frames = 0;
    for _ in 0..20 {
        client_stack.poll(at(1));
        client_frames += client_device.tx.borrow().len();
        for frame in client_device.tx.borrow_mut().drain(..) { server_device.rx.borrow_mut().push_back(frame); }
        server_stack.poll(at(1));
        for frame in server_device.tx.borrow_mut().drain(..) { client_device.rx.borrow_mut().push_back(frame); }
    }
    println!("client frames sent within one instant over 20 round trips: {}", client_frames);
    assert!(client_frames <= 4, "client looped: {client_frames} frames at one instant");
}

#[test]
fn vfy_discover_fixed_interval() {
    use crate::iface::dhcpv4::DhcpConfig;
    let client_device = TestDevice::new(Medium::Ethernet);
    let mut client_stack = Stack::new(2, at(0));
    let client_iface = client_device.install(&mut client_stack, HardwareAddress::Ethernet(CLIENT_HW));
    client_stack.iface(client_iface).set_dhcpv4(Some(DhcpConfig::default())).unwrap();
    let mut times = Vec::new();
    let mut t = at(0);
    for _ in 0..6 {
        client_stack.poll(t);
        if !client_device.tx.borrow().is_empty() { times.push(t - at(0)); client_device.tx.borrow_mut().clear(); }
        t = client_stack.poll(t);
    }
    println!("DISCOVER send times: {:?}", times);
}
```

`cargo test --lib -- vfy_zero_lease_loop vfy_discover --nocapture`:
```
DISCOVER send times: [0 ms, 10000 ms, 20000 ms, 30000 ms, 40000 ms, 50000 ms]
client frames sent within one instant over 20 round trips: 21
panicked: client looped: 21 frames at one instant
```

## Suggested fix
- DISCOVER and REQUEST: 4 s doubling to 64 s, with ±1 s jitter from `inner.rand`.
- A random delay when entering INIT (1-10 s at startup, or at least 0-1 s after a NAK or expiry). This also caps the NAK and zero-lease loops.
- Fuzz T1/T2.
- A floor on the accepted lease duration in the client, and on `DhcpServerConfig::lease_duration` in the server.
