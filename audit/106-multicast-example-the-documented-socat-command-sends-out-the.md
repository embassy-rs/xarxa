# 106. multicast example: the documented socat command sends out the host's default-route interface, not tap0

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [examples/multicast.rs:16](../examples/multicast.rs#L16) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The header suggests `echo hi | socat - UDP4-DATAGRAM:224.0.0.251:5353,bind=:5353`. It sets no multicast interface. Linux picks the egress interface for 224.0.0.251 by a FIB lookup, which hits the default route, not tap0. The example never sees the datagram.

## Details
examples/multicast.rs:13-16:
```
sudo ip link set up dev tap0
sudo ip addr add 192.168.69.100/24 dev tap0
# e.g. avahi-browse -a, or:
echo hi | socat - UDP4-DATAGRAM:224.0.0.251:5353,bind=:5353
```
Adding 192.168.69.100/24 installs a route for 192.168.69.0/24 only. Nothing routes 224.0.0.0/4 to tap0. `multicast6.rs` scopes its address (`ff02::1234%tap0`) and works. `avahi-browse` works because avahi sets the multicast interface per socket.

## Reproduction
On a host with a default route:
```
$ ip route get 224.0.0.251
multicast 224.0.0.251 dev enp10s0 src 10.22.0.20 ... cache <local,mc>
```
`enp10s0` holds the default route. Only hosts with no default or multicast route elsewhere are unaffected.

## Suggested fix
Use `socat - UDP4-DATAGRAM:224.0.0.251:5353,bind=:5353,ip-multicast-if=192.168.69.100`, or document `sudo ip route add 224.0.0.0/4 dev tap0`.
