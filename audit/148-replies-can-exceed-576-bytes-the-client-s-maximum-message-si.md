# 148. Replies can exceed 576 bytes: the client's maximum message size option is ignored

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/iface/dhcpv4_server.rs:675](../src/iface/dhcpv4_server.rs#L675) |
| Features | dhcpv4-server |
| Verification | confirmed against the code |

## Summary
`build_reply` gives the options writer the whole packet buffer and never reads option 57. With more than about 300 bytes of user `outgoing_options`, an OFFER/ACK grows past 576 bytes, the only size a client must accept unless it negotiated more. The default configuration stays well under 576 bytes.

## Details
src/iface/dhcpv4_server.rs:675:
```rust
buf.set_len(buf.tailroom());
```
Options are then written up to the whole buffer, ending in `unwrap!(result, "DHCP reply does not fit in a packet")`. `OPT_MAX_DHCP_MESSAGE_SIZE` appears only in the client emit code in src/wire/dhcpv4.rs.

## Failure scenario
The user adds classless routes and a domain search list, about 350 bytes. A minimal client that accepts only 576-byte messages drops the OFFER and is never configured.

## RFC reference
RFC 2131 §2: "A DHCP client must be prepared to receive DHCP messages with an 'options' field of at least length 312 octets. This requirement implies that a DHCP client must be prepared to receive a message of up to 576 octets ... DHCP clients may negotiate the use of larger DHCP messages through the 'maximum DHCP message size' option."

RFC 2132 §9.10: "This option specifies the maximum length DHCP message that it is willing to accept."

## Suggested fix
Limit the reply to min(buffer, client's option 57, 576 if absent). When configured options don't fit, drop optional ones instead of building an oversized message or panicking.
