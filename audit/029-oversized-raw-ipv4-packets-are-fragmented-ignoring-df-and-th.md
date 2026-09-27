# 029. Oversized raw IPv4 packets are fragmented ignoring DF, and the sender's ident, MF and fragment offset are overwritten

| | |
|---|---|
| Severity | medium |
| Category | rfc-compliance |
| Location | [src/fragmentation.rs:282](../src/fragmentation.rs#L282), [src/fragmentation.rs:213](../src/fragmentation.rs#L213), [src/stack.rs:2670](../src/stack.rs#L2670), [src/raw.rs:612](../src/raw.rs#L612), [README.md:110](../README.md#L110) |
| Features | `raw-ip`, `ipv4-fragmentation` (default) |
| Verification | reproduced with a test |

## Summary

A raw IP packet larger than the interface's IP MTU goes to the IPv4 fragmenter. The fragmenter clears DF, replaces the ident with the stack's counter, and numbers fragments from offset 0 with MF clear on the last one. So a DF packet is fragmented anyway, contrary to RFC 791, and a packet that is already a fragment gets wrong offsets and MF. `send_slice` returns `Ok` in both cases. This contradicts the README claim that raw IP headers keep all fields.

## Details

src/raw.rs:586-612, IP mode: validate, route, `can_transmit`, `transmit_raw_ip`. Nothing compares the length with `route.ip_mtu` or reads DF, MF or the offset.

src/stack.rs:2670-2674, `transmit_ip` fragments any oversized IPv4 packet without a DF check:

```rust
if total_ip_len > iface.ip_mtu() {
    match ethertype {
        #[cfg(feature = "ipv4-fragmentation")]
        EthernetProtocol::Ipv4 => self.fragment_ipv4(iface, dst_addr, next_hop, buf),
```

src/fragmentation.rs:213-214, `fragment_ipv4`:

```rust
frag.ipv4.ident = ipv4_id;
frag.ipv4.frag_offset = 0;
```

src/fragmentation.rs:274-283, `dispatch_ipv4_frag`:

```rust
tx_buffer[..ip_header_len].copy_from_slice(&buffer[..ip_header_len]);
...
packet.set_ident(frag.ipv4.ident);
packet.set_more_frags(more_frags);
packet.set_dont_frag(false);
packet.set_frag_offset(frag.ipv4.frag_offset);
```

The original offset and MF are never carried forward. The whole header is copied into every fragment, so options with the copied flag at 0 are replicated too.

README.md:110: "IP headers are byte-copied instead of parsed+re-emitted, so all fields and options are kept". The `send_with` docs ([src/raw.rs:484-486](../src/raw.rs#L484)) say the packet "is routed like any other egress packet" and say nothing about fragmentation.

The stack's own packets set DF in `push_ipv4_header` ([src/stack.rs:2805](../src/stack.rs#L2805)) and are also fragmented with DF cleared. That is allowed: a host may fragment its own datagrams. Only the raw path is a defect here. The DF-without-PMTUD problem is finding 030.

## Failure scenario

- A raw-socket PMTU prober sends a 1400-byte DF packet over a 1280-MTU interface. It expects a refusal. The packet leaves as DF-clear fragments with a new ident, `send_slice` returns `Ok`, and the probe concludes 1400 bytes fit.
- A raw sender relays a fragment (MF=1, offset 1480) larger than the local MTU. It goes out as fragments at offset 0 with MF=0 on the last one. The receiver reassembles garbage.

## RFC reference

RFC 791 §3.2:

> If the Don't Fragment flag (DF) bit is set, then internet fragmentation of this datagram is NOT permitted, although it may be discarded.

Fragmentation procedure: "IF TL =< MTU THEN Submit ... ELSE IF DF = 1 THEN discard the datagram", "(2) OIHL <- IHL; OTL <- TL; OFO <- FO; OMF <- MF;", "(7) Selectively copy the internet header (some options are not copied, see option definitions)", "FO <- OFO + NFB;  MF <- OMF".

RFC 791 §3.1: "The copied flag indicates that this option is copied into all fragments on fragmentation. 0 = not copied".

## Reproduction

Added to `src/stack.rs` `mod test` in a scratch copy of HEAD:

```rust
#[test]
fn verif_raw_df_fragmented() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ip, 1000);
    let handle = stack.add_raw_socket().unwrap();
    stack.raw_socket(handle).bind(RawMode::Ip { version: Some(IpVersion::V4), protocol: None }).unwrap();
    let mut pkt = ipv4_packet(OUR_V4, REMOTE_V4, IpProtocol::Udp, &[0xab; 1480]);
    { let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]); ip.set_ident(0x4242); ip.set_dont_frag(true); ip.fill_checksum(); }
    println!("send DF: {:?}", stack.raw_socket(handle).send_slice(&pkt));
    stack.poll(Instant::ZERO);
    for f in tx.borrow().iter() { let mut f = f.clone(); let ip = Ipv4Packet::new_checked(&mut f[..]).unwrap();
        println!("DF case: len {} df {} mf {} off {} ident {:#x}", ip.total_len(), ip.dont_frag(), ip.more_frags(), ip.frag_offset(), ip.ident()); }
    tx.borrow_mut().clear();
    let mut pkt = ipv4_packet(OUR_V4, REMOTE_V4, IpProtocol::Udp, &[0xab; 1480]);
    { let mut ip = Ipv4Packet::new_unchecked(&mut pkt[..]); ip.set_ident(0x4343); ip.set_more_frags(true); ip.set_frag_offset(1480); ip.fill_checksum(); }
    println!("send frag: {:?}", stack.raw_socket(handle).send_slice(&pkt));
    stack.poll(Instant::ZERO);
    for f in tx.borrow().iter() { /* same print as above, prefixed "frag case" */ }
}
```

`cargo test --lib verif_raw_df_fragmented -- --nocapture`:

```
send DF: Ok(())
DF case: len 996 df false mf true off 0 ident 0x826
DF case: len 524 df false mf false off 976 ident 0x826
send frag: Ok(())
frag case: len 996 df false mf true off 0 ident 0x827
frag case: len 524 df false mf false off 976 ident 0x827
```

## Suggested fix

In the raw IP send path, reject a packet larger than `route.ip_mtu` when DF is set or when MF/offset is already set (a new `PacketTooLarge` error, or an existing one). Or make the fragmenter honor DF, carry OFO/OMF forward, and drop non-copied options after the first fragment. Document the behavior in the README and the `send_with` docs.
