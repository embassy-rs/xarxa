# xarxa audit

Audit of `xarxa` and `xarxa-driver` at commit `b5254a66` (2026-09-26). One file per finding. No code was changed. Line numbers in the findings refer to that commit.

## Counts

| Severity | Findings |
|---|---|
| critical | 3 |
| high | 17 |
| medium | 83 |
| low | 229 |
| info | 31 |
| **total** | **363** |

| Verification | Findings |
|---|---|
| test | 199 |
| code | 111 |
| RFC text | 49 |
| code + RFC text | 1 |
| plausible | 3 |

- **test**: a verifier reproduced it with a unit test in a scratch copy of the crate. The test and its output are in the file.
- **code**: confirmed by tracing the code paths, no test.
- **RFC text**: the RFC's normative text is quoted next to the code that violates it.
- **plausible**: likely real, not demonstrated.

## How it was done

- 41 auditors in parallel: one per subsystem (TCP split five ways, stack ingress/egress, iface, neighbor, routes, UDP, raw, multicast, DHCP client and server, SLAAC, DNS/mDNS, 6LoWPAN, fragmentation, wire, driver crate), one per cross-cutting concern (timers and deadlines, wakers, pool and backpressure, panics from network input, security, public docs, multiple interfaces, feature combinations), three RFC checklists (RFC 1122 summary tables, RFC 9293 Appendix B, IPv6 host requirements), and a fuzzing run of the whole stack with the harness from `worktree-fuzz`, ported to this commit.
- A completeness critic then picked 8 follow-up hunts: TCP soak tests, Linux interop, stale `now` between polls, checksum offload, config changes under live traffic, hot-path performance, examples and 802.15.4 docs, and a second fuzzing run (stopped early, its confirmed leads were kept).
- 663 raw reports, merged into 367 unique findings.
- Each finding was checked by a verifier that tried to reproduce it with a test, or quoted the RFC or doc text against the code. Critical and high findings without a test, medium findings that were only plausible, and refuted high findings got a second, skeptical verifier, and a judge on disagreement.
- 363 kept, 4 dropped (listed at the end).

Caveat: to fit the usage budget, verification was batched and most findings had a single verifier. The confirm rate was very high (363 of 367). Findings marked **code** or **RFC text** were not demonstrated with a test. Low and info findings were checked with less effort than the rest.

## Findings

### Critical (3)

| # | Finding | Category | Location | Verified by |
|---|---|---|---|---|
| 001 | [TCP: SYN-SENT socket panics in last_scaled_window (SeqNumber underflow) when the handshake completes with remote_last_win == 0](001-tcp-syn-sent-socket-panics-seqnumber-underflow-in-last-scale.md) | panic | `src/tcp/mod.rs:697` | test |
| 002 | [TCP: unscaled SYN/SYN\|ACK window is stored in remote_last_win and later left-shifted, so a peer can overrun the RX ring and panic the stack (RX buffers > 65535 bytes)](002-syn-syn-ack-window-is-recorded-unscaled-but-later-left-shift.md) | panic | `src/tcp/mod.rs:1092` | test |
| 003 | [TCP: FIN on a segment trimmed at the right window edge is still processed: stream truncated, unreceived data ACKed, clean EOF reported](003-fin-on-a-segment-that-was-trimmed-at-the-right-window-edge-i.md) | correctness | `src/tcp/mod.rs:1236` | test |

### High (17)

| # | Finding | Category | Location | Verified by |
|---|---|---|---|---|
| 004 | [Pending-queue default is still 16, the whole default packet pool: d2d95301 changed gen_config.py but the generated files were never regenerated](004-pending-queue-default-is-still-16-whole-default-packet-pool-.md) | security | `build.rs:16` | test |
| 005 | [With `alloc` (default), SLAAC prefix and router tables, interface addresses and routes grow without limit from Router Advertisements](005-with-alloc-on-by-default-slaac-prefix-router-tables-interfac.md) | security | `src/iface/slaac.rs:157` | test |
| 006 | [UDP/raw datagram sent between polls to an unresolved neighbor is dropped at the next poll](006-udp-raw-datagram-sent-between-polls-to-an-unresolved-neighbo.md) | correctness | `src/neighbor.rs:492` | test |
| 007 | [Pending queue can hold every pool buffer by default, so the ARP/NA reply that would drain it cannot be received](007-pending-queue-can-hold-every-pool-buffer-by-default-so-the-a.md) | hang-stall | `src/neighbor.rs:492` | test |
| 008 | [The shared PRNG gives away its whole state after two outputs, so TCP ISNs, ephemeral ports, DNS txids and DHCP xids are predictable](008-the-shared-prng-gives-away-its-whole-state-after-two-outputs.md) | security | `src/rand.rs:23` | test |
| 009 | [A failed or late 6LoWPAN fragment pins the only reassembly slot for 60 s](009-a-failed-or-late-6lowpan-fragment-pins-the-only-reassembly-s.md) | hang-stall | `src/sixlowpan.rs:682` | test |
| 010 | [IPv4 packet fragmented on an IEEE 802.15.4 interface leaves IPv4 state in the fragmenter, and sixlowpan_egress then sends empty FRAGN frames forever](010-ipv4-packet-fragmented-on-an-ieee-802-15-4-interface-leaves-.md) | hang-stall | `src/stack.rs:2670` | test |
| 011 | [About 16 spoofed on-link pings (or UDP packets to closed ports) fill the whole packet pool for 3 to 5 s](011-about-16-spoofed-on-link-pings-or-udp-packets-to-closed-port.md) | security | `src/stack.rs:2714` | test |
| 012 | [IPv4 DF is set on every packet but Fragmentation Needed is ignored, so paths with a smaller MTU black-hole traffic](012-ipv4-df-is-set-on-every-packet-but-fragmentation-needed-is-i.md) | hang-stall | `src/stack.rs:2805` | RFC text |
| 013 | [TCP accepts segments addressed to broadcast/multicast: listeners record them, accepted sockets hang in SYN-RECEIVED, and RSTs go out with a broadcast source](013-tcp-listeners-accept-syns-addressed-to-broadcast-multicast-m.md) | rfc-compliance | `src/stack.rs:1483` | test |
| 014 | [ISNs are raw output of a non-cryptographic PRNG: no clock component (MUST-8), and the state is recoverable from two observed ISNs (MUST-9)](014-isns-are-pure-prng-output-no-clock-component-must-8-and-the-.md) | security | `src/tcp/mod.rs:782` | test |
| 015 | [ACKs covering data that was never sent are accepted and dequeue it from the TX buffer](015-acks-covering-data-that-was-never-sent-are-accepted-and-dequ.md) | correctness | `src/tcp/mod.rs:1056` | test |
| 016 | [No default retransmission limit: SYN-SENT, SYN-RECEIVED and data retransmissions go on forever](016-no-default-connection-timeout-syn-sent-and-syn-received-retr.md) | hang-stall | `src/tcp/mod.rs:1630` | test |
| 017 | [After an RTO rewind, pure ACKs and RSTs carry the rewound SND.NXT, so a bidirectional connection where both sides time out hangs forever](017-after-an-rto-rewind-pure-acks-and-rsts-carry-the-rewound-snd.md) | hang-stall | `src/tcp/mod.rs:1851` | test |
| 018 | [The zero-window probe byte is not counted as sent, so when both ends probe at once each drops the other's ACKs and window updates, with no loss](018-the-zero-window-probe-byte-is-not-counted-as-sent-when-both-.md) | hang-stall | `src/tcp/mod.rs:2048` | test |
| 019 | [TIME-WAIT expiry calls reset(), discarding received and ACKed data the application has not read](019-time-wait-expiry-calls-reset-wiping-received-but-unread-data.md) | correctness | `src/tcp/mod.rs:2094` | test |
| 020 | [close() in SYN-RECEIVED drops the SYN from sequence space: no SYN\|ACK retransmission, no FIN, and the ACK of the SYN is taken as the ACK of the FIN](020-close-in-syn-received-never-re-sends-the-syn-ack-emits-a-bar.md) | correctness | `src/tcp/mod.rs:2660` | test |

### Medium (83)

| # | Finding | Category | Location | Verified by |
|---|---|---|---|---|
| 021 | [`DnsClient::poll` docs say to call it again at its deadline, but it uses the last `Stack::poll` time, so doing only that busy-loops](021-dnsclient-poll-docs-say-to-call-it-again-at-its-deadline-but.md) | hang-stall | `src/dns.rs:349` | test |
| 022 | [`DnsClient` accepts any packet from source port 5353, from any address and for every query](022-dnsclient-accepts-any-packet-from-source-port-5353-from-any-.md) | security | `src/dns.rs:363` | test |
| 023 | [SERVFAIL/REFUSED/FORMERR from the first server fails the whole query instead of trying the next server](023-servfail-refused-formerr-from-the-first-server-fails-the-who.md) | correctness | `src/dns.rs:507` | test |
| 024 | [mDNS one-shot queries use the 10 s unicast timeout per address family, IPv6 first](024-mdns-one-shot-queries-use-the-10-s-unicast-timeout-per-addre.md) | performance | `src/dns.rs:536` | test |
| 025 | [A permanent send error or an unspecified server address fails the query without trying the next server](025-a-permanent-send-error-or-an-unspecified-server-address-fail.md) | correctness | `src/dns.rs:617` | test |
| 026 | [DNS names are compared case-sensitively, so an answer whose name differs only in case fails the query](026-dns-names-are-compared-case-sensitively-so-a-response-whose-.md) | rfc-compliance | `src/dns.rs:642` | test |
| 027 | [TunTapDriver and RawSocketDriver panic on routine OS errors (interface down)](027-tuntapdriver-and-rawsocketdriver-panic-on-routine-os-errors-.md) | panic | `src/driver_impls/raw_socket.rs:214` | test |
| 028 | [IPv4 fragmentation sends a zero UDP/ICMP checksum when the egress device claims tx checksum offload](028-ipv4-fragmentation-sends-a-zero-l4-checksum-when-the-egress-.md) | correctness | `src/fragmentation.rs:274` | test |
| 029 | [Oversized raw IPv4 packets are fragmented ignoring DF, and the sender's ident, MF and fragment offset are overwritten](029-oversized-raw-ipv4-packets-are-fragmented-ignoring-df-and-th.md) | rfc-compliance | `src/fragmentation.rs:282` | test |
| 030 | [No PMTU reaction to ICMP Fragmentation Needed / ICMPv6 Packet Too Big, while DF is always set (TCP black holes)](030-no-pmtu-reaction-to-icmp-fragmentation-needed-icmpv6-packet-.md) | rfc-compliance | `src/icmp_error.rs:33` | test |
| 031 | [ICMP Source Quench is delivered to TCP and aborts connections in SYN-SENT/SYN-RECEIVED](031-icmp-source-quench-is-delivered-to-tcp-and-aborts-connection.md) | rfc-compliance | `src/icmp_error.rs:36` | test |
| 032 | [A stale record makes the DHCP server NAK a client's valid lease from another server (INIT-REBOOT and REBINDING)](032-a-stale-record-makes-the-server-nak-a-client-s-valid-lease-f.md) | rfc-compliance | `src/iface/dhcpv4_server.rs:567` | test |
| 033 | [DHCP `outgoing_options` that do not fit panic, and for the server any received DISCOVER or REQUEST triggers it](033-dhcp-outgoing-options-that-do-not-fit-panic-and-for-the-serv.md) | panic | `src/iface/dhcpv4_server.rs:737` | test |
| 034 | [DHCPv4 client retransmits without randomization or exponential backoff, and restarts discovery instantly](034-dhcpv4-client-retransmits-without-randomization-or-exponenti.md) | rfc-compliance | `src/iface/dhcpv4.rs:714` | test |
| 035 | [`Iface::set_hardware_addr` leaves SLAAC addresses formed from the old MAC assigned forever](035-iface-set-hardware-addr-leaves-slaac-addresses-formed-from-t.md) | correctness | `src/iface/mod.rs:345` | test |
| 036 | [set_ip_addrs / remove_ip_addr drop the DHCPv4 lease address, and renewals never put it back](036-set-ip-addrs-remove-ip-addr-silently-remove-the-dhcpv4-lease.md) | correctness | `src/iface/mod.rs:431` | test |
| 037 | [IPv6 source selection falls back to ::1 when the interface has no IPv6 address](037-ipv6-source-selection-falls-back-to-1-when-the-interface-has.md) | rfc-compliance | `src/iface/mod.rs:1067` | test |
| 038 | [RFC 4862 two-hour rule not implemented: one spoofed RA with a zero or short valid lifetime removes SLAAC addresses](038-rfc-4862-5-5-3-e-two-hour-rule-not-implemented-one-unauthent.md) | rfc-compliance | `src/iface/slaac.rs:253` | test |
| 039 | [No IPv6 path MTU handling: RA MTU option and Packet Too Big are ignored, and full-size packets go off-link](039-no-ipv6-path-mtu-handling-ra-mtu-option-and-packet-too-big-a.md) | rfc-compliance | `src/iface/slaac.rs:389` | RFC text |
| 040 | [RA fields Cur Hop Limit, Reachable Time, Retrans Timer and the MTU option are ignored](040-ra-fields-cur-hop-limit-reachable-time-retrans-timer-and-the.md) | rfc-compliance | `src/iface/slaac.rs:397` | RFC text |
| 041 | [SLAAC address is installed as a /64, so an A=1/L=0 prefix becomes on-link](041-slaac-address-is-installed-as-a-64-on-the-interface-so-an-a-.md) | rfc-compliance | `src/iface/slaac.rs:253` | test |
| 042 | [IGMP and MLDv2 join/leave reports are sent once, and a join is lost for good if the pool is empty](042-no-retransmission-of-igmp-unsolicited-reports-or-mldv2-state.md) | rfc-compliance | `src/multicast.rs:271` | test |
| 043 | [No IGMPv1 Router Present state: joins always go out as v2 and leaves are still sent](043-igmpv1-querier-compatibility-no-version-1-router-present-sta.md) | rfc-compliance | `src/multicast.rs:446` | test |
| 044 | [IGMP messages are sent without the IP Router Alert option](044-igmp-messages-are-sent-without-the-ip-router-alert-option.md) | rfc-compliance | `src/multicast.rs:515` | test |
| 045 | [One report slot per protocol: a group-specific query cancels a pending general-query response](045-one-report-slot-per-protocol-a-group-specific-query-cancels-.md) | correctness | `src/multicast.rs:584` | test |
| 046 | [NeighborCache::insert accepts a hardware address of the wrong medium, and the next send to that neighbor panics](046-neighborcache-insert-accepts-a-hardware-address-of-the-wrong.md) | panic | `src/neighbor.rs:355` | test |
| 047 | [Neighbor cache eviction defeats per-neighbor solicitation rate limiting](047-cache-eviction-thrash-defeats-per-neighbor-solicitation-rate.md) | rfc-compliance | `src/neighbor.rs:422` | test |
| 048 | [Global drop-head pending queue drops another neighbor's only parked packet](048-global-drop-head-pending-queue-drops-another-neighbor-s-only.md) | rfc-compliance | `src/neighbor.rs:498` | test |
| 049 | [packet-log recursion over nested ICMP errors lets one crafted packet use tens of KB of stack](049-packet-log-recursion-over-nested-icmp-errors-lets-one-crafte.md) | panic | `src/packet_log.rs:702` | test |
| 050 | [Raw-socket packets carry user checksums, but the driver contract lets the device's tx offload rewrite them: raw ICMPv4 pings break on the stm32 MAC](050-raw-socket-packets-carry-user-computed-checksums-but-the-dev.md) | api | `src/raw.rs:484` | code |
| 051 | [Single reassembly slot with no eviction: one stray fragment blocks all IPv4/6LoWPAN reassembly for 60 s](051-single-reassembly-slot-with-no-eviction-a-lost-spoofed-overs.md) | hang-stall | `src/reassembly.rs:179` | test |
| 052 | [No ICMP Time Exceeded is sent when IPv4 reassembly times out](052-no-icmp-time-exceeded-fragment-reassembly-time-exceeded-is-s.md) | rfc-compliance | `src/reassembly.rs:197` | RFC text |
| 053 | [Routes via a gateway outside the interface's subnets are accepted but never resolve](053-routes-via-a-gateway-outside-the-interface-s-subnets-are-acc.md) | correctness | `src/route.rs:154` | test |
| 054 | [Routes::add accepts a gateway of the other IP family, which panics on 802.15.4](054-routes-add-accepts-a-gateway-of-the-other-ip-family-on-802-1.md) | panic | `src/route.rs:154` | test |
| 055 | [Among equal-prefix routes, lookup always picks the last one and never fails over](055-among-equal-prefix-routes-several-default-routers-lookup-alw.md) | rfc-compliance | `src/route.rs:304` | test |
| 056 | [IEEE 802.15.4 ingress never checks the frame's destination address](056-ieee-802-15-4-ingress-never-checks-the-frame-s-destination-a.md) | correctness | `src/sixlowpan.rs:138` | test |
| 057 | [6LoWPAN drops IPv6 Traffic Class and Flow Label in both directions](057-6lowpan-drops-ipv6-traffic-class-and-flow-label-in-both-dire.md) | correctness | `src/sixlowpan.rs:334` | test |
| 058 | [Elided UDP checksums (NHC C=1) are accepted with no integrity check, and a computed zero checksum is written as 0](058-elided-udp-checksums-nhc-c-1-are-accepted-with-no-integrity-.md) | rfc-compliance | `src/sixlowpan.rs:366` | test |
| 059 | [Loopback and node-local destinations (127/8, ::1, ff00::/16, ff01::/16) are sent onto the wire](059-loopback-and-node-local-destinations-127-8-1-ff00-16-ff01-16.md) | rfc-compliance | `src/stack.rs:346` | test |
| 060 | [TCP and UDP traffic to an IPv6 link-local peer always goes out the first interface](060-tcp-and-udp-traffic-to-an-ipv6-link-local-peer-always-goes-o.md) | correctness | `src/stack.rs:364` | test |
| 061 | [On-link determination uses assigned address prefixes and ignores the RA on-link (L) flag](061-on-link-determination-uses-assigned-address-prefixes-ignorin.md) | rfc-compliance | `src/stack.rs:364` | RFC text |
| 062 | [TX timestamp waiters can hang: nothing wakes the poll task or schedules a deadline when a transmit timestamp becomes ready](062-tx-timestamp-waker-can-hang-nothing-makes-a-driver-wake-the-.md) | missed-wake | `src/stack.rs:1081` | code |
| 063 | [Ingress drain in poll is unbounded: a sustained packet flood keeps poll from returning](063-ingress-drain-in-poll-is-unbounded-a-sustained-packet-flood-.md) | hang-stall | `src/stack.rs:1093` | test |
| 064 | [Loopback and Class E IPv4 source addresses are accepted from the wire and answered](064-loopback-and-class-e-source-addresses-accepted-from-the-wire.md) | security | `src/stack.rs:1388` | test |
| 065 | [Raw socket handling UDP or TCP in a build without that feature still triggers Protocol Unreachable / Parameter Problem](065-raw-socket-handling-tcp-or-udp-in-a-build-without-that-featu.md) | correctness | `src/stack.rs:1425` | test |
| 066 | [TCP segments to broadcast/multicast destinations are processed and answered with an RST sourced from that address](066-tcp-segments-to-broadcast-multicast-destinations-are-process.md) | rfc-compliance | `src/stack.rs:1538` | test |
| 067 | [Incoming ICMP errors are not checked against traffic we could have sent: spoofed errors make wildcard UDP recv() fail](067-incoming-icmp-errors-are-not-validated-against-traffic-we-se.md) | security | `src/stack.rs:1655` | test |
| 068 | [Neighbor solicitations from :: (DAD probes) are dropped, so the stack never defends its addresses](068-neighbor-solicitations-with-an-unspecified-source-dad-probes.md) | rfc-compliance | `src/stack.rs:1689` | test |
| 069 | [IPv6 ingress accepts ::1 as destination and source from any link, and replies from ::1 on the wire; IPv4 accepts 127/8 sources](069-ipv6-ingress-accepts-the-loopback-address-1-as-destination-a.md) | security | `src/stack.rs:1699` | test |
| 070 | [Destination Options, Routing (Segments Left 0), No Next Header and atomic fragments are answered with "unrecognized next header"](070-destination-options-routing-segments-left-0-no-next-header-a.md) | rfc-compliance | `src/stack.rs:1767` | test |
| 071 | [ICMP errors are sent in reply to link-layer broadcast and multicast frames](071-icmp-errors-are-sent-in-reply-to-link-layer-broadcast-multic.md) | rfc-compliance | `src/stack.rs:1245` | test |
| 072 | [No rate limiting of originated ICMPv6 error messages](072-no-rate-limiting-of-originated-icmpv6-error-messages.md) | rfc-compliance | `src/stack.rs:2090` | test |
| 073 | [ARP from senders outside the interface's prefixes is dropped, so an off-prefix gateway never resolves](073-arp-replies-and-requests-from-addresses-outside-our-prefixes.md) | correctness | `src/stack.rs:2206` | test |
| 074 | [UDP and raw sends larger than the egress IP MTU return Ok but are silently dropped](074-udp-and-raw-sends-larger-than-the-egress-ip-mtu-return-ok-bu.md) | doc-mismatch | `src/stack.rs:2670` | test |
| 075 | [Initial cwnd is a fixed 2048 bytes: one segment with MSS 1460, and more than 4 segments with MSS below 512](075-initial-cwnd-is-a-fixed-2048-bytes-one-segment-with-mss-1460.md) | performance | `src/tcp/congestion/cubic.rs:39` | test |
| 076 | [CUBIC computes K with the RFC 8312 formula and starts t at the loss, so app-limited flows regrow at 0.5 SMSS per ACK after a loss](076-cubic-uses-the-rfc-8312-k-formula-and-starts-t-at-loss-time-.md) | rfc-compliance | `src/tcp/congestion/cubic.rs:57` | test |
| 077 | [The CUBIC increment `(target - cwnd) * segment` overflows usize on 32-bit targets](077-the-cubic-increment-target-cwnd-segment-overflows-usize-on-3.md) | panic | `src/tcp/congestion/cubic.rs:167` | test |
| 078 | [ack_reply marks the ACK and window as sent before the reply is transmitted, so a dropped immediate ACK is never retried](078-ack-reply-marks-the-ack-and-window-as-sent-even-when-the-imm.md) | hang-stall | `src/tcp/mod.rs:883` | test |
| 079 | [SYN in a synchronized state is silently dropped: no challenge ACK and no RST, so half-open connections never recover](079-syn-in-a-synchronized-state-is-silently-dropped-no-challenge.md) | rfc-compliance | `src/tcp/mod.rs:1039` | test |
| 080 | [Window scale rounding retracts the advertised right edge, and data that was in window for an earlier ACK is trimmed (RFC 7323 §2.4 MUST)](080-window-scaling-rounding-retracts-the-advertised-right-edge-a.md) | rfc-compliance | `src/tcp/mod.rs:1091` | test |
| 081 | [A FIN that arrives out of order is thrown away and never remembered, so the connection only closes after the peer retransmits the FIN](081-a-fin-that-arrives-out-of-order-is-thrown-away-and-never-rem.md) | rfc-compliance | `src/tcp/mod.rs:1236` | test |
| 082 | [In-window RST with a non-exact sequence number resets the connection (RFC 5961 §3 only half implemented)](082-in-window-rst-with-a-non-exact-sequence-number-resets-the-co.md) | security | `src/tcp/mod.rs:1247` | test |
| 083 | [Congestion control uses the peer's MSS option (or its own 1024 default) as SMSS, not the real segment size](083-congestion-control-uses-the-peer-s-mss-option-or-its-own-102.md) | rfc-compliance | `src/tcp/mod.rs:1280` | test |
| 084 | [Segment text after the peer's FIN is accepted in CLOSE-WAIT, CLOSING and LAST-ACK and delivered to the application](084-segment-text-after-the-peer-s-fin-is-accepted-in-close-wait-.md) | correctness | `src/tcp/mod.rs:1357` | test |
| 085 | [LAST-ACK returns early on any ACK that doesn't advance SND.UNA, dropping window updates and duplicate ACKs](085-last-ack-returns-early-on-any-ack-that-doesn-t-advance-snd-u.md) | hang-stall | `src/tcp/mod.rs:1365` | test |
| 086 | [No Limited Transmit and no partial-ACK retransmission, so small windows and multiple losses per window fall back to an RTO](086-no-limited-transmit-and-no-partial-ack-newreno-retransmissio.md) | performance | `src/tcp/mod.rs:1442` | code + RFC text |
| 087 | [Partial ACK with a zero window replaces the retransmit timer, and in-flight data is never resent after the window reopens](087-partial-ack-with-a-zero-window-replaces-the-retransmit-timer.md) | hang-stall | `src/tcp/mod.rs:1509` | test |
| 088 | [After close(), FIN-WAIT-2 never times out, even with a timeout set](088-after-close-fin-wait-2-never-times-out-even-with-a-timeout-s.md) | hang-stall | `src/tcp/mod.rs:1618` | test |
| 089 | [No receiver SWS avoidance: reading 1 byte from a full buffer advertises a 1-byte window](089-receiver-sws-avoidance-missing-reading-1-byte-from-a-full-bu.md) | performance | `src/tcp/mod.rs:1687` | test |
| 090 | [TCP stalls forever after the peer shrinks its window to zero: an RTO or the end of zero-window probing leaves in-flight data with no timer](090-tcp-stalls-forever-after-the-peer-shrinks-its-window-to-zero.md) | hang-stall | `src/tcp/mod.rs:1869` | test |
| 091 | [Fast retransmit with only a FIN in flight disarms the retransmit timer, and the FIN is never retransmitted](091-fast-retransmit-with-only-a-fin-in-flight-disarms-the-retran.md) | hang-stall | `src/tcp/mod.rs:2012` | test |
| 092 | [Sender SWS avoidance missing: window-limited sub-MSS segments are sent whenever nothing is in flight](092-sender-sws-avoidance-missing-window-limited-sub-mss-segments.md) | rfc-compliance | `src/tcp/mod.rs:2033` | test |
| 093 | [connect()/accept() on a socket in TIME-WAIT discard TIME-WAIT, including for the identical 4-tuple](093-connect-accept-on-a-socket-in-time-wait-silently-discard-tim.md) | rfc-compliance | `src/tcp/mod.rs:2549` | test |
| 094 | [TcpSocket::connect allows broadcast and multicast remote addresses and sends SYNs to them](094-tcpsocket-connect-allows-broadcast-and-multicast-remote-addr.md) | rfc-compliance | `src/tcp/mod.rs:2552` | test |
| 095 | [TcpSocket::connect accepts a concrete local address of the other family, not ours, or with no route, and the socket sits in SYN-SENT forever sending nothing](095-tcpsocket-connect-accepts-a-concrete-local-address-of-the-ot.md) | correctness | `src/tcp/mod.rs:2561` | test |
| 096 | [TcpSocket::accept does not check for an existing socket with the same 4-tuple, so a retransmitted SYN yields a duplicate socket stuck in SYN-RECEIVED](096-tcpsocket-accept-does-not-check-for-an-existing-socket-with-.md) | hang-stall | `src/tcp/mod.rs:2633` | test |
| 097 | [UDP receive metadata gives the raw broadcast/multicast destination, not the specific-destination address or arrival interface, so replying with it fails](097-udp-receive-metadata-gives-the-raw-broadcast-multicast-desti.md) | rfc-compliance | `src/udp.rs:355` | test |
| 098 | [UDP and raw sends bigger than the egress interface's IP MTU (IPv6, or IPv4 without fragmentation) return Ok and are dropped silently](098-udp-and-raw-sends-bigger-than-the-egress-interface-s-ip-mtu-.md) | correctness | `src/udp.rs:919` | test |
| 099 | [Reassembled datagrams skip L4 checksum verification when the arrival device claims rx offload, although the hardware cannot verify fragments](099-reassembled-datagrams-skip-l4-checksum-verification-when-the.md) | rfc-compliance | `src/udp.rs:994` | test |
| 100 | [No ICMPv6 error rate limiting: every datagram to a closed UDP port triggers a Port Unreachable](100-no-icmpv6-error-rate-limiting-every-datagram-to-a-closed-udp.md) | rfc-compliance | `src/stack.rs:2090` | RFC text |
| 101 | [MLDv1 queries are dropped as malformed: no MLDv1 host compatibility mode](101-mldv1-queries-are-dropped-as-malformed-no-mldv1-host-compati.md) | rfc-compliance | `src/wire/icmpv6.rs:296` | test |
| 102 | [IGMPv2 queries have their Max Resp Time decoded with the IGMPv3 floating-point encoding, so reports come late or never](102-igmpv2-queries-have-their-max-resp-time-decoded-with-the-igm.md) | rfc-compliance | `src/wire/igmp.rs:169` | test |
| 103 | [PacketBuf::set_len overflow check wraps in release builds, so safe code can break the headroom+len invariant (UB)](103-packetbuf-set-len-overflow-check-wraps-in-release-builds-so-.md) | correctness | `xarxa-driver/src/buf.rs:321` | test |

### Low (229)

| # | Finding | Category | Location | Verified by |
|---|---|---|---|---|
| 104 | [Cargo feature docs invite enabling tcp-reno or defmt, but both fail to compile with the default features](104-cargo-feature-docs-invite-enabling-tcp-reno-or-defmt-but-bot.md) | doc-mismatch | `Cargo.toml:141` | code |
| 105 | [9 of 10 examples do not build with their declared required-features: `alloc` is missing](105-9-of-10-examples-do-not-build-with-their-declared-required-f.md) | feature-gating | `Cargo.toml:528` | test |
| 106 | [multicast example: the documented socat command sends out the host's default-route interface, not tap0](106-multicast-example-the-documented-socat-command-sends-out-the.md) | doc-mismatch | `examples/multicast.rs:16` | test |
| 107 | [tcp_client example breaks the poll contract: the greeting and the FIN are queued after poll and sit until the next deadline (up to a day)](107-tcp-client-example-breaks-the-poll-contract-the-greeting-and.md) | hang-stall | `examples/tcp_client.rs:86` | test |
| 108 | [Example main loop: packets taken in by the loop's second poll are not handled until the next wake-up](108-example-main-loop-packets-taken-in-by-the-loop-s-second-poll.md) | doc-mismatch | `examples/tcp_server.rs:115` | code |
| 109 | [Example run instructions omit creating the TAP/TUN device: `cargo run` as a normal user panics with EPERM](109-example-run-instructions-omit-creating-the-tap-tun-device-ca.md) | doc-mismatch | `examples/tuntap.rs:7` | code |
| 110 | [UDP echo examples panic on routine network input: send_slice(...).unwrap() fails for a datagram from source port 0 or from an unroutable source](110-udp-echo-examples-panic-on-routine-network-input-send-slice-.md) | panic | `examples/tuntap.rs:78` | code |
| 111 | [README says "No `unsafe`" but the packet buffer and the no-alloc slab use unsafe code](111-readme-says-no-unsafe-but-the-packet-buffer-and-the-no-alloc.md) | doc-mismatch | `README.md:15` | code |
| 112 | [README says the neighbor cache has "renewal on use", but sending never renews an entry](112-readme-feature-list-says-the-neighbor-cache-has-renewal-on-u.md) | doc-mismatch | `README.md:79` | code |
| 113 | [README and DESIGN say DHCP/SLAAC are not restarted on link-up, but Stack::poll does it](113-readme-not-yet-implemented-and-design-say-dhcp-slaac-are-not.md) | doc-mismatch | `README.md:141` | code |
| 114 | [With `alloc`, routes, SLAAC routers/prefixes and addresses learned from RAs are unbounded](114-with-alloc-default-routes-slaac-routers-prefixes-and-address.md) | resource-leak | `src/config.rs:52` | code |
| 115 | [config docs: MULTICAST_GROUP_COUNT is per interface and shared with solicited-node groups; IFACE_ADDR_COUNT omits the link-local slot](115-config-docs-multicast-group-count-is-per-interface-not-per-s.md) | doc-mismatch | `src/config.rs:54` | code |
| 116 | [DNS retransmits to one server every 1 s for 10 s before trying the next, and ignores ICMP port unreachable](116-retransmission-policy-1-s-retries-to-the-same-server-10-s-be.md) | performance | `src/dns.rs:33` | code |
| 117 | [DnsClient::update_servers with pending queries: old server index carries over, and replies from removed servers are dropped](117-dnsclient-update-servers-while-queries-are-pending-server-in.md) | correctness | `src/dns.rs:201` | code |
| 118 | [.local detection is case-sensitive, so "host.LOCAL" goes to the unicast DNS servers](118-local-detection-is-case-sensitive-so-host-local-is-sent-to-t.md) | rfc-compliance | `src/dns.rs:240` | test |
| 119 | [start_query_raw docs say .local names use mDNS, but the caller's `mdns` argument decides, and the name is not validated](119-start-query-raw-docs-claim-local-names-are-sent-over-mdns-bu.md) | doc-mismatch | `src/dns.rs:271` | code |
| 120 | [Two concurrent queries with the same random txid: a response for one blocks the other](120-two-concurrent-queries-with-the-same-random-txid-a-response-.md) | correctness | `src/dns.rs:282` | code |
| 121 | [start_query sends nothing, and the DnsClient docs don't say to poll after it](121-start-query-sends-nothing-and-asks-for-no-poll-and-the-docs-.md) | hang-stall | `src/dns.rs:291` | test |
| 122 | [TC (truncated) responses are used as if complete; an empty truncated answer fails the query](122-tc-truncated-responses-are-used-as-if-complete-an-empty-trun.md) | rfc-compliance | `src/dns.rs:507` | RFC text |
| 123 | [NXDOMAIN response kills a query before the question section is checked; mDNS queries accept NXDOMAIN too](123-nxdomain-response-kills-a-query-before-the-question-section-.md) | security | `src/dns.rs:415` | test |
| 124 | [A CNAME rewrites the pending query's name even when the response is rejected; a failed copy leaves an unterminated name on the wire](124-a-cname-rewrites-the-pending-query-s-name-even-when-the-resp.md) | correctness | `src/dns.rs:496` | test |
| 125 | [DNS_MAX_NAME_SIZE above 496 makes dispatch panic slicing its 512-byte buffer](125-dns-max-name-size-above-496-makes-dispatch-panic-slicing-its.md) | panic | `src/dns.rs:590` | code |
| 126 | [mDNS queries are sent with the RD bit set](126-mdns-queries-are-sent-with-the-rd-bit-set.md) | rfc-compliance | `src/dns.rs:593` | RFC text |
| 127 | [driver_impls::wait panics for fds >= FD_SETSIZE (1024)](127-driver-impls-wait-panics-for-fds-fd-setsize-1024.md) | panic | `src/driver_impls/mod.rs:41` | code |
| 128 | [RawSocketDriver ignores set_multicast_filter, so the host NIC can filter out groups the stack joins](128-rawsocketdriver-ignores-set-multicast-filter-so-multicast-gr.md) | correctness | `src/driver_impls/raw_socket.rs:193` | plausible |
| 129 | [RawSocketDriver::can_transmit always returns true but transmit fails with EAGAIN](129-rawsocketdriver-can-transmit-always-returns-true-but-transmi.md) | correctness | `src/driver_impls/raw_socket.rs:229` | code |
| 130 | [Local struct ifreq is 20 bytes but the kernel copies 40, and TUNSETIFF flags are written as an int (0 on big-endian)](130-struct-ifreq-is-20-bytes-but-the-kernel-copies-sizeof-struct.md) | correctness | `src/driver_impls/tuntap.rs:38` | test |
| 131 | [ifreq_for panics on interface names of 17+ bytes and silently truncates 16-byte names](131-ifreq-for-panics-on-interface-names-longer-than-16-bytes-and.md) | panic | `src/driver_impls/tuntap.rs:49` | test |
| 132 | [TunTapDriver::new leaks the /dev/net/tun fd on every error path](132-tuntapdriver-new-leaks-the-dev-net-tun-fd-on-every-error-pat.md) | resource-leak | `src/driver_impls/tuntap.rs:102` | code |
| 133 | [TunTapDriver::from_fd: nonblocking fd, fd ownership and mtu units are undocumented](133-tuntapdriver-from-fd-nonblocking-fd-required-but-not-documen.md) | doc-mismatch | `src/driver_impls/tuntap.rs:119` | code |
| 134 | [TunTapDriver and RawSocketDriver leave the frame in the kernel when the pool is empty, so the main loop spins](134-tuntapdriver-leaves-the-frame-in-the-kernel-when-the-pool-is.md) | hang-stall | `src/driver_impls/tuntap.rs:219` | code |
| 135 | [IPv4 fragment identification is one global sequential counter: predictable and not rate-limited](135-ipv4-fragment-identification-is-one-global-sequential-counte.md) | security | `src/fragmentation.rs:169` | RFC text |
| 136 | [Raw IPv4 packets that are already fragments, or that have bytes beyond total_len, are fragmented wrongly](136-raw-ipv4-packets-that-are-already-fragments-or-that-have-byt.md) | correctness | `src/fragmentation.rs:186` | code |
| 137 | [IPv4 fragments drop the packet's PacketMeta, unlike 6LoWPAN fragments and contrary to the Driver::transmit doc](137-ipv4-fragments-drop-the-packet-s-packetmeta-unlike-6lowpan-f.md) | correctness | `src/fragmentation.rs:264` | code |
| 138 | [IPv4 fragmenter copies every option into every fragment, including options whose copied flag is 0](138-ipv4-fragmenter-copies-every-option-into-every-fragment-incl.md) | rfc-compliance | `src/fragmentation.rs:274` | RFC text |
| 139 | [ICMPv4 and ICMPv6 Redirects are ignored entirely (RFC 1122 MUST, RFC 4861 SHOULD)](139-icmpv4-and-icmpv6-redirects-are-ignored-entirely-rfc-1122-mu.md) | rfc-compliance | `src/icmp_error.rs:39` | RFC text |
| 140 | [ICMPv6 error messages of unknown type are dropped instead of being passed to the upper layer (RFC 4443 §2.4(a))](140-icmpv6-error-messages-of-unknown-type-are-dropped-instead-of.md) | rfc-compliance | `src/wire/icmpv6.rs:233` | RFC text |
| 141 | [DhcpServerConfig::lease_duration doc: clients asking for less than 60 s don't get it](141-dhcpserverconfig-lease-duration-doc-clients-asking-for-less-.md) | doc-mismatch | `src/iface/dhcpv4_server.rs:68` | test |
| 142 | [The lease table (8 slots by default) is exhausted by 8 spoofed DISCOVERs a minute, or 8 DISCOVER+DECLINE pairs per 10 minutes](142-the-lease-table-8-slots-by-default-is-exhausted-by-8-spoofed.md) | security | `src/iface/dhcpv4_server.rs:340` | test |
| 143 | [DHCP server pool is not validated against the subnet; a large out-of-subnet pool makes every DISCOVER scan up to 2^32 addresses](143-dhcp-server-pool-is-not-validated-against-the-subnet-a-large.md) | performance | `src/iface/dhcpv4_server.rs:372` | test |
| 144 | [Released/Expired records don't keep their address: the next new client takes it even when the pool has unused addresses](144-released-expired-records-don-t-keep-their-address-the-next-n.md) | doc-mismatch | `src/iface/dhcpv4_server.rs:372` | test |
| 145 | [OFFER to a bound client can carry lease time 0, and the ACK contradicts the OFFER's lease time](145-offer-to-a-bound-client-can-carry-lease-time-0-and-the-ack-c.md) | correctness | `src/iface/dhcpv4_server.rs:491` | test |
| 146 | [Server identifier compared only against the first IPv4 address](146-server-identifier-compared-only-against-the-first-ipv4-addre.md) | rfc-compliance | `src/iface/dhcpv4_server.rs:537` | test |
| 147 | [REQUEST carrying our server identifier plus ciaddr but no requested-IP is silently dropped](147-request-carrying-our-server-identifier-plus-ciaddr-but-no-re.md) | correctness | `src/iface/dhcpv4_server.rs:546` | test |
| 148 | [Replies can exceed 576 bytes: the client's maximum message size option is ignored](148-replies-can-exceed-576-bytes-the-client-s-maximum-message-si.md) | rfc-compliance | `src/iface/dhcpv4_server.rs:675` | code |
| 149 | [A /31 subnet with the server on the upper address can lease nothing](149-a-31-subnet-with-the-server-on-the-upper-address-can-lease-n.md) | correctness | `src/iface/dhcpv4_server.rs:768` | test |
| 150 | [When only T2 is given and T2 <= lease/2, T1 equals T2, so RENEWING is skipped](150-when-only-t2-is-given-and-t2-lease-2-t1-equals-t2-so-renewin.md) | rfc-compliance | `src/iface/dhcpv4.rs:440` | code |
| 151 | [Lease timers start at ACK arrival, not when the DHCPREQUEST was sent](151-lease-timers-start-at-ack-arrival-not-when-the-dhcprequest-w.md) | rfc-compliance | `src/iface/dhcpv4.rs:450` | code |
| 152 | [DHCP client advertises a Maximum DHCP Message Size below the legal minimum of 576](152-dhcp-client-advertises-a-maximum-dhcp-message-size-below-the.md) | rfc-compliance | `src/iface/dhcpv4.rs:491` | test |
| 153 | [DhcpConfig / DhcpServerConfig outgoing options that don't fit panic inside Stack::poll](153-dhcpconfig-dhcpserverconfig-outgoing-options-larger-than-255.md) | panic | `src/iface/dhcpv4.rs:553` | test |
| 154 | [Renewals are unicast to the OFFER's IP source, not to the server identifier](154-renewals-are-unicast-to-the-offer-s-ip-source-not-to-the-ser.md) | rfc-compliance | `src/iface/dhcpv4.rs:643` | RFC text |
| 155 | [No duplicate-address check, no DHCPDECLINE and no ARP announcement after binding](155-no-duplicate-address-check-no-dhcpdecline-and-no-arp-announc.md) | rfc-compliance | `src/iface/dhcpv4.rs:663` | RFC text |
| 156 | [After rebinding to a different server, the lease keeps the old server](156-after-rebinding-to-a-different-server-the-lease-keeps-the-ol.md) | correctness | `src/iface/dhcpv4.rs:667` | code |
| 157 | [NAK or ACK received in BOUND (before T1) is acted on: a stray NAK drops a valid lease](157-nak-or-ack-received-in-bound-before-t1-is-acted-on-a-stray-n.md) | rfc-compliance | `src/iface/dhcpv4.rs:681` | test |
| 158 | [Lease time 0, or a server that always NAKs, causes a DISCOVER/REQUEST loop with no backoff](158-lease-time-0-or-max-lease-duration-0-or-a-server-that-always.md) | hang-stall | `src/iface/dhcpv4.rs:771` | test |
| 159 | [A DHCP address change drops every parked packet and neighbor entry on the interface, IPv6 included](159-a-dhcp-address-change-drops-every-parked-packet-and-neighbor.md) | correctness | `src/iface/dhcpv4.rs:865` | code |
| 160 | [Iface::ip_mtu doc is wrong for IEEE 802.15.4 interfaces](160-iface-ip-mtu-doc-is-wrong-for-ieee-802-15-4-interfaces.md) | doc-mismatch | `src/iface/mod.rs:317` | code |
| 161 | [set_hardware_addr never tells the driver, and the doc does not say so](161-set-hardware-addr-never-tells-the-driver-so-hardware-unicast.md) | doc-mismatch | `src/iface/mod.rs:331` | code |
| 162 | [set_hardware_addr silently replaces the link-local address and flushes neighbor state, even for the same MAC](162-set-hardware-addr-docs-omit-that-it-replaces-the-ipv6-link-l.md) | doc-mismatch | `src/iface/mod.rs:345` | code |
| 163 | [Non-unicast hardware addresses are accepted by add_iface and set_hardware_addr](163-non-unicast-hardware-addresses-are-accepted-by-add-iface-and.md) | api | `src/iface/mod.rs:346` | code |
| 164 | [add_ip_addr doc misstates how address order affects source selection](164-add-ip-addr-doc-misstates-how-address-order-affects-source-s.md) | doc-mismatch | `src/iface/mod.rs:376` | code |
| 165 | [add_ip_addr/set_ip_addrs accept the subnet's own broadcast/network address and loopback addresses](165-add-ip-addr-set-ip-addrs-accept-the-subnet-s-own-broadcast-n.md) | api | `src/iface/mod.rs:389` | test |
| 166 | [add_ip_addr with a new prefix silently changes an autoconfigured address into a manual one](166-add-ip-addr-with-a-new-prefix-silently-changes-an-autoconfig.md) | api | `src/iface/mod.rs:397` | test |
| 167 | [set_ip_addrs accepts duplicate addresses, and remove_ip_addr then leaves the address assigned](167-set-ip-addrs-accepts-duplicate-addresses-and-remove-ip-addr-.md) | correctness | `src/iface/mod.rs:434` | test |
| 168 | [config_generation and the interface waker miss manual and expired route changes, and MAC changes in IPv4-only builds](168-config-generation-and-the-interface-waker-miss-manual-and-ex.md) | doc-mismatch | `src/iface/mod.rs:474` | test |
| 169 | [remove_dhcpv4_server_lease doesn't revoke: the client's next renewal is ACKed again](169-remove-dhcpv4-server-lease-doesn-t-revoke-the-client-s-next-.md) | doc-mismatch | `src/iface/mod.rs:612` | code |
| 170 | [IPv6 builds without `multicast` never send MLD reports for solicited-node groups](170-ipv6-builds-without-multicast-never-send-mld-reports-for-sol.md) | rfc-compliance | `src/iface/mod.rs:708` | RFC text |
| 171 | [Small driver MTUs cause integer underflow panics (debug) or wrapped sizes (release) in ip_mtu, TCP MSS and DHCP](171-small-driver-mtus-cause-integer-underflow-panics-debug-or-wr.md) | panic | `src/iface/mod.rs:731` | test |
| 172 | [TX timestamp queue overflow drains the driver's timestamps and throws them away](172-tx-timestamp-queue-overflow-drains-the-driver-s-timestamps-a.md) | correctness | `src/iface/mod.rs:755` | code |
| 173 | [IPv4 source for routed (off-link) destinations is the interface's first IPv4 address, not the one on the gateway's subnet](173-ipv4-source-for-routed-off-link-destinations-is-the-interfac.md) | correctness | `src/iface/mod.rs:840` | test |
| 174 | [Packets from another interface's subnet-broadcast address cause echo replies, ICMP errors and RSTs to be broadcast on that other interface](174-packets-from-another-interface-s-subnet-broadcast-address-ca.md) | security | `src/iface/mod.rs:902` | test |
| 175 | [Non-/64 autoconf prefixes use prefix-table slots, and a full table drops new prefixes with no eviction](175-non-64-autoconf-prefixes-use-prefix-table-slots-and-a-full-t.md) | correctness | `src/iface/slaac.rs:106` | test |
| 176 | [Every RA, even an identical refresh, runs config_changed and reprograms the multicast filter](176-every-ra-even-an-identical-refresh-runs-config-changed-the-d.md) | performance | `src/iface/slaac.rs:531` | code |
| 177 | [PIO reserved prefix bits are not ignored, so a duplicate entry's expiry removes a valid SLAAC address](177-pio-reserved-prefix-bits-are-not-ignored-a-pio-for-the-same-.md) | correctness | `src/iface/slaac.rs:258` | test |
| 178 | [Any RA, including one with router lifetime 0, stops router solicitation](178-any-ra-including-one-with-router-lifetime-0-stops-router-sol.md) | rfc-compliance | `src/iface/slaac.rs:296` | test |
| 179 | [No random initial delay before the first router solicitation](179-no-random-initial-delay-before-the-first-router-solicitation.md) | rfc-compliance | `src/iface/slaac.rs:183` | RFC text |
| 180 | [Packets parked on neighbor resolution are sent with a SLAAC source address after it became invalid](180-packets-parked-on-neighbor-resolution-are-sent-with-a-slaac-.md) | rfc-compliance | `src/iface/slaac.rs:467` | code |
| 181 | [set_slaac purges the whole interface's neighbor cache and parked packets, IPv4 included](181-set-slaac-on-off-re-enable-purges-the-whole-interface-s-neig.md) | correctness | `src/iface/slaac.rs:609` | test |
| 182 | [Default std feature compiles driver_impls unconditionally, breaking non-unix builds](182-default-std-feature-compiles-driver-impls-unconditionally-br.md) | feature-gating | `src/lib.rs:43` | code |
| 183 | [Iface::join_multicast_group docs omit the TooManyGroups error](183-iface-join-multicast-group-docs-omit-the-toomanygroups-error.md) | doc-mismatch | `src/multicast.rs:157` | code |
| 184 | [join/leave_multicast_group docs: IPv4 reports wait for an address, and a leave with no address is never sent](184-join-leave-multicast-group-docs-ipv4-reports-wait-for-an-add.md) | doc-mismatch | `src/multicast.rs:157` | code |
| 185 | [Solicited-node groups share the fixed multicast group table: when full, a new address gets no MLD report](185-solicited-node-groups-share-the-per-interface-multicast-grou.md) | correctness | `src/multicast.rs:255` | code |
| 186 | [IGMP general-query spreading indexes the group table by position, so a removal during the spread skips a group](186-igmp-general-query-spreading-indexes-the-group-table-by-posi.md) | correctness | `src/multicast.rs:346` | code |
| 187 | [A pool miss during IGMP general-query spreading abandons all remaining reports](187-a-pool-miss-during-igmp-general-query-spreading-abandons-all.md) | correctness | `src/multicast.rs:362` | code |
| 188 | [A pending group-specific response is sent after the group was left](188-a-pending-group-specific-response-is-sent-even-after-the-gro.md) | correctness | `src/multicast.rs:321` | RFC text |
| 189 | [IGMP response delays are deterministic, although the stack has a PRNG](189-igmp-response-delays-are-deterministic-although-the-stack-no.md) | rfc-compliance | `src/multicast.rs:460` | RFC text |
| 190 | [IGMP host never suppresses its report on hearing another host's report](190-igmp-host-never-suppresses-its-report-on-hearing-another-hos.md) | rfc-compliance | `src/multicast.rs:489` | RFC text |
| 191 | [Reports are sent for ff02::1, 224.0.0.1 and interface/reserved-scope groups](191-reports-are-sent-for-ff02-1-224-0-0-1-and-interface-reserved.md) | rfc-compliance | `src/multicast.rs:584` | RFC text |
| 192 | [MLDv2 report packing ignores the interface MTU and never splits: extra groups are silently dropped](192-mldv2-report-packing-ignores-the-interface-mtu-and-never-spl.md) | correctness | `src/multicast.rs:622` | code |
| 193 | [Neighbor timers are fixed: RA Reachable Time and Retrans Timer are ignored, and the ARP timeout cannot be configured](193-neighbor-timers-are-fixed-ra-reachable-time-and-retrans-time.md) | rfc-compliance | `src/neighbor.rs:160` | RFC text |
| 194 | [Public APIs take arbitrary Instants without documenting the 24.8-day range, and Route::preferred_until does nothing](194-public-apis-take-arbitrary-instants-without-documenting-the-.md) | doc-mismatch | `src/neighbor.rs:355` | code |
| 195 | [NeighborCache::remove/retain/clear docs misdescribe the fate of parked packets](195-neighborcache-remove-retain-clear-docs-misdescribe-the-fate-.md) | doc-mismatch | `src/neighbor.rs:372` | code |
| 196 | [Public raw socket docs don't say that only the first matching socket (in slab order) receives a packet](196-public-raw-socket-docs-don-t-say-that-only-the-first-matchin.md) | doc-mismatch | `src/raw.rs:56` | code |
| 197 | [IPv6 raw protocol filter compares different next-header fields on send and on receive](197-ipv6-raw-protocol-filter-compares-different-next-header-fiel.md) | correctness | `src/raw.rs:236` | test |
| 198 | [Raw send docs: panic conditions are wrong or incomplete](198-raw-send-docs-panic-conditions-are-wrong-or-incomplete.md) | doc-mismatch | `src/raw.rs:502` | code |
| 199 | [Raw Ethernet frames are handed to the driver without checking the device's max_transmission_unit](199-raw-ethernet-frames-are-handed-to-the-driver-without-checkin.md) | correctness | `src/raw.rs:561` | test |
| 200 | [Raw IP send transmits bytes past the IP total length, and fragments them as payload](200-raw-ip-send-accepts-buffers-with-bytes-past-the-ip-total-pay.md) | correctness | `src/raw.rs:588` | test |
| 201 | [Overlapping 6LoWPAN fragments are merged instead of discarding the reassembly](201-overlapping-6lowpan-fragments-are-merged-later-data-wins-ins.md) | rfc-compliance | `src/reassembly.rs:112` | RFC text |
| 202 | [IPv4 reassembly always memmoves the whole reassembled datagram](202-ipv4-reassembly-always-memmoves-the-whole-reassembled-datagr.md) | performance | `src/reassembly.rs:313` | code |
| 203 | [Reassembled IPv4 datagram uses the completing fragment's header, not fragment 0's](203-reassembled-datagram-uses-the-ip-header-of-whichever-fragmen.md) | rfc-compliance | `src/reassembly.rs:318` | RFC text |
| 204 | [Public Route::preferred_until is never read](204-public-route-preferred-until-is-never-read.md) | doc-mismatch | `src/route.rs:61` | code |
| 205 | [A default route with host bits set (e.g. 10.0.0.0/0) is not recognized by the default-route helpers](205-a-default-route-written-with-host-bits-set-e-g-1-2-3-4-0-is-.md) | correctness | `src/route.rs:96` | code |
| 206 | [Default-route helpers ignore the interface and remove another interface's DHCP route](206-routes-default-route-helpers-ignore-the-interface-they-remov.md) | api | `src/route.rs:261` | code |
| 207 | [6LoWPAN decompression rejects packets with more than three compressed extension headers](207-decompression-rejects-valid-packets-with-more-than-three-com.md) | correctness | `src/sixlowpan.rs:276` | test |
| 208 | [Valid IPHC/NHC encodings longer than the uncompressed headers are rejected](208-valid-iphc-nhc-encodings-longer-than-the-uncompressed-header.md) | rfc-compliance | `src/sixlowpan.rs:315` | test |
| 209 | [Compression rebuilds Payload Length and UDP Length from the buffer size, so raw IP packets with trailing bytes change meaning](209-compression-rebuilds-payload-length-and-udp-length-from-the-.md) | correctness | `src/sixlowpan.rs:436` | test |
| 210 | [Unicast 802.15.4 frames never request a MAC ACK](210-unicast-802-15-4-frames-never-request-a-mac-ack-so-there-is-.md) | performance | `src/sixlowpan.rs:590` | code |
| 211 | [6LoWPAN fragmenter lets the compressed header chain straddle FRAG1](211-6lowpan-fragmenter-lets-the-compressed-header-chain-straddle.md) | rfc-compliance | `src/sixlowpan.rs:775` | test |
| 212 | [purge_iface_link_state on an IPv4 address change flushes IPv6 neighbors and parked packets](212-purge-iface-link-state-on-a-dhcpv4-address-change-flushes-ip.md) | correctness | `src/stack.rs:143` | test |
| 213 | [Broadcast and multicast go to the first interface even when it can't carry that IP version](213-broadcast-and-multicast-from-an-unbound-socket-go-to-the-fir.md) | correctness | `src/stack.rs:357` | test |
| 214 | [Packets addressed to one of our own addresses are put on the wire](214-packets-addressed-to-one-of-our-own-addresses-are-put-on-the.md) | correctness | `src/stack.rs:364` | test |
| 215 | [Route expiry and address deprecation are checked against the last poll's time](215-route-expiry-and-address-deprecation-checked-against-the-las.md) | correctness | `src/stack.rs:372` | test |
| 216 | [A route naming a nonexistent interface makes poll() panic on network input](216-a-route-naming-a-nonexistent-interface-makes-poll-panic-on-n.md) | panic | `src/stack.rs:376` | test |
| 217 | [Handle accessor docs promise a panic on stale handles, but a reused slot silently addresses a different object](217-handle-accessor-docs-promise-a-panic-on-stale-handles-but-a-.md) | doc-mismatch | `src/stack.rs:737` | test |
| 218 | [Removing an interface or socket drops its registered wakers without waking them](218-removing-an-interface-or-socket-drops-its-registered-wakers-.md) | missed-wake | `src/stack.rs:751` | code |
| 219 | [Stale interface bindings survive remove_iface and silently apply to a new interface that reuses the index](219-stale-interface-bindings-survive-remove-iface-and-silently-a.md) | correctness | `src/stack.rs:751` | test |
| 220 | [Neighbor retransmit/failure timers run before the interface's RX queue is drained](220-neighbor-retransmit-failure-timers-run-before-the-interface-.md) | correctness | `src/stack.rs:1090` | test |
| 221 | [README/DESIGN say the stack does not restart DHCP/SLAAC on link-up, but poll does](221-readme-design-say-the-stack-does-not-restart-dhcp-slaac-on-l.md) | doc-mismatch | `src/stack.rs:1125` | code |
| 222 | [Iface waker misses a link flap between two polls, while Iface::link_state() reads the driver live](222-iface-waker-misses-a-link-flap-between-two-polls-while-iface.md) | missed-wake | `src/stack.rs:1125` | code |
| 223 | [Link-up throws away a still-valid DHCP lease at once, breaking live traffic during rediscovery](223-link-up-throws-away-a-still-valid-dhcp-lease-at-once-address.md) | correctness | `src/stack.rs:1133` | code |
| 224 | [Raw Ethernet sockets get copies, not moves, of ethertypes the build cannot process](224-raw-ethernet-sockets-get-copies-not-moves-of-ethertypes-the-.md) | feature-gating | `src/stack.rs:1264` | code |
| 225 | [IPv4 options are invisible to UDP/TCP, and incomplete source routes are delivered locally](225-ip-options-not-passed-to-or-settable-by-udp-tcp-dropped-from.md) | rfc-compliance | `src/stack.rs:1437` | RFC text |
| 226 | [Neighbor-failure ICMP errors are dropped when the source belongs to another interface](226-weak-host-egress-combined-with-strong-host-ingress-replies-a.md) | correctness | `src/stack.rs:2000` | code |
| 227 | [iface-bind: first-match TCP demux lets an unbound socket shadow a same-tuple bound socket or listener](227-iface-bind-first-match-tcp-connected-socket-demux-lets-an-un.md) | correctness | `src/stack.rs:1511` | code |
| 228 | [Immediate ACKs from process() ignore the socket's hop limit and interface binding](228-immediate-acks-from-process-ignore-the-socket-s-hop-limit-an.md) | correctness | `src/stack.rs:1550` | code |
| 229 | [Echo replies drop IP options and do not reverse a received source route](229-echo-replies-drop-ip-options-and-do-not-reverse-a-received-s.md) | rfc-compliance | `src/stack.rs:1437` | RFC text |
| 230 | [Gateway neighbor entries expire every 60 s under traffic and are re-resolved](230-neighbor-reachability-comes-from-one-way-nd-messages-never-f.md) | performance | `src/stack.rs:1407` | test |
| 231 | [Echoes from spoofed on-link sources evict real neighbor cache entries](231-neighbor-cache-flooding-forged-on-link-icmp-echoes-evict-rea.md) | security | `src/neighbor.rs:422` | test |
| 232 | [Hop-by-hop option errors are sent in response to ICMPv6 error messages](232-hop-by-hop-option-errors-are-sent-in-response-to-icmpv6-erro.md) | rfc-compliance | `src/stack.rs:1730` | test |
| 233 | [Echo replies and errors for multicast-destined packets can go out from ::1 when the interface has no IPv6 address](233-echo-replies-and-errors-for-multicast-destined-packets-can-g.md) | rfc-compliance | `src/stack.rs:1829` | test |
| 234 | [MLD query reception checks deviate from RFC 3810: no Router Alert check, nonzero Code rejected, specific queries only accepted at the group address](234-mld-query-reception-checks-deviate-from-rfc-3810-no-router-a.md) | rfc-compliance | `src/stack.rs:1896` | RFC text |
| 235 | [Router advertisements with a non-zero ICMP code are accepted; NS/RA are dropped over malformed options they must ignore](235-router-advertisements-with-a-non-zero-icmp-code-are-accepted.md) | rfc-compliance | `src/stack.rs:1904` | test |
| 236 | [Neighbor-failure ICMP errors are generated for every parked non-initial fragment and demuxed on payload bytes read as ports](236-neighbor-failure-icmp-errors-are-generated-for-every-parked-.md) | correctness | `src/stack.rs:1942` | test |
| 237 | [A neighbor resolution failure error is lost when the queued packet's source address belongs to another interface](237-a-neighbor-resolution-failure-error-is-lost-when-the-queued-.md) | correctness | `src/stack.rs:2000` | test |
| 238 | [Fixed TTL 64 for stack-generated packets and the socket default is not configurable](238-fixed-ttl-64-for-stack-generated-packets-and-the-socket-defa.md) | rfc-compliance | `src/stack.rs:2079` | RFC text |
| 239 | [ARP ignores packets not targeted at us, so the merge step never runs: gratuitous ARP and MAC changes are not picked up](239-arp-ignores-packets-not-targeted-at-us-so-the-merge-step-nev.md) | rfc-compliance | `src/stack.rs:2189` | test |
| 240 | [ARP probes (sender IP 0.0.0.0) and DAD neighbor solicitations for our addresses are never answered](240-arp-probes-sender-ip-0-0-0-0-are-never-answered-so-other-hos.md) | rfc-compliance | `src/stack.rs:2201` | test |
| 241 | [A neighbor solicitation fills the neighbor cache before checking that its target is ours](241-a-neighbor-solicitation-fills-the-neighbor-cache-before-chec.md) | security | `src/stack.rs:2259` | test |
| 242 | [An NDISC link-layer address option holding an 802.15.4 short address makes the whole NS/NA be dropped](242-an-ndisc-link-layer-address-option-holding-an-802-15-4-short.md) | other | `src/stack.rs:2260` | code |
| 243 | [NA with the Router flag cleared does not remove the router from the default route list](243-na-with-the-router-flag-cleared-does-not-remove-the-router-f.md) | rfc-compliance | `src/stack.rs:2304` | RFC text |
| 244 | [Routes::add accepts a gateway of the other address family: parked packets are flushed with the wrong ethertype, and 802.15.4 panics](244-routes-add-accepts-a-gateway-of-the-other-address-family-par.md) | panic | `src/route.rs:154` | test |
| 245 | [UDP datagrams sent while resolved-but-parked packets wait for device room overtake them](245-udp-datagrams-sent-while-resolved-but-parked-packets-wait-fo.md) | correctness | `src/stack.rs:2709` | test |
| 246 | [Neighbor cache entries keep being used to send after they expire, until the next poll](246-neighbor-cache-entries-keep-being-used-to-send-after-they-ex.md) | doc-mismatch | `src/stack.rs:2512` | test |
| 247 | [Neighbor Solicitation source address is chosen from the target, not from the packet that prompted it](247-neighbor-solicitation-source-address-is-chosen-from-the-targ.md) | rfc-compliance | `src/stack.rs:2559` | RFC text |
| 248 | [DHCP unicast renewal takes a gateway from any interface's route, then resolves it on the DHCP interface](248-transmit-ipv4-on-dhcp-renewals-picks-a-gateway-from-any-inte.md) | correctness | `src/stack.rs:2651` | code |
| 249 | [NeighborCache::insert accepts a hardware address of the wrong medium, and egress then panics](249-neighborcache-insert-accepts-a-hardware-address-of-the-wrong.md) | panic | `src/neighbor.rs:355` | test |
| 250 | [No way for UDP/TCP to set DSCP/ECN or see the received value](250-no-way-for-udp-tcp-to-set-tos-dscp-ecn-or-see-the-received-t.md) | rfc-compliance | `src/stack.rs:2799` | RFC text |
| 251 | [ICMPv6 errors are not capped to the egress interface's IP MTU, so they are dropped on small-MTU links](251-icmpv6-errors-are-not-capped-to-the-egress-interface-s-ip-mt.md) | correctness | `src/stack.rs:2893` | code |
| 252 | [tcp-cubic keeps past instants (recovery_start, idle_start) indefinitely, and cwnd freezes after 24.8 days](252-tcp-cubic-keeps-past-instants-recovery-start-idle-start-inde.md) | timer | `src/tcp/congestion/cubic.rs:65` | test |
| 253 | [CUBIC's W_est counts at most one segment per ACK, so the Reno-friendly region grows at half rate with delayed ACKs](253-cubic-s-w-est-counts-at-most-one-segment-per-ack-so-its-reno.md) | rfc-compliance | `src/tcp/congestion/cubic.rs:81` | test |
| 254 | [cwnd is never reduced after idle and grows while app-limited (Reno and CUBIC)](254-cwnd-is-never-reduced-after-idle-and-grows-while-app-limited.md) | rfc-compliance | `src/tcp/congestion/cubic.rs:106` | RFC text |
| 255 | [Test suite fails to compile or pass in feature sets CI never tests](255-test-suite-fails-to-compile-or-pass-in-feature-sets-ci-never.md) | feature-gating | `src/tcp/mod.rs:11` | test |
| 256 | [Go-back-N after an RTO suppresses RTT samples for the whole recovery, so the backed-off RTO can ratchet up to 60 s](256-go-back-n-after-an-rto-suppresses-all-rtt-samples-for-the-wh.md) | performance | `src/tcp/mod.rs:324` | code |
| 257 | [RTO is not re-initialized to 3 s after a handshake that needed a SYN retransmission](257-rto-is-not-re-initialized-to-3-s-after-a-handshake-that-need.md) | rfc-compliance | `src/tcp/mod.rs:343` | test |
| 258 | [TIME-WAIT is 10 s and can be cut short by connect()/accept() on the same socket](258-time-wait-is-10-s-can-be-cut-short-by-connect-accept-on-the-.md) | rfc-compliance | `src/tcp/mod.rs:382` | RFC text |
| 259 | [Default send MSS is 536 for IPv6 too (MUST-15 says 1220)](259-default-send-mss-is-536-for-ipv6-too-must-15-says-1220.md) | rfc-compliance | `src/tcp/mod.rs:596` | RFC text |
| 260 | [A 1 GiB receive buffer (the documented maximum) produces window scale shift 15](260-a-1-gib-receive-buffer-the-documented-maximum-produces-windo.md) | rfc-compliance | `src/tcp/mod.rs:615` | test |
| 261 | [TCP ISN has no clock component (RFC 9293 MUST-8)](261-tcp-isn-has-no-clock-component-rfc-9293-must-8.md) | rfc-compliance | `src/tcp/mod.rs:781` | RFC text |
| 262 | [Immediate ACK replies omit TSopt when the triggering segment lacked one, even on a timestamp connection](262-immediate-ack-replies-omit-the-timestamps-option-when-the-tr.md) | rfc-compliance | `src/tcp/mod.rs:872` | test |
| 263 | [TCP aborts a handshake on any ICMP error, including Source Quench](263-tcp-aborts-a-handshake-on-any-icmp-error-including-source-qu.md) | rfc-compliance | `src/tcp/mod.rs:957` | test |
| 264 | [SYN-SENT: PSH/FIN segments with an unacceptable ACK are dropped instead of answered with RST](264-syn-sent-psh-fin-segments-with-an-unacceptable-ack-are-dropp.md) | rfc-compliance | `src/tcp/mod.rs:1020` | test |
| 265 | [A TCP transmit buffer over 2 GiB makes every incoming ACK panic in sequence arithmetic](265-a-tcp-transmit-buffer-over-2-gib-makes-every-incoming-ack-pa.md) | panic | `src/tcp/mod.rs:1056` | code |
| 266 | [Acceptability test ignores the FIN's sequence space: FIN coalesced with already-received data is dropped](266-acceptability-test-ignores-the-fin-s-sequence-space-fin-coal.md) | rfc-compliance | `src/tcp/mod.rs:1097` | test |
| 267 | [ACK field of data segments ignored while our receive window is zero](267-ack-field-of-data-segments-ignored-while-our-receive-window-.md) | rfc-compliance | `src/tcp/mod.rs:1125` | test |
| 268 | [A retransmitted bare FIN is answered under the 1/s challenge-ACK rate limit, although the comment says FINs are exempt](268-a-retransmitted-bare-fin-is-answered-under-the-1-s-challenge.md) | correctness | `src/tcp/mod.rs:1191` | test |
| 269 | [Zero-length window probes and keep-alives (SEG.SEQ = RCV.NXT-1) are throttled by the 1/s challenge-ACK limiter and go unanswered](269-zero-length-window-probes-and-keep-alives-seg-seq-rcv-nxt-1-.md) | rfc-compliance | `src/tcp/mod.rs:1191` | test |
| 270 | [An in-order FIN is accepted even though earlier out-of-order data lies past it: bytes after the FIN are delivered and ACKed](270-an-in-order-fin-is-accepted-even-though-earlier-out-of-order.md) | correctness | `src/tcp/mod.rs:1236` | test |
| 271 | [Application cannot tell an aborted connection from a graceful close after a FIN was received (MUST-12)](271-application-cannot-tell-an-aborted-connection-from-a-gracefu.md) | api | `src/tcp/mod.rs:1247` | test |
| 272 | [Missing SND.WL1/SND.WL2 check: reordered older data segments overwrite the send window](272-missing-snd-wl1-snd-wl2-check-reordered-old-segments-overwri.md) | rfc-compliance | `src/tcp/mod.rs:1385` | RFC text |
| 273 | [Peer's FIN (and other SYN/FIN segments) counted as duplicate ACKs for fast retransmit](273-peer-s-fin-and-other-syn-fin-segments-counted-as-duplicate-a.md) | rfc-compliance | `src/tcp/mod.rs:1426` | test |
| 274 | [Duplicate ACKs after the third that arrive before dispatch never inflate cwnd](274-duplicate-acks-after-the-third-that-arrive-before-dispatch-n.md) | rfc-compliance | `src/tcp/mod.rs:1443` | test |
| 275 | [TSecr echo rules of RFC 7323 §4.3 not followed, and ack_reply can omit TSopt](275-tsecr-echo-rules-of-rfc-7323-4-3-not-followed-echoes-the-tri.md) | rfc-compliance | `src/tcp/mod.rs:1486` | RFC text |
| 276 | [Every-second-segment ACK threshold uses the peer's MSS instead of our own (RMSS)](276-every-second-segment-ack-threshold-uses-the-peer-s-mss-inste.md) | rfc-compliance | `src/tcp/mod.rs:1675` | RFC text |
| 277 | [A single retransmitted SYN or SYN\|ACK sets ssthresh to 2048 for the whole connection](277-a-single-retransmitted-syn-or-syn-ack-sets-ssthresh-to-2-102.md) | performance | `src/tcp/mod.rs:1846` | test |
| 278 | [Every poll routes and builds a TcpRepr for every open TCP socket, idle or not](278-every-poll-does-about-440-instructions-of-tcp-dispatch-work-.md) | performance | `src/tcp/mod.rs:1887` | test |
| 279 | [No way for the application to set the DSCP/Diffserv field on TCP segments (MUST-48)](279-no-way-for-the-application-to-set-the-dscp-diffserv-field-on.md) | rfc-compliance | `src/tcp/mod.rs:1900` | code |
| 280 | [Public docs of set_timeout, set_nagle_enabled and set_ack_delay do not match behavior](280-public-docs-of-set-timeout-set-nagle-enabled-and-set-ack-del.md) | doc-mismatch | `src/tcp/mod.rs:2356` | code |
| 281 | [set_ack_delay accepts any duration, MUST-40 requires the ACK delay to be under 0.5 s](281-set-ack-delay-accepts-any-duration-must-40-requires-the-ack-.md) | api | `src/tcp/mod.rs:2381` | RFC text |
| 282 | [set_nagle_enabled doc says at most one sub-MSS segment is in flight, but the ack_due exemption breaks that](282-set-nagle-enabled-doc-says-at-most-one-sub-mss-segment-is-in.md) | doc-mismatch | `src/tcp/mod.rs:2392` | code |
| 283 | [set_keep_alive changes don't take effect on an idle connection](283-set-keep-alive-changes-don-t-take-effect-on-an-idle-connecti.md) | timer | `src/tcp/mod.rs:2420` | code |
| 284 | [abort()/is_open()/is_active() docs are inaccurate](284-abort-is-open-is-active-docs-are-inaccurate.md) | doc-mismatch | `src/tcp/mod.rs:2679` | code |
| 285 | [is_open docs say a non-open socket won't process or dispatch packets, but TIME-WAIT and aborted CLOSED sockets do](285-is-open-docs-say-a-non-open-socket-won-t-process-or-dispatch.md) | doc-mismatch | `src/tcp/mod.rs:2683` | code |
| 286 | [TcpSocket::send and recv panic if the closure returns more than the slice length, and this is not documented](286-tcpsocket-send-and-recv-panic-if-the-closure-returns-more-th.md) | doc-mismatch | `src/tcp/mod.rs:2824` | code |
| 287 | [TcpSocket::peek_slice skips the receive-state check: never returns Finished/InvalidState and reads data before the connection is established](287-tcpsocket-peek-slice-skips-the-receive-state-check-never-ret.md) | doc-mismatch | `src/tcp/mod.rs:2920` | test |
| 288 | [Segments with RST combined with SYN or FIN are rejected as malformed instead of being processed as resets](288-segments-with-rst-combined-with-syn-or-fin-are-rejected-as-m.md) | correctness | `src/tcp/repr.rs:82` | RFC text |
| 289 | [Urgent data unsupported, although the code comment claims this is standards-compliant](289-urgent-data-unsupported-although-the-code-comment-claims-thi.md) | rfc-compliance | `src/tcp/repr.rs:95` | RFC text |
| 290 | [Instant::now() uses the wall clock, so clock steps stall or fire every timer in hosted builds](290-instant-now-and-so-every-hosted-example-uses-the-wall-clock-.md) | timer | `src/time.rs:67` | code |
| 291 | [Default config lets UDP RX queues pin the entire packet pool](291-default-config-lets-udp-rx-queues-pin-the-entire-packet-pool.md) | security | `src/udp.rs:230` | test |
| 292 | [Spoofed ICMP error quoting source port 0 is stored on an unbound socket and reported after a later bind()](292-spoofed-icmp-error-quoting-source-port-0-is-stored-on-a-clos.md) | correctness | `src/udp.rs:258` | test |
| 293 | [UDP bind docs say the socket sends only from/to the bound addresses, but send metadata overrides both](293-udp-bind-docs-say-the-socket-sends-only-from-to-the-bound-ad.md) | doc-mismatch | `src/udp.rs:477` | code |
| 294 | [bind() with a fully specified IPv6 remote and no IPv6 address binds the local address to ::1](294-bind-with-a-fully-specified-ipv6-remote-on-an-interface-with.md) | correctness | `src/udp.rs:555` | test |
| 295 | [Ephemeral UDP port allocation can hand out a port that overlaps an existing socket's filter](295-ephemeral-udp-port-allocation-can-hand-out-a-port-that-overl.md) | correctness | `src/udp.rs:568` | test |
| 296 | [peek() and recv() disagree while an ICMP error is pending, and can_recv() never reports one](296-peek-and-recv-disagree-while-an-icmp-error-is-pending-can-re.md) | doc-mismatch | `src/udp.rs:718` | code |
| 297 | [Unaddressable docs omit "no route", and bind docs omit that a connected bind pins the local address](297-unaddressable-docs-omit-the-most-common-cause-no-route-and-b.md) | doc-mismatch | `src/udp.rs:804` | code |
| 298 | [Undocumented panics when a send/recv closure returns more than the slice it was given](298-undocumented-panics-when-a-send-recv-closure-returns-more-th.md) | doc-mismatch | `src/udp.rs:820` | code |
| 299 | [Default hop limit for multicast UDP is 64 instead of 1](299-default-hop-limit-for-multicast-is-64-instead-of-1.md) | rfc-compliance | `src/udp.rs:839` | plausible |
| 300 | [UDP send to 127.0.0.0/8 goes out via the default gateway, and 127/8 sources are accepted on ingress](300-udp-send-to-127-0-0-0-8-is-routed-via-the-default-gateway-an.md) | rfc-compliance | `src/udp.rs:876` | test |
| 301 | [A UDP/raw sender blocked by DeviceBusy is not woken when routing moves away from that interface](301-a-udp-raw-sender-blocked-by-devicebusy-is-tied-to-the-interf.md) | missed-wake | `src/udp.rs:912` | code |
| 302 | [With UDP RX checksum offload, IPv6 datagrams with a zero checksum are accepted](302-with-udp-rx-checksum-offload-ipv6-datagrams-with-a-zero-chec.md) | rfc-compliance | `src/udp.rs:994` | test |
| 303 | [DhcpPacket::sname() reads the wrong offset and returns Err(Malformed) for every normal packet](303-dhcppacket-sname-reads-the-wrong-offset-and-returns-err-malf.md) | correctness | `src/wire/dhcpv4.rs:185` | test |
| 304 | [DHCPv4 option overload (52) is ignored and repeated options are not concatenated](304-option-overload-52-is-ignored-and-repeated-options-are-not-c.md) | rfc-compliance | `src/wire/dhcpv4.rs:396` | code |
| 305 | [DNS public doc inaccuracies: DNS_MAX_NAME_SIZE, parse_name pointers, Record::parse errors](305-small-public-doc-inaccuracies-dns-max-name-size-size-relatio.md) | doc-mismatch | `src/wire/dns.rs:184` | code |
| 306 | [Garbled doc on Icmpv4Message::is_error, broken link in Icmpv4Packet::check_len](306-garbled-public-doc-on-icmpv4message-is-error-and-broken-intr.md) | doc-mismatch | `src/wire/icmpv4.rs:38` | code |
| 307 | [Ieee802154Address::is_unicast returns true for Absent](307-ieee802154address-is-unicast-and-hardwareaddress-is-unicast-.md) | api | `src/wire/ieee802154.rs:103` | code |
| 308 | [802.15.4 PAN ID presence wrong for 2015 src-only compressed frames and 2003/2006 address-less frames](308-pan-id-presence-rules-are-wrong-for-some-frames-a-2015-frame.md) | correctness | `src/wire/ieee802154.rs:243` | plausible |
| 309 | [802.15.4-2015 sequence number suppression and IE Present bits are ignored](309-802-15-4-2015-frames-sequence-number-suppression-and-ie-pres.md) | correctness | `src/wire/ieee802154.rs:353` | test |
| 310 | [Ieee802154Repr::emit and buffer_len ignore PAN presence rules, so emit then parse does not round-trip](310-public-ieee802154repr-emit-buffer-len-ignore-the-frame-versi.md) | doc-mismatch | `src/wire/ieee802154.rs:418` | test |
| 311 | [Assorted inaccurate public doc comments in wire and TCP](311-assorted-inaccurate-public-doc-comments-in-the-wire-and-sock.md) | doc-mismatch | `src/wire/ip.rs:167` | code |
| 312 | [IpAddr::prefix_len doc says it counts leading zeroes, it counts leading ones](312-ipaddr-prefix-len-doc-says-it-counts-leading-zeroes-it-count.md) | doc-mismatch | `src/wire/ip.rs:167` | code |
| 313 | [IPV4_MIN_MTU is documented as the minimum link MTU, but 576 is the minimum datagram every host must receive](313-ipv4-min-mtu-is-documented-as-the-minimum-link-mtu-but-576-i.md) | doc-mismatch | `src/wire/ipv4.rs:9` | RFC text |
| 314 | [IPv4 ingress accepts packets with source 127/8 (and 0/8, 240/4) from the wire](314-ipv4-ingress-accepts-packets-with-source-127-8-and-0-8-240-4.md) | rfc-compliance | `src/wire/ipv4.rs:64` | test |
| 315 | [Ipv4Cidr::from_netmask rejects the 0.0.0.0 netmask (/0), with no documented error](315-ipv4cidr-from-netmask-rejects-the-0-0-0-0-netmask-0-with-no-.md) | api | `src/wire/ipv4.rs:132` | test |
| 316 | [Scope classification gives ::1 and non-2000::/3 addresses Unknown scope, so ::1 can be picked as source](316-scope-classification-gives-1-and-non-2000-3-global-addresses.md) | rfc-compliance | `src/wire/ipv6.rs:175` | test |
| 317 | [Ipv6ExtHeader doc claims every extension header except Fragment uses the 8-octet length layout](317-ipv6extheader-doc-claims-every-extension-header-except-fragm.md) | doc-mismatch | `src/wire/ipv6ext.rs:9` | RFC text |
| 318 | [RA or NS/NA with a short Redirected Header option is discarded whole](318-ra-with-a-defined-but-inapplicable-option-of-short-length-re.md) | rfc-compliance | `src/wire/ndiscoption.rs:176` | test |
| 319 | [Wire lifetime accessors saturate at Duration::MAX, infinite PIO lifetimes can't be read or written, set_router_lifetime truncates](319-wire-lifetime-accessors-saturate-at-duration-max-so-infinite.md) | api | `src/wire/ndiscoption.rs:232` | test |
| 320 | [NdiscOption::check_len accepts Length 0, then data() and link_layer_addr() panic](320-ndiscoption-check-len-promises-no-accessor-will-panic-but-da.md) | doc-mismatch | `src/wire/ndiscoption.rs:155` | test |
| 321 | [SixlowpanFragRepr::emit silently truncates datagram sizes above 2047](321-sixlowpanfragrepr-emit-silently-truncates-datagram-sizes-abo.md) | api | `src/wire/sixlowpan/frag.rs:179` | code |
| 322 | [SixlowpanIphcRepr::parse truncates the 20-bit flow label to 16 bits and returns ECN unshifted](322-sixlowpaniphcrepr-parse-truncates-the-20-bit-flow-label-to-1.md) | wire-correctness | `src/wire/sixlowpan/iphc.rs:209` | RFC text |
| 323 | [Uncompressed IPv6 dispatch (0x41) is dropped, and the gap is not documented](323-uncompressed-ipv6-dispatch-0x41-mesh-and-lowpan-bc0-headers-.md) | rfc-compliance | `src/wire/sixlowpan/mod.rs:44` | code |
| 324 | [NHC extension headers with EID 4, 5, 6 or 7 decompress as Hop-by-Hop](324-nhc-extension-headers-with-eid-4-mobility-5-6-reserved-or-7-.md) | correctness | `src/wire/sixlowpan/nhc.rs:62` | test |
| 325 | [TcpSeqNumber ordering is not antisymmetric at distance 2^31, and its operators panic undocumented](325-tcpseqnumber-ordering-is-not-antisymmetric-at-distance-2-31-.md) | doc-mismatch | `src/wire/tcp.rs:74` | test |
| 326 | [TcpOption::emit panics for Unknown options unless the buffer is exactly the option's length](326-public-tcpoption-emit-panics-for-unknown-options-unless-the-.md) | panic | `src/wire/tcp.rs:587` | test |
| 327 | [build.rs scripts use env::vars(), which panics on any non-UTF-8 environment variable](327-xarxa-driver-build-rs-uses-env-vars-which-panics-if-any-envi.md) | build | `xarxa-driver/build.rs:42` | test |
| 328 | [packet-buf-align cannot be set through xarxa, and XARXA_PACKET_BUF_ALIGN is silently ignored](328-packet-buf-align-cannot-be-set-through-xarxa-no-forwarding-f.md) | doc-mismatch | `xarxa-driver/src/config.rs:16` | code |
| 329 | [PACKET_BUF_SIZE doc suggests 128 for 802.15.4, but full frames don't fit once decompressed](329-packet-buf-size-doc-suggests-128-for-ieee-802-15-4-but-decom.md) | doc-mismatch | `xarxa-driver/src/config.rs:65` | code |
| 330 | [ChecksumOffload docs don't say what rx/tx mean for frames the hardware skips, or that failed frames must be dropped](330-checksumoffload-docs-don-t-define-rx-tx-semantics-for-frames.md) | doc-mismatch | `xarxa-driver/src/lib.rs:90` | code |
| 331 | [Capabilities::max_transmission_unit doesn't say it includes the Ethernet header, and values below 14 underflow](331-capabilities-max-transmission-unit-doc-doesn-t-say-what-it-c.md) | doc-mismatch | `xarxa-driver/src/lib.rs:170` | code |
| 332 | [Timestamp::from_seconds_and_nanos does not enforce the documented sub-second invariant](332-timestamp-from-seconds-and-nanos-does-not-enforce-the-docume.md) | api | `xarxa-driver/src/meta.rs:41` | code |

### Info (31)

| # | Finding | Category | Location | Verified by |
|---|---|---|---|---|
| 333 | [DESIGN.md says no congestion control and no TCP timestamps by default, but defaults enable both](333-design-md-says-there-is-no-congestion-control-and-no-tcp-tim.md) | doc-mismatch | `Cargo.toml:55` | code |
| 334 | [Default socket RX queue bounds add up past the pool size](334-default-table-sizes-let-socket-rx-queues-pin-the-whole-pool-.md) | resource-leak | `src/config.rs:125` | code |
| 335 | [DNS txid comes from the same non-cryptographic PRNG that emits raw TCP ISNs](335-dns-txid-comes-from-a-non-cryptographic-prng-that-also-emits.md) | security | `src/dns.rs:282` | code |
| 336 | [Quoted packet parsing ignores the IPv4 fragment offset and reads payload bytes of non-first fragments as ports](336-quoted-packet-parsing-ignores-the-ipv4-fragment-offset-and-r.md) | correctness | `src/icmp_error.rs:128` | code |
| 337 | [DHCP client messages are shorter than the 300-byte BOOTP minimum](337-client-messages-are-shorter-than-the-300-byte-bootp-minimum.md) | interop | `src/iface/dhcpv4.rs:554` | code |
| 338 | [DHCP ACK in REQUESTING is not checked against the selected server identifier](338-dhcp-offer-ack-accepted-from-any-source-as-long-as-xid-and-c.md) | security | `src/iface/dhcpv4.rs:649` | code |
| 339 | [Broadcast recognition is limited to 255.255.255.255 and each prefix's all-ones address](339-broadcast-recognition-limited-to-255-255-255-255-and-the-con.md) | rfc-compliance | `src/iface/mod.rs:885` | RFC text |
| 340 | [SLAAC interface identifiers are the modified EUI-64 of the MAC](340-slaac-interface-identifiers-are-the-modified-eui-64-of-the-m.md) | security | `src/iface/slaac.rs:383` | code |
| 341 | [Raw socket ingress copy is allocated and copied even when the RX queue is full](341-ingress-copy-for-a-raw-socket-is-allocated-and-copied-even-w.md) | performance | `src/raw.rs:651` | code |
| 342 | [L4 checksum offload flags are honored on IEEE 802.15.4 interfaces](342-l4-tx-offload-is-honored-on-ieee-802-15-4-interfaces-a-zero-.md) | hardening | `src/udp.rs:950` | code |
| 343 | [Ephemeral ports use only 49152-65535, RFC 6056 recommends the largest possible range](343-ephemeral-ports-use-only-49152-65535-while-rfc-6056-says-to-.md) | rfc-compliance | `src/stack.rs:492` | RFC text |
| 344 | [set_hostname checks only length, and the hostname feature does not imply dhcpv4](344-set-hostname-accepts-any-bytes-and-without-dhcpv4-the-hostna.md) | api | `src/stack.rs:588` | code |
| 345 | [RFC 1042 LLC/SNAP frames are dropped, and the driver contract does not say who pads short frames](345-rfc-1042-802-3-length-llc-snap-frames-and-short-frame-paddin.md) | rfc-compliance | `src/stack.rs:1274` | code |
| 346 | [IPv4 source-route options are ignored: the recorded route is not passed up or reversed](346-ipv4-source-route-and-other-ip-options-are-ignored-not-rejec.md) | rfc-compliance | `src/stack.rs:1305` | RFC text |
| 347 | [Echo requests to an IPv4 broadcast address are answered by default](347-icmp-echo-reply-to-subnet-broadcast-destination-smurf-amplif.md) | security | `src/stack.rs:1585` | code |
| 348 | [Coverage note: ICMP redirects are ignored, NDISC and RA guards are mostly correct](348-icmp-redirects-are-correctly-ignored-ra-source-hop-limit-che.md) | security | `src/stack.rs:1884` | code |
| 349 | [Neighbor cache can be overwritten by spoofed ARP or NA with Override (unauthenticated ND)](349-ndisc-arp-cache-poisoning-cache-filled-from-any-solicited-or.md) | security | `src/stack.rs:2313` | code |
| 350 | [IPv6 flow label is always zero](350-ipv6-flow-label-is-always-zero.md) | rfc-compliance | `src/stack.rs:2832` | RFC text |
| 351 | [RST to an unmatched non-SYN segment without ACK omits the ACK field](351-rst-sent-for-an-unmatched-non-syn-segment-without-ack-bit-ha.md) | rfc-compliance | `src/tcp/mod.rs:846` | RFC text |
| 352 | [TCP ICMP-error sequence check accepts SEG.SEQ == SND.NXT](352-tcp-icmp-error-sequence-check-accepts-seg-seq-snd-nxt-rfc-59.md) | security | `src/tcp/mod.rs:951` | test |
| 353 | [TCP soft ICMP errors are recorded without waking any waker](353-tcp-soft-icmp-errors-are-recorded-without-waking-any-waker.md) | api | `src/tcp/mod.rs:955` | code |
| 354 | [Without a congestion-control feature, every RTO resends the whole window](354-default-no-congestion-control-resends-the-whole-window-in-on.md) | rfc-compliance | `src/tcp/mod.rs:1851` | code |
| 355 | [Zero-window probe timer keeps firing after the tx buffer empties, suppressing keep-alive](355-zero-window-probe-timer-keeps-firing-after-the-tx-buffer-emp.md) | other | `src/tcp/mod.rs:1514` | test |
| 356 | [Keep-alives always carry one garbage octet, and the comment misstates RFC 1122](356-keep-alives-always-carry-one-garbage-octet-shld-12-says-no-d.md) | rfc-compliance | `src/tcp/mod.rs:2086` | RFC text |
| 357 | [Broken intra-doc links in public docs](357-broken-intra-doc-links-in-public-docs.md) | doc-mismatch | `src/udp.rs:506` | test |
| 358 | [ICMP errors on unconnected UDP sockets can be forged into recv(), undocumented](358-icmp-errors-on-unconnected-server-sockets-are-attacker-injec.md) | security | `src/udp.rs:1090` | code |
| 359 | [checksum::data overflows its u32 accumulator for slices over about 128 KiB](359-checksum-data-s-u32-accumulator-overflows-for-slices-over-ab.md) | panic | `src/wire/ip.rs:544` | test |
| 360 | [Public `checksum::pseudo_header` panics via `unreachable!()` on mixed address families, undocumented](360-public-checksum-pseudo-header-panics-via-unreachable-on-mixe.md) | api | `src/wire/ip.rs:605` | test |
| 361 | [Wire wrappers need `&mut [u8]` even for reading, so peeked socket data cannot be parsed without a copy](361-wire-wrappers-need-mut-u8-even-for-reading-so-peeked-socket-.md) | api | `src/wire/ipv4.rs:228` | code |
| 362 | [`is_link_local` matches only fe80::/64, not the fe80::/10 link-local range](362-is-link-local-matches-only-fe80-64-not-the-fe80-10-link-loca.md) | rfc-compliance | `src/wire/ipv6.rs:140` | test |
| 363 | [`Icmpv6Packet::set_qrv` panics on values >= 8 without documenting it](363-wire-mldpacket-style-set-qrv-panics-on-values-8-without-docu.md) | doc-mismatch | `src/wire/mld.rs:145` | code |

## Dropped

Reported, then refuted during verification.

| Reported severity | Location | Report | Why dropped |
|---|---|---|---|
| low | `src/stack.rs:372` | IPv4 link-local (169.254/16) destinations are sent to the default router | refuted: The behavior is real. With a default route, a UDP send to 169.254.3.4 ARPs for the gateway 192.168.1.254 (confirmed in a test). The RFC claim does not hold, though. The quoted §2.6.2 requirements bind only a host that implements RFC 3927, and xarxa does not implement IPv4LL. The finder's ... |
| info | `src/stack.rs:1561` | ICMP echo reply reuses the request buffer including its PacketMeta id but the request source is only checked for unicast | refuted: This entry is a note on what the finder reviewed, not a defect, and the finder says no defect was found. The echo reply path does reject non-unicast sources, resets PacketMeta to its default, and recomputes the checksum (or zeroes it for offload). There is nothing to confirm. |
| medium | `src/tcp/congestion.rs:47` | Default build has no congestion control (MUST-19) | refuted: The finding rests on the default build having no congestion control. That is false. `tcp-cubic` is in the crate's `default` feature list, so a default build uses `cubic::Cubic` (congestion.rs:50-51), not `NoControl`. `NoControl` is only used when the user turns off default features and ... |
| info | `src/udp.rs:981` | UDP does not drop datagrams whose destination is broadcast/multicast when no socket wants them beyond ICMP suppression; broadcast source not rejected at UDP layer | refuted: This is a coverage note that reports no defect, and its claims check out. process_ipv4 drops non-unicast sources (except unspecified, which it allows on purpose). process_ipv6 drops non-unicast sources. transmit_icmpv4_error requires unicast source and destination. There is no defect to ... |
