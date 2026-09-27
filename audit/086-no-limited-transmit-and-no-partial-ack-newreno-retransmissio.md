# 086. No Limited Transmit and no partial-ACK retransmission, so small windows and multiple losses per window fall back to an RTO

| | |
|---|---|
| Severity | medium |
| Category | performance |
| Location | [src/tcp/mod.rs:1442](../src/tcp/mod.rs#L1442), [src/tcp/mod.rs:1454](../src/tcp/mod.rs#L1454), [src/tcp/mod.rs:2022](../src/tcp/mod.rs#L2022), [src/tcp/congestion/cubic.rs:171](../src/tcp/congestion/cubic.rs#L171), [src/tcp/congestion/cubic.rs:101](../src/tcp/congestion/cubic.rs#L101), [src/tcp/congestion/reno.rs:70](../src/tcp/congestion/reno.rs#L70), [src/tcp/congestion/reno.rs:53](../src/tcp/congestion/reno.rs#L53) |
| Features | `tcp-cubic` or `tcp-reno` for the Limited Transmit part. The partial-ACK part applies to every build. |
| Verification | confirmed against the code and the RFC text |

## Summary

The sender does nothing on the 1st and 2nd duplicate ACK. Fast retransmit fires only at the 3rd. After a fast retransmit, the first ACK of new data ends fast recovery and resets the duplicate-ACK count, and nothing retransmits the next hole. So a loss followed by fewer than 3 segments, and a second loss in the same window, both wait for the RTO. In a test against Linux with 1% loss, xarxa sending took 3-9x longer than Linux sending the same data back.

Only the Limited Transmit part is an RFC violation (a SHOULD). Plain Reno without partial-ACK handling is allowed by RFC 5681. NewReno or SACK recovery is only RECOMMENDED.

## Details

src/tcp/mod.rs:1442, fast retransmit only at exactly 3 duplicate ACKs:

```rust
if self.local_rx_dup_acks == 3 {
    self.timer.set_for_fast_retransmit();
    debug!("started fast retransmit");
}
```

src/tcp/congestion/cubic.rs:171 (reno.rs:70 is the same). cwnd grows on duplicate ACKs only inside fast recovery:

```rust
fn on_dup_ack(&mut self, _now: Instant, len: usize, _in_flight: usize) {
    if self.in_fast_recovery {
        self.cwnd = self.cwnd.saturating_add(len).min(self.rwnd).max(self.mss);
    }
}
```

src/tcp/mod.rs:2022, the new-data limit has no `cwnd + 2*SMSS` allowance for the first two duplicate ACKs:

```rust
let limit = tx_len.min(self.remote_win_len).min(self.congestion_controller.window());
```

A partial ACK takes the `_ =>` arm at src/tcp/mod.rs:1454-1466. It resets `local_rx_dup_acks` and calls `on_ack`. src/tcp/congestion/cubic.rs:101 (reno.rs:53) leaves fast recovery on any new-data ACK, partial or not:

```rust
if self.in_fast_recovery {
    self.in_fast_recovery = false;
    self.cwnd = self.ssthresh;
```

There is no `recover` point and nothing retransmits the segment now at SND.UNA. The next hole needs 3 fresh duplicate ACKs or the RTO. README lists "TCP SACK, acting on ranges received from the peer" as not implemented. Partial-ACK recovery (RFC 6582) does not need SACK.

Without a congestion-control feature, cwnd does not limit sending, so Limited Transmit does not apply there. The partial-ACK gap does.

## Failure scenario

Pcap, SACK available, xarxa port 7001 sending to Linux, IPv4, netem 10ms±3ms, 1% loss, 10% reorder:

```
3.940798 X  retransmit 466257 (fast retransmit)
3.958439 L  ack 473497 sack {474945:477841}     <- partial ACK, 473497 is lost too
3.958446 X  new data 479289                    <- no retransmission of 473497
3.971015 L  ack 473497 (dup #1)
3.974101 L  ack 473497 (dup #2)                 <- never reaches 3
4.159316 X  retransmit 473497 (RTO, 200 ms idle)
```

Second pcap, Linux with SACK, timestamps and wscale disabled, netem 5 ms delay, 1% loss. 1353421 was lost with only 2 segments behind it. xarxa got 2 duplicate ACKs (5.427887, 5.437911), sent nothing, and waited for the RTO at 5.628169. Over the 3 MB transfer xarxa was idle on RTOs for 2.6 s of 6.4 s. Linux sent the same 3 MB the other way in 0.69 s.

With small send buffers (the examples use 4 KiB) only 2-3 segments are in flight, so a single loss often cannot produce 3 duplicate ACKs. Limited Transmit does not help there, since it needs unsent data and the whole buffer is already in flight. Only partial-ACK or SACK recovery, or a lower duplicate-ACK threshold, would.

## RFC reference

RFC 5681 §3.2, step 1:

> On the first and second duplicate ACKs received at a sender, a TCP SHOULD send a segment of previously unsent data per [RFC3042] provided that the receiver's advertised window allows, the total FlightSize would remain less than or equal to cwnd plus 2*SMSS, and that new data is available for transmission. Further, the TCP sender MUST NOT change cwnd to reflect these two segments [RFC3042].

RFC 5681 §4.3:

> We RECOMMEND that TCP implementors employ some form of advanced loss recovery that can cope with multiple losses in a window of data. The algorithms detailed in [RFC3782] and [RFC3517] conform to the general principles outlined above.

## Suggested fix

- Limited Transmit: on duplicate ACK 1 and 2, allow new data up to a flight size of cwnd + 2*SMSS, without touching cwnd.
- NewReno (RFC 6582): record `recover = SND.NXT` on entering fast recovery. On an ACK that advances SND.UNA but stays below `recover`, retransmit the first unacknowledged segment, deflate cwnd by the amount ACKed, and stay in fast recovery.
