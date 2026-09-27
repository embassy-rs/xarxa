# 254. cwnd is never reduced after idle and grows while app-limited (Reno and CUBIC)

| | |
|---|---|
| Severity | low |
| Category | rfc-compliance |
| Location | [src/tcp/congestion/cubic.rs:106](../src/tcp/congestion/cubic.rs#L106), [src/tcp/congestion/reno.rs:59](../src/tcp/congestion/reno.rs#L59), [src/tcp/congestion/cubic.rs:65](../src/tcp/congestion/cubic.rs#L65), [src/tcp/congestion/cubic.rs:234](../src/tcp/congestion/cubic.rs#L234), [src/tcp/congestion/reno.rs:107](../src/tcp/congestion/reno.rs#L107) |
| Features | `tcp-cubic` (default) or `tcp-reno` |
| Verification | confirmed against the RFC text |

## Summary
Both controllers grow cwnd on every ACK of new data, whether or not the flow was cwnd-limited, up to the largest window the peer ever advertised. Neither applies the RFC 5681 restart window after an idle longer than the RTO. After an idle or app-limited period, a burst can go out at line rate, bounded only by the tx buffer.

## Details
- Reno `on_ack` (reno.rs:59-67) adds to cwnd on every new-data ACK.
- CUBIC slow start (cubic.rs:106-109) and CA (cubic.rs:150-168) do the same.
- `set_remote_window` only ever increases `rwnd` (cubic.rs:234, reno.rs:107), so a flow sending one segment per RTT still drives cwnd up to it.
- CUBIC's `absorb_idle` (cubic.rs:65) only slides `recovery_start`. It never reduces cwnd, and it covers only fully idle periods (in_flight == 0), not partially app-limited ones.
- Nothing in `dispatch` compares idle time to the RTO.

Small embedded tx buffers limit the impact.

## Failure scenario
A device sends a small status message every few seconds, and cwnd climbs to the peer's max window. After an hour of silence it uploads 32 KB of queued logs back to back into a slow uplink, overruns the bottleneck queue, and takes an RTO.

## RFC reference
RFC 5681 §4.1: "Therefore, a TCP SHOULD set cwnd to no more than RW before beginning transmission if the TCP has not sent data in an interval exceeding the retransmission timeout." with "RW = min(IW,cwnd)".

RFC 9438 §4.2: "The elapsed time t in Figure 1 MUST NOT include periods during which cwnd has not been updated due to application-limited behavior (see Section 5.8)."

RFC 9438 §5.8: "CUBIC does not increase its congestion window if a flow is application limited."

## Suggested fix
Record the time of the last data transmission. Before sending, if it is more than one RTO ago, set cwnd to min(cwnd, IW). In `on_ack`, only grow cwnd when the flight before the ACK was close to cwnd.
