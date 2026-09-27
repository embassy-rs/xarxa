# 017. After an RTO rewind, pure ACKs and RSTs carry the rewound SND.NXT, so a bidirectional connection where both sides time out hangs forever

| | |
|---|---|
| Severity | high |
| Category | hang-stall |
| Location | [src/tcp/mod.rs:1851](../src/tcp/mod.rs#L1851), [src/tcp/mod.rs:1919](../src/tcp/mod.rs#L1919), [src/tcp/mod.rs:2069](../src/tcp/mod.rs#L2069), [src/tcp/mod.rs:2127](../src/tcp/mod.rs#L2127), [src/tcp/mod.rs:881](../src/tcp/mod.rs#L881), [src/tcp/mod.rs:1963](../src/tcp/mod.rs#L1963), [src/tcp/mod.rs:1117](../src/tcp/mod.rs#L1117) |
| Features | default (also with `tcp-reno`, no congestion control, with and without `tcp-timestamps` and `tcp-sack`) |
| Verification | reproduced with a test |

## Summary

When the RTO fires, `dispatch` rewinds `remote_last_seq` to `local_seq_no` (go-back-N). Every pure ACK, window update, `ack_reply` and abort RST then uses that rewound value as SEG.SEQ. If the peer already received data past that point (only its ACKs were lost), the peer's RCV.NXT is ahead of that SEG.SEQ. The zero-length acceptability test fails and the peer drops the segment along with its ACK and window. When both ends of a bidirectional connection time out before either side's retransmission arrives, every ACK in both directions is discarded and the connection never makes progress again.

## Details

src/tcp/mod.rs:1851, on RTO:

```rust
self.remote_last_seq = self.local_seq_no;
```

src/tcp/mod.rs:1919, the base repr every dispatch segment starts from:

```rust
seq_number: self.remote_last_seq,
```

The pure ACK at src/tcp/mod.rs:2069-2071 calls `send_segment(.., TcpControl::None, offset, 0)` with `offset = self.flight_size()`. `send_segment` sets `seq_number: self.local_seq_no + offset` (src/tcp/mod.rs:2127), which is the rewound `remote_last_seq`.

src/tcp/mod.rs:881, `ack_reply`, used for out-of-window data (1194) and in-order ACKs (1604):

```rust
reply_repr.seq_number = self.remote_last_seq;
```

src/tcp/mod.rs:1963-1964, the RST of an aborted socket, also at the rewound value:

```rust
let offset = self.flight_size();
self.send_segment(clock, &mut send, &repr, TcpControl::Rst, offset, 0)?;
```

On the receiving side, src/tcp/mod.rs:1117-1123 rejects a zero-length segment with SEG.SEQ < RCV.NXT. It falls through to `challenge_ack_reply` (1197) and returns before the ACK and window are processed.

Mechanism: A and B both have more than one post-RTO cwnd (1 MSS) of data in flight. The peer received all of it, but the ACKs were lost. Both RTOs fire. Each side rewinds and retransmits one MSS. That retransmission is entirely below the peer's RCV.NXT, so the peer answers with `ack_reply`, whose SEQ is its own rewound `remote_last_seq` (local_seq_no + what was retransmitted), below our RCV.NXT. We drop it. The other direction is symmetric. Neither SND.UNA advances. With no timeout set (the default, see 016) the RTO backs off to 60 s and this repeats forever.

One-sided RTOs heal: the peer's replies carry an acceptable SEQ, and `remote_last_seq` moves forward again at src/tcp/mod.rs:1478. The hang also does not happen if the whole flight fits in the post-RTO cwnd, since the retransmission then restores `remote_last_seq`.

Second symptom, same root cause: `abort()` after an RTO sends an RST with SEQ below the peer's RCV.NXT. The peer drops it as out of window (xarxa itself does this at 1159-1161). The peer only learns of the abort at its next retransmission, up to 60 s later.

A two-stack netsim (default features, IPv4, 45 ms one-way, 400 kB each way, link down A->B 932-3591 ms and B->A 926-1515 ms) was still stuck at 640 s simulated. In a sweep of 1500 random link-outage scenarios, 84 hung on HEAD. With the fix below, 0 hung. Under 5-7 % random loss both ways it hit about 5 in 1000 seeds.

## Failure scenario

A bidirectional transfer (request/response pipelining, or two bulk streams). The link drops for a few seconds: Wi-Fi roam, cable replug, cellular handover. Segments sent just before the outage arrive, their ACKs do not. Both RTOs fire during the outage. After the link returns, each side's retransmission is old to the peer, and the peer's ACK reply is dropped. The connection is wedged permanently and, with no timeout set, never errors.

## RFC reference

RFC 9293 §3.10.7.4:

> If an incoming segment is not acceptable, an acknowledgment should be sent in reply (unless the RST bit is set, if so drop the segment and return):
>
> <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
>
> After sending the acknowledgment, drop the unacceptable segment and return.

Acceptability for Segment Length 0, Receive Window > 0: "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND".

The receiver behaviour is per spec. In RFC 9293, SND.NXT never moves backwards: retransmission comes from the retransmission queue. So an ACK sent at SND.NXT stays acceptable. xarxa sends it at the rewound value.

## Reproduction

Helpers added to `mod test` in src/tcp/mod.rs, in a scratch copy of HEAD:

```rust
fn zz_own(r: TcpRepr) -> TcpRepr<'static> { let p: &'static [u8] = [r.payload, r.payload2].concat().leak(); TcpRepr { payload: p, payload2: &[], ..r } }
fn zz_out(s: &mut TestSocket, t: Instant) -> Vec<TcpRepr<'static>> { s.stack.inner.now = t; let mut clock = Clock::new(t); let mut v = Vec::new(); let _: Result<(), ()> = s.sockets.get_mut(0).dispatch(&mut s.stack.tx_context(), &mut clock, |_, _, _, _, _, r| { v.push(zz_own(r)); Ok(()) }); s.deadline = clock.next(); v }
fn zz_deliver(s: &mut TestSocket, t: Instant, r: &TcpRepr<'static>) -> Option<TcpRepr<'static>> { let m = TcpRepr { src_port: r.dst_port, dst_port: r.src_port, ..*r }; send(s, t, &m).map(zz_own) }
fn zz_pair(tx: usize, rx: usize) -> (TestSocket, TestSocket) { let a = socket_established_with_buffer_sizes(tx, rx); let mut b = socket_established_with_buffer_sizes(tx, rx); b.local_seq_no = REMOTE_SEQ + 1; b.remote_last_seq = REMOTE_SEQ + 1; b.remote_seq_no = LOCAL_SEQ + 1; b.remote_last_ack = Some(LOCAL_SEQ + 1); (a, b) }
fn zz_pair_mss(tx: usize, rx: usize, mss: usize, win: usize) -> (TestSocket, TestSocket) { let (mut a, mut b) = zz_pair(tx, rx); for s in [&mut a, &mut b] { s.remote_mss = mss; s.congestion_controller.set_mss(mss); s.remote_win_len = win; s.remote_max_win_len = win; } (a, b) }
// zz_exchange(a, b, t, verbose): up to 50 rounds of zz_out on both sides, delivering
// every segment and every reply to the other side at time t (lossless, zero delay),
// until neither sends anything.
// zz_run(a, b, until_ms, verbose): loop { let t = a.deadline.min(b.deadline);
// if t > Instant::from_millis(until_ms) { break; } zz_exchange(a, b, t, verbose); }

#[test]
fn zz_rto_rewind_mutual_hang2() {
    let (mut a, mut b) = zz_pair_mss(4096, 4096, 100, 1000);
    a.view().send_slice(&[b'a'; 500]).unwrap();
    b.view().send_slice(&[b'b'; 500]).unwrap();
    let t0 = Instant::from_millis(0);
    let da = zz_out(&mut a, t0); let db = zz_out(&mut b, t0);
    for r in &da { let _ = zz_deliver(&mut b, t0, r); }
    for r in &db { let _ = zz_deliver(&mut a, t0, r); }
    let _ = zz_out(&mut a, t0); let _ = zz_out(&mut b, t0); // the only loss: one pure ACK each way
    zz_run(&mut a, &mut b, 40_000, true);
    zz_run(&mut a, &mut b, 600_000, false);
    assert!(a.tx_buffer.len() == 0 && b.tx_buffer.len() == 0, "connection wedged: data never acked on a lossless link");
}
```

Output (excerpt):

```
A sent 5 segs, B sent 5 segs
lost ACKs: 1 1
A: local_seq=10001 remote_last_seq=10501 rcv_nxt=-9500
B: local_seq=-10000 remote_last_seq=-9500 rcv_nxt=10501
t=1000
  A>B seq=10001 ack=Some(-9500) len=100 win=3596 ctl=None
  B>A seq=-10000 ack=Some(10501) len=100 win=3596 ctl=None
  A>B seq=10101 ack=Some(-9500) len=0 win=3596 ctl=None
  B>A seq=-9900 ack=Some(10501) len=0 win=3596 ctl=None
(identical at t=3000, 7000, 15000, 31000)
after 600s: A tx_buffer.len=500 local_seq=10001 remote_last_seq=10101 timer=Retransmit { expires_at: Instant { millis: 603000 } }; B tx_buffer.len=500 local_seq=-10000
panicked: connection wedged: data never acked on a lossless link
```

Control: a one-sided variant (only A sends) passes, and A's tx buffer drains.

## Suggested fix

Track the highest sequence number ever sent (SND.MAX; `rtte.max_seq_sent` already holds it for data). Use `max(SND.MAX, remote_last_seq)` as SEG.SEQ for segments that carry no new data: pure ACKs and window updates in `send_segment`, `ack_reply`, and the abort RST. Do not feed it back into `remote_last_seq`, or go-back-N breaks. Clamp to the peer's window edge like Linux's `tcp_acceptable_seq()`. This removed every hang in the outage sweep. It also covers 018.
