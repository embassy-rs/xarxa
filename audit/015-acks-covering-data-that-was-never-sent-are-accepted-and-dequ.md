# 015. ACKs covering data that was never sent are accepted and dequeue it from the TX buffer

| | |
|---|---|
| Severity | high |
| Category | correctness |
| Location | [src/tcp/mod.rs:1056](../src/tcp/mod.rs#L1056), [src/tcp/mod.rs:980](../src/tcp/mod.rs#L980), [src/tcp/mod.rs:271](../src/tcp/mod.rs#L271) |
| Features | default |
| Verification | reproduced with a test |

## Summary

The upper bound of the acceptable ACK range is `local_seq_no + tx_buffer.len() + control_len`: all queued data plus a FIN that may not have been sent. It should be SND.NXT (the highest sequence sent). An ACK beyond SND.NXT removes unsent bytes from the TX ring. The peer never gets them and the stream is desynchronized.

## Details

src/tcp/mod.rs:1052
```rust
let unacknowledged = self.tx_buffer.len() + control_len;

// Acceptable ACK range (both inclusive)
let mut ack_min = self.local_seq_no;
let ack_max = self.local_seq_no + unacknowledged;
```

An ACK up to `ack_max` is accepted. The ACK processing then dequeues `ack_number - local_seq_no` bytes from the TX buffer and moves `local_seq_no` and `remote_last_seq` to it. After that the real peer's ACKs are below SND.UNA and the missing bytes cannot be retransmitted.

`sent_fin` is taken from the state (src/tcp/mod.rs:980), not from whether a FIN left. So an ACK of an unsent FIN in FIN-WAIT-1, CLOSING or LAST-ACK is accepted too.

The loose bound exists because the RTO rewinds `remote_last_seq` to `local_seq_no`, so it is not the highest-sent mark. `rtte.max_seq_sent` (src/tcp/mod.rs:271) already tracks that.

The code implements the RFC 5961 lower bound (`ack_number < ack_min - self.remote_max_win_len`, a few lines below) but not the upper bound.

## Failure scenario

An established socket has 6 KB queued but not sent (held back by Nagle, cwnd or the peer window). A buggy peer, or an injected segment with an acceptable sequence number, carries an ACK within that unsent range. The data is discarded as delivered and the byte stream reaching the real peer has a hole. The connection then hangs until the user timeout, if one is set.

## RFC reference

RFC 9293 §3.10.7.4, ESTABLISHED STATE: "If the ACK acks something not yet sent (SEG.ACK > SND.NXT), then send an ACK, drop the segment, and return."

RFC 9293 §3.10.7.4: "TCP stacks that implement RFC 5961 MUST add an input check that the ACK value is acceptable only if it is in the range of ((SND.UNA - MAX.SND.WND) =< SEG.ACK =< SND.NXT). All incoming segments whose ACK value doesn't satisfy the above condition MUST be discarded and an ACK sent back."

## Reproduction

Added to `mod test` of src/tcp/mod.rs:

```rust
#[test]
fn audit_ack_beyond_snd_nxt() {
    let mut s = socket_established();
    s.view().send_slice(b"abcdef").unwrap();
    send!(s, TcpRepr { seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1 + 6), ..SEND_TEMPL }, None);
    println!("tx_len={} local_seq_no={} remote_last_seq={}", s.tx_buffer.len(), s.local_seq_no, s.remote_last_seq);
    assert_eq!(s.tx_buffer.len(), 6, "unsent data was dequeued by an ACK beyond SND.NXT");
}
```

```
tx_len=0 local_seq_no=10007 remote_last_seq=10007
assertion `left == right` failed: unsent data was dequeued by an ACK beyond SND.NXT
  left: 0
  right: 6
```

No reply was sent, and the 6 bytes are gone.

## Suggested fix

Bound `ack_max` by the highest sequence number ever sent, SYN and FIN included (a `snd_max` field, or `rtte.max_seq_sent`). Answer ACKs above it with an ACK (or the rate-limited challenge ACK) and drop the segment. Derive `sent_fin` from whether the FIN was actually sent.
