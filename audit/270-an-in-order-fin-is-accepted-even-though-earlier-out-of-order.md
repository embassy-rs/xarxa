# 270. An in-order FIN is accepted even though earlier out-of-order data lies past it: bytes after the FIN are delivered and ACKed

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/tcp/mod.rs:1236](../src/tcp/mod.rs#L1236), [src/tcp/mod.rs:1527](../src/tcp/mod.rs#L1527), [src/tcp/mod.rs:1560](../src/tcp/mod.rs#L1560), [src/tcp/mod.rs:1312](../src/tcp/mod.rs#L1312) |
| Features | default |
| Verification | reproduced with a test |

## Summary
A FIN segment starting at RCV.NXT is accepted even if the assembler already holds data past the FIN. That data is merged into the stream, so the application reads bytes after end of stream, and the ACK covers sequence numbers past the FIN. Only a peer sending inconsistent FIN positions, or an attacker able to inject in-window data, can trigger it. Found by the fuzzer (crash-cab18fbee3c36927c423f8a937fbe67739f35698).

## Details
src/tcp/mod.rs:1236, the only FIN check:
```rust
if control == TcpControl::Fin && window_start < segment_start {
```
Nothing checks the assembler for data past `segment_end`. src/tcp/mod.rs:1527 `add_then_remove_front(payload_offset, payload_len)` returns a `contig_len` that includes the stored range, and src/tcp/mod.rs:1560 `enqueue_unallocated(contig_len)` makes it readable. The FIN arm (src/tcp/mod.rs:1312) adds 1 to `remote_seq_no` and sets `rx_fin_received`.

## Failure scenario
Stream offsets from REMOTE_SEQ+1. The assembler holds bytes 4..16. A segment for 0..12 with FIN at 12 arrives. The socket goes to CLOSE-WAIT and ACKs offset 17 instead of 13. `recv` returns "abcdefghijklMNOP" (4 bytes past the FIN), then `Finished`.

## Reproduction
Test in the `src/tcp/mod.rs` test module, on unmodified HEAD:
```rust
#[test]
fn zz_fin_before_ooo_data() {
    let mut s = socket_established();
    send!(s, TcpRepr { control: TcpControl::Fin, seq_number: REMOTE_SEQ + 1 + 4,
        ack_number: Some(LOCAL_SEQ + 1), payload: &b"EFGHIJKLMNOP"[..], ..SEND_TEMPL },
        Some(TcpRepr { seq_number: LOCAL_SEQ + 1, ack_number: Some(REMOTE_SEQ + 1), ..RECV_TEMPL }));
    let r = send(&mut s, Instant::from_millis(0), &TcpRepr { control: TcpControl::Fin,
        seq_number: REMOTE_SEQ + 1, ack_number: Some(LOCAL_SEQ + 1), payload: &b"abcdefghijkl"[..], ..SEND_TEMPL });
    println!("immediate reply {:?}", r.map(|r| r.ack_number));
    println!("state {:?} rx len {}", s.state, s.rx_buffer.len());
    let mut buf = [0u8; 64];
    let n = s.view().recv_slice(&mut buf).unwrap();
    println!("recv {:?}", core::str::from_utf8(&buf[..n]));
    println!("recv again {:?}", s.view().recv_slice(&mut buf));
}
```
Output:
```
immediate reply Some(Some(SeqNumber(-9983)))   (correct FIN ACK: SeqNumber(-9987))
state CloseWait rx len 16
recv Ok("abcdefghijklMNOP")
recv again Err(Finished)
```

## Suggested fix
When accepting a FIN at `segment_end`, truncate `contig_len` to the FIN position and clear assembler data past it. Or ignore the FIN when the assembler holds data past it.
