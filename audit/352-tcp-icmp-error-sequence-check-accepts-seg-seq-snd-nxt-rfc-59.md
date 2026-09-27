# 352. TCP ICMP-error sequence check accepts SEG.SEQ == SND.NXT

| | |
|---|---|
| Severity | info |
| Category | security |
| Location | [src/tcp/mod.rs:951](../src/tcp/mod.rs#L951) |
| Features | default (`icmp-errors`) |
| Verification | reproduced with a test |

## Summary
`process_icmp_error` accepts SND.UNA <= seq <= SND.NXT. RFC 5927 §4.1 describes the half-open range SND.UNA <= SEG.SEQ < SND.NXT, which accepts nothing when no data is in flight. On an idle synchronized connection, a spoofed error quoting exactly SND.NXT is recorded as a soft error.

## Details
src/tcp/mod.rs:951:
```rust
if seq < self.local_seq_no || seq > self.remote_last_seq {
```
`remote_last_seq` is SND.NXT. RFC 5927 is Informational, so this is not a MUST. The inclusive bound has a reason: a genuine error about one of our pure ACKs quotes SEG.SEQ == SND.NXT. The attacker still has to guess the exact 32-bit SND.NXT, and on a synchronized connection the only effect is the soft error slot.

## RFC reference
RFC 5927 §4.1: "These implementations check that the TCP sequence number contained in the payload of the ICMP error message is within the range SND.UNA =< SEG.SEQ < SND.NXT." ... "For a TCP endpoint with no data "in flight", this would completely eliminate the possibility of success of these attacks."

## Reproduction
In the `tcp` module test harness:
```rust
#[test]
fn vv_f2_icmp_seq_eq_snd_nxt() {
    let mut s = socket_established();
    assert_eq!(s.local_seq_no, s.remote_last_seq);
    s.process_icmp_error(IcmpError::HostUnreachable, LOCAL_SEQ + 1);
    assert!(s.icmp_error.is_none());
}
```
Output: `icmp_error: Some(HostUnreachable)`, assertion failed.

## Suggested fix
Reject `seq >= self.remote_last_seq` if the half-open range is wanted. That drops genuine errors about pure ACKs, so keeping the current bound with a comment is also reasonable.
