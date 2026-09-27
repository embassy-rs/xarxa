# 287. TcpSocket::peek_slice skips the receive-state check: never returns Finished/InvalidState and reads data before the connection is established

| | |
|---|---|
| Severity | low |
| Category | doc-mismatch |
| Location | [src/tcp/mod.rs:2920](../src/tcp/mod.rs#L2920) |
| Features | default |
| Verification | reproduced with a test |

## Summary
The doc says `peek_slice` "otherwise behaves identically to recv_slice". `recv_slice` and `peek` call `recv_error_check`, `peek_slice` does not. It returns `Ok(0)` on a closed socket or after a FIN, never `Finished` or `InvalidState`. It can also read data buffered in SYN-RECEIVED, which `recv_error_check` deliberately forbids.

## Details
src/tcp/mod.rs:2916-2922:
```rust
/// This function otherwise behaves identically to [recv_slice](#method.recv_slice).
pub fn peek_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
    Ok(self.inner_mut().rx_buffer.read_allocated(0, data))
}
```
Compare src/tcp/mod.rs:2906-2907:
```rust
pub fn peek(&mut self, size: usize) -> Result<&[u8], RecvError> {
    self.recv_error_check()?;
```

## Failure scenario
A parser loops `while sock.peek_slice(&mut hdr)? < HDR_LEN { wait_readable().await }`. The peer sends a FIN or resets. `peek_slice` keeps returning `Ok(0)`, so the loop never ends and the task spins or hangs. Applications that also check state or use `recv` are not affected.

## Reproduction
Test in the `stack_test` module harness, run in a scratch copy of the crate:
```rust
#[test]
fn zz_v_peek_slice_state() {
    let (mut stack, _driver) = stack();
    let h = stack.add_tcp_socket_with_bufs(vec![0; 64].leak(), vec![0; 64].leak()).unwrap();
    let mut buf = [0u8; 8];
    let p = stack.tcp_socket(h).peek_slice(&mut buf);
    let r = stack.tcp_socket(h).recv_slice(&mut buf);
    let pk = stack.tcp_socket(h).peek(8).map(|b| b.len());
    assert_eq!(p, Ok(0));
    assert_eq!(r, Err(RecvError::InvalidState));
}
```
Output:
```
closed: peek_slice=Ok(0) recv_slice=Err(InvalidState) peek=Err(InvalidState)
ok
```

## Suggested fix
Call `self.recv_error_check()?` at the top of `peek_slice`, like `peek` does.
