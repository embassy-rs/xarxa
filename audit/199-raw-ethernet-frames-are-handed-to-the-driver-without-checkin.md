# 199. Raw Ethernet frames are handed to the driver without checking the device's max_transmission_unit

| | |
|---|---|
| Severity | low |
| Category | correctness |
| Location | [src/raw.rs:561](../src/raw.rs#L561), [src/raw.rs:583](../src/raw.rs#L583), [src/stack.rs:2739](../src/stack.rs#L2739), [xarxa-driver/src/lib.rs:172](../xarxa-driver/src/lib.rs#L172) |
| Features | raw-ethernet |
| Verification | reproduced with a test |

## Summary
Ethernet-mode raw sends only check the frame against the buffer capacity. A driver that declared a smaller `Capabilities::max_transmission_unit` gets frames larger than it said it can send. Every IP path is capped by `ip_mtu()`, which derives from that value.

## Details
src/raw.rs:561
```rust
if max_size > buf.capacity() - headroom {
```
is the only size check. src/raw.rs:583 then calls `transmit_ethernet`, which hands the buffer to `driver.transmit` (src/stack.rs:2739). xarxa-driver/src/lib.rs:172: "The network device is unable to send or receive frames larger than the value returned by this function."

## Failure scenario
A MAC with MTU 600. An app sends a 1000-byte raw frame. `send_slice` returns `Ok` and the driver gets a frame it may truncate, reject (only logged), or mishandle in its DMA setup.

## Reproduction
Added to `src/stack.rs` `mod test` in a scratch copy:
```rust
#[test]
fn vv_raw8_eth_frame_exceeds_mtu() {
    let (mut stack, _rx, tx, _room) = test_stack_with_mtu(Medium::Ethernet, 600);
    let h = stack.add_raw_socket().unwrap();
    stack.raw_socket(h).bind(RawMode::Ethernet { ethertype: None }).unwrap();
    let mut frame = vec![0u8; 1000]; frame[12] = 0x88; frame[13] = 0xb5;
    let r = stack.raw_socket(h).send_slice(&frame);
    let lens: Vec<usize> = tx.borrow().iter().map(|f| f.len()).collect();
    println!("raw8 result {:?}, frames {:?}", r, lens);
    assert!(lens.iter().all(|&l| l <= 600));
}
```
Output:
```
raw8 result Ok(()), frames [1000] ... assertion failed
```

## Suggested fix
In Ethernet mode, reject frames larger than the interface's `caps.max_transmission_unit` (`BufferFull` or a new error).
