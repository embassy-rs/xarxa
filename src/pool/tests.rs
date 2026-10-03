use std::vec::Vec;

use super::*;
use crate::driver::PacketMeta;

/// The storage a driver DMAs into must be aligned to the pool's alignment,
/// whatever the `RawPacketBuf` in front of it does to the layout.
fn check_dma_shaped(pool: &'static dyn Pool, size: usize, align: usize) {
    assert_eq!(pool.buf_capacity(), size);
    // Two buffers, so that one isn't the first of the pool.
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut buf = pool.alloc().unwrap();
        assert_eq!(buf.storage_mut().as_ptr() as usize % align, 0);
        assert_eq!(buf.storage_mut().len(), size);
        assert_eq!(buf.capacity(), size);
        held.push(buf);
    }
}

#[test]
fn static_storage_is_dma_shaped() {
    static PLAIN: StaticPool<1536, 2> = StaticPool::new();
    static ODD: StaticPool<1501, 2, 8> = StaticPool::new();
    static WIDE: StaticPool<1514, 2, 64> = StaticPool::new();
    check_dma_shaped(&PLAIN, 1536, 1);
    check_dma_shaped(&ODD, 1501, 8);
    check_dma_shaped(&WIDE, 1514, 64);
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_storage_is_dma_shaped() {
    static PLAIN: AllocPool<1536> = AllocPool::new(2);
    static ODD: AllocPool<1501, 8> = AllocPool::new(2);
    static WIDE: AllocPool<1514, 64> = AllocPool::new(2);
    check_dma_shaped(&PLAIN, 1536, 1);
    check_dma_shaped(&ODD, 1501, 8);
    check_dma_shaped(&WIDE, 1514, 64);
}

/// A fresh buffer starts out empty with default metadata, whatever its previous
/// owner left behind. (Pool exhaustion and reuse are covered by the
/// `packet_pool` integration test.)
#[test]
fn fresh_buffer_is_reset() {
    let mut buf = test_pool().alloc().unwrap();
    buf.reserve(100);
    buf.set_len(200);
    buf.fill(0xff);
    drop(buf);

    let buf = test_pool().alloc().unwrap();
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.headroom(), 0);
    assert_eq!(buf.meta(), PacketMeta::default());
}

/// A pool gives out at most its count of buffers, and a dropped buffer goes back
/// to the pool it came from.
fn check_limit(a: &'static dyn Pool, b: &'static dyn Pool, count: usize) {
    let mut held = Vec::new();
    while let Some(buf) = a.alloc() {
        held.push(buf);
    }
    assert_eq!(held.len(), count);
    let mut held_b = Vec::new();
    while let Some(buf) = b.alloc() {
        held_b.push(buf);
    }
    assert_eq!(held_b.len(), count);
    // Freeing a buffer of B doesn't free one in A.
    drop(held_b.pop());
    assert!(a.alloc().is_none());
    drop(held.pop());
    held.push(a.alloc().unwrap());
    assert!(a.alloc().is_none());
}

#[test]
fn static_limit() {
    static A: StaticPool<1514, 4> = StaticPool::new();
    static B: StaticPool<1514, 4> = StaticPool::new();
    check_limit(&A, &B, 4);
}

/// `StaticPool` looks for a free slot from the last one freed on, and wraps
/// around to find the ones before it.
#[test]
fn static_claim_wraps() {
    static POOL: StaticPool<1514, 4> = StaticPool::new();
    let mut held: Vec<PacketBuf> = core::iter::from_fn(|| POOL.alloc()).collect();
    assert_eq!(held.len(), 4);
    let mut ptrs: Vec<*const u8> = held.iter_mut().map(|b| b.storage_mut().as_ptr()).collect();

    // Free the first slot, then the last: the search starts at the last one.
    drop(held.remove(0));
    drop(held.pop());
    let mut last = POOL.alloc().unwrap();
    assert_eq!(last.storage_mut().as_ptr(), ptrs.pop().unwrap());
    // The first slot is only found by wrapping around.
    let mut first = POOL.alloc().unwrap();
    assert_eq!(first.storage_mut().as_ptr(), ptrs.remove(0));
    assert!(POOL.alloc().is_none());
}

#[cfg(feature = "alloc")]
#[test]
fn alloc_limit() {
    static A: AllocPool = AllocPool::new(4);
    static B: AllocPool = AllocPool::new(4);
    check_limit(&A, &B, 4);
}

/// The stack gives a driver the receive buffers it wants at the first poll,
/// not when the interface is added. When the pool can't top the driver up, it
/// asks to be polled again soon.
#[cfg(feature = "medium-ip")]
fn check_rx_refill(pool: &'static impl Pool) {
    use crate::Stack;
    use crate::driver::{Capabilities, Driver, HardwareAddress, Medium};
    use crate::time::{Duration, Instant, idle_deadline};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A receive ring of 4 slots that never receives anything.
    struct Ring(Rc<RefCell<Vec<PacketBuf>>>);
    impl Driver for Ring {
        fn capabilities(&self) -> Capabilities {
            let mut caps = Capabilities::default();
            caps.medium = Medium::Ip;
            caps
        }
        fn hardware_address(&self) -> HardwareAddress {
            HardwareAddress::Ip
        }
        fn rx_wanted(&mut self) -> usize {
            4 - self.0.borrow().len()
        }
        fn rx_give(&mut self, buf: PacketBuf) {
            self.0.borrow_mut().push(buf);
        }
        fn receive(&mut self) -> Option<PacketBuf> {
            None
        }
        fn can_transmit(&mut self) -> bool {
            true
        }
        fn transmit(&mut self, _buf: PacketBuf) -> Result<(), PacketBuf> {
            Ok(())
        }
    }

    let ring = Rc::new(RefCell::new(Vec::new()));
    let mut stack = Stack::new(pool, 0);
    stack
        .add_iface_borrowed(std::boxed::Box::leak(std::boxed::Box::new(Ring(ring.clone()))))
        .unwrap();
    assert_eq!(ring.borrow().len(), 0);

    let now = Instant::from_secs(1);
    assert_eq!(stack.poll(now), idle_deadline(now));
    assert_eq!(ring.borrow().len(), 4);

    // The driver drops a buffer, and the pool has none to replace it.
    let mut held = Vec::new();
    while let Some(buf) = pool.alloc() {
        held.push(buf);
    }
    drop(ring.borrow_mut().pop());
    held.push(pool.alloc().unwrap());
    assert_eq!(stack.poll(now), now + Duration::from_millis(1));
    assert_eq!(ring.borrow().len(), 3);

    // A buffer is free by the retry.
    drop(held.pop());
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(retry), idle_deadline(retry));
    assert_eq!(ring.borrow().len(), 4);
}

#[cfg(feature = "medium-ip")]
#[test]
fn static_rx_refill() {
    static POOL: StaticPool = StaticPool::new();
    check_rx_refill(&POOL);
}

#[cfg(all(feature = "medium-ip", feature = "alloc"))]
#[test]
fn alloc_rx_refill() {
    static POOL: AllocPool = AllocPool::new(16);
    check_rx_refill(&POOL);
}
