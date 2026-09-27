//! This is an integration test rather than a unit test because it has to own the
//! whole pool, and unit tests run in parallel threads of one process

use xarxa::Stack;
use xarxa::driver::PacketBuf;
use xarxa::iface::Medium;
use xarxa::udp::SendError;
use xarxa::wire::{HardwareAddress, IpCidr, Ipv4Addr, ListenSocketAddr, SocketAddr};

use test_device::TestDevice;

// The mock device the library's own unit tests use. It lives in `src/` so that both
// can share it; it is written against the public API, so including it here works.
#[path = "../src/test_device.rs"]
mod test_device;

/// One test function, so that every step runs in order on the one pool.
#[test]
fn exhaustion() {
    let mut stack = Stack::new(0x1234_5678_dead_beef);
    // The device copies out and drops (frees) whatever it is given.
    let iface = TestDevice::new(Medium::Ip).install(&mut stack, HardwareAddress::Ip);
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 24))
        .unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();
    let dst = SocketAddr::new(Ipv4Addr::new(192, 168, 1, 2).into(), 5678);

    // Sends work while the pool has buffers. The device drops what it is given,
    // so a send leaves the pool as it found it.
    stack.udp_socket(udp).send_slice(b"hello", dst).unwrap();

    // Take every buffer.
    let mut held = Vec::new();
    while let Some(buf) = PacketBuf::try_new() {
        held.push(buf);
    }
    assert!(!held.is_empty());
    assert!(PacketBuf::try_new().is_none());

    // A send now fails, and the socket is unharmed.
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst),
        Err(SendError::NoBuffer)
    );
    assert!(stack.udp_socket(udp).is_open());

    // An owned send needs no free buffer, even without reserved headroom.
    let mut buf = held.pop().unwrap();
    buf.set_len(5);
    buf.copy_from_slice(b"hello");
    stack.udp_socket(udp).send_packet(buf, dst).unwrap();
    held.push(PacketBuf::try_new().unwrap());
    assert!(PacketBuf::try_new().is_none());

    // Freeing one buffer is enough for a send. Taking it back starves sends again.
    drop(held.pop());
    stack.udp_socket(udp).send_slice(b"hello", dst).unwrap();
    held.push(PacketBuf::try_new().unwrap());
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst),
        Err(SendError::NoBuffer)
    );

    // Everything freed: the pool is whole again.
    let count = held.len();
    drop(held);
    let mut again = Vec::new();
    while let Some(buf) = PacketBuf::try_new() {
        again.push(buf);
    }
    assert!(again.len() >= count);

    // Still with no buffer free: a router solicitation that can't be built counts
    // as sent, and the retry timer sends the next one, 4 s later. The stack doesn't
    // ask to be polled again right away.
    #[cfg(all(feature = "slaac", feature = "medium-ethernet"))]
    {
        use xarxa::iface::slaac::SlaacConfig;
        use xarxa::time::Instant;
        use xarxa::wire::EthernetAddress;

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let hw = HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01]));
        let iface = TestDevice::new(Medium::Ethernet).install(&mut stack, hw);
        stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
        assert_eq!(stack.poll(Instant::from_secs(1)), Instant::from_secs(5));
    }

    // Still with no buffer free: nothing waits for one on behalf of a socket. The
    // send waker is not woken, and the stack doesn't ask to be polled for the send.
    #[cfg(feature = "async")]
    {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};
        use xarxa::time::Instant;

        #[derive(Default)]
        struct WakeCount(AtomicUsize);
        impl Wake for WakeCount {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let now = Instant::from_secs(1);
        let deadline = stack.poll(now);
        assert_eq!(
            stack.udp_socket(udp).send_slice(b"hello", dst),
            Err(SendError::NoBuffer)
        );
        let wakes = Arc::new(WakeCount::default());
        stack.udp_socket(udp).register_send_waker(&Waker::from(wakes.clone()));
        assert_eq!(stack.poll(now), deadline);
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
    }

    // Still with no buffer free: a TCP SYN is held back, and the stack asks to be
    // polled again 1 ms later to retry it, since nothing signals a freed buffer.
    #[cfg(feature = "tcp")]
    {
        use xarxa::time::{Duration, Instant};

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let device = TestDevice::new(Medium::Ip);
        let tx = device.tx.clone();
        let iface = device.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 24))
            .unwrap();
        let tcp = stack
            .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
            .unwrap();
        stack.tcp_socket(tcp).connect(dst, 0).unwrap();

        let now = Instant::from_secs(1);
        let retry = now + Duration::from_millis(1);
        assert_eq!(stack.poll(now), retry);
        assert!(tx.borrow().is_empty());

        // A buffer is free by the retry, which sends the SYN. The retransmit timer
        // is the deadline from then on.
        drop(again.pop());
        let deadline = stack.poll(retry);
        assert_eq!(tx.borrow().len(), 1);
        assert!(deadline > retry + Duration::from_millis(1));
        // The device freed the SYN's buffer. Take it back.
        again.push(PacketBuf::try_new().unwrap());
    }

    // The fragments of a datagram wait for buffers the same way. With one free
    // buffer, the datagram takes it and none is left for the fragments.
    #[cfg(feature = "ipv4-fragmentation")]
    {
        use xarxa::time::{Duration, Instant};

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let device = TestDevice::new(Medium::Ip).with_mtu(600);
        let tx = device.tx.clone();
        let iface = device.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 24))
            .unwrap();
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();

        drop(again.pop());
        stack.udp_socket(udp).send_slice(&[0; 800], dst).unwrap();
        assert!(tx.borrow().is_empty());

        let now = Instant::from_secs(1);
        let retry = now + Duration::from_millis(1);
        assert_eq!(stack.poll(now), retry);
        assert!(tx.borrow().is_empty());

        // A buffer is back by the retry. The device frees each fragment's buffer as
        // it takes it, so the one buffer carries both fragments.
        drop(again.pop());
        // Nothing left to do: the stack asks to be polled again in a day.
        assert_eq!(stack.poll(retry), retry + Duration::from_secs(24 * 60 * 60));
        assert_eq!(tx.borrow().len(), 2);
    }

    // A TCP segment held back behind fragments that wait for a buffer waits for a
    // buffer too. It is retried soon even if the fragments get their buffer later in
    // the same poll: the device never said no, so no wakeup would bring a poll.
    #[cfg(all(feature = "tcp", feature = "ipv4-fragmentation"))]
    {
        use xarxa::driver::{Capabilities, Driver};
        use xarxa::time::{Duration, Instant};

        /// Hands the stack one junk frame, which it drops. That frees a buffer in
        /// the middle of a poll, as a driver reclaiming a sent frame would.
        struct Junk(Option<PacketBuf>);
        impl Driver for Junk {
            fn capabilities(&self) -> Capabilities {
                let mut caps = Capabilities::default();
                caps.medium = xarxa::driver::Medium::Ip;
                caps
            }
            fn hardware_address(&self) -> xarxa::driver::HardwareAddress {
                xarxa::driver::HardwareAddress::Ip
            }
            fn receive(&mut self) -> Option<PacketBuf> {
                self.0.take()
            }
            fn can_transmit(&mut self) -> bool {
                true
            }
            fn transmit(&mut self, _buf: PacketBuf) -> Result<(), PacketBuf> {
                Ok(())
            }
        }

        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let device = TestDevice::new(Medium::Ip).with_mtu(600);
        let tx = device.tx.clone();
        let iface = device.install(&mut stack, HardwareAddress::Ip);
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 24))
            .unwrap();
        let udp = stack.add_udp_socket().unwrap();
        stack.udp_socket(udp).bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();
        let tcp = stack
            .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
            .unwrap();

        // Take back what the steps above left free. Then the datagram takes the
        // one free buffer, and its fragments wait.
        while let Some(buf) = PacketBuf::try_new() {
            again.push(buf);
        }
        drop(again.pop());
        stack.udp_socket(udp).send_slice(&[0; 800], dst).unwrap();
        assert!(tx.borrow().is_empty());
        stack.tcp_socket(tcp).connect(dst, 0).unwrap();

        // The second interface is polled after the first one's fragments tried and
        // failed, and before they try again at the end of the poll.
        drop(again.pop());
        let junk = Junk(Some(PacketBuf::try_new().unwrap()));
        stack.add_iface_borrowed(Box::leak(Box::new(junk))).unwrap();

        let now = Instant::from_secs(1);
        let retry = now + Duration::from_millis(1);
        assert_eq!(stack.poll(now), retry);
        assert_eq!(tx.borrow().len(), 2);

        // The retry sends the SYN.
        stack.poll(retry);
        assert_eq!(tx.borrow().len(), 3);
    }
}
