//! Packet pool exhaustion. The test has a pool of its own, so it can take every
//! buffer in it.

use xarxa::driver::PacketBuf;
use xarxa::iface::Medium;
use xarxa::udp::SendError;
use xarxa::wire::{HardwareAddress, IpCidr, Ipv4Addr, ListenSocketAddr, SocketAddr};
use xarxa::{Pool, Stack, StaticPool};

use test_device::TestDevice;

// The mock device the library's own unit tests use. It lives in `src/` so that both
// can share it; it is written against the public API, so including it here works.
#[path = "../src/test_device.rs"]
mod test_device;

/// The pool every stack in this test allocates from.
static POOL: StaticPool = StaticPool::new();

/// One test function, so that every step runs in order on the one pool.
#[test]
fn exhaustion() {
    let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
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
    while let Some(buf) = POOL.alloc() {
        held.push(buf);
    }
    assert!(!held.is_empty());
    assert!(POOL.alloc().is_none());

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
    held.push(POOL.alloc().unwrap());
    assert!(POOL.alloc().is_none());

    // Freeing one buffer is enough for a send. Taking it back starves sends again.
    drop(held.pop());
    stack.udp_socket(udp).send_slice(b"hello", dst).unwrap();
    held.push(POOL.alloc().unwrap());
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst),
        Err(SendError::NoBuffer)
    );

    // Everything freed: the pool is whole again.
    let count = held.len();
    drop(held);
    let mut again = Vec::new();
    while let Some(buf) = POOL.alloc() {
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

        let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
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

        let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
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
        again.push(POOL.alloc().unwrap());
    }

    // The fragments of a datagram wait for buffers the same way. With one free
    // buffer, the datagram takes it and none is left for the fragments.
    #[cfg(feature = "ipv4-fragmentation")]
    {
        use xarxa::time::{Duration, Instant};

        let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
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
            // It has its one frame already, and wants no buffers.
            fn rx_wanted(&mut self) -> usize {
                0
            }
            fn rx_give(&mut self, _buf: PacketBuf) {}
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

        let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
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
        while let Some(buf) = POOL.alloc() {
            again.push(buf);
        }
        drop(again.pop());
        stack.udp_socket(udp).send_slice(&[0; 800], dst).unwrap();
        assert!(tx.borrow().is_empty());
        stack.tcp_socket(tcp).connect(dst, 0).unwrap();

        // The second interface is polled after the first one's fragments tried and
        // failed, and before they try again at the end of the poll.
        drop(again.pop());
        let junk = Junk(Some(POOL.alloc().unwrap()));
        stack.add_iface_borrowed(Box::leak(Box::new(junk))).unwrap();

        let now = Instant::from_secs(1);
        let retry = now + Duration::from_millis(1);
        assert_eq!(stack.poll(now), retry);
        assert_eq!(tx.borrow().len(), 2);

        // The retry sends the SYN.
        stack.poll(retry);
        assert_eq!(tx.borrow().len(), 3);
    }

    // The ACKs that received TCP segments call for right away wait for a buffer
    // too. The segment's own buffer is free again by the time they are built, so
    // one free buffer is enough to receive a segment and answer it.
    #[cfg(feature = "tcp")]
    {
        use xarxa::tcp::State;
        use xarxa::time::{Duration, Instant};
        use xarxa::wire::{IPV4_HEADER_LEN, IpProtocol, Ipv4Packet, TCP_HEADER_LEN, TcpPacket, TcpSeqNumber};

        let local = Ipv4Addr::new(192, 168, 1, 1);
        let remote = Ipv4Addr::new(192, 168, 1, 2);
        // A segment from port 80 of the remote to port 5000 here, as the device
        // receives it.
        let segment = |seq: TcpSeqNumber, ack: TcpSeqNumber, syn: bool, payload: &[u8]| {
            let len = IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len();
            let mut bytes = vec![0; len];
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len(len as u16);
            ip.set_next_header(IpProtocol::Tcp);
            ip.set_hop_limit(64);
            ip.set_src_addr(remote);
            ip.set_dst_addr(local);
            ip.fill_checksum();
            let mut tcp = TcpPacket::new_unchecked(&mut bytes[IPV4_HEADER_LEN..]);
            tcp.set_src_port(80);
            tcp.set_dst_port(5000);
            tcp.set_seq_number(seq);
            tcp.set_ack_number(ack);
            tcp.set_header_len(TCP_HEADER_LEN as u8);
            tcp.set_syn(syn);
            tcp.set_ack(true);
            tcp.set_window_len(1024);
            tcp.payload_mut().copy_from_slice(payload);
            tcp.fill_checksum(&remote.into(), &local.into());
            bytes
        };
        // The ACK number of a pure ACK the stack sent.
        let ack_number = |frame: &mut Vec<u8>| {
            let tcp = TcpPacket::new_checked(&mut frame[IPV4_HEADER_LEN..]).unwrap();
            assert!(tcp.ack() && !tcp.syn() && tcp.payload().is_empty());
            tcp.ack_number()
        };

        let mut stack = Stack::new(&POOL, 0x1234_5678_dead_beef);
        let device = TestDevice::new(Medium::Ip);
        let (rx, tx, room) = (device.rx.clone(), device.tx.clone(), device.room.clone());
        let iface = device.install(&mut stack, HardwareAddress::Ip);
        stack.iface(iface).add_ip_addr(IpCidr::new(local.into(), 24)).unwrap();
        let tcp = stack
            .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
            .unwrap();

        // One free buffer from here on.
        while let Some(buf) = POOL.alloc() {
            again.push(buf);
        }
        drop(again.pop());

        // The handshake: the SYN, then the SYN|ACK in and its ACK out.
        stack.tcp_socket(tcp).connect((remote, 80), 5000).unwrap();
        let now = Instant::from_secs(1);
        stack.poll(now);
        let local_seq = {
            let mut tx = tx.borrow_mut();
            assert_eq!(tx.len(), 1);
            let seq = TcpPacket::new_checked(&mut tx[0][IPV4_HEADER_LEN..])
                .unwrap()
                .seq_number();
            tx.clear();
            seq + 1
        };
        let remote_seq = TcpSeqNumber(1000);
        rx.borrow_mut().push_back(segment(remote_seq, local_seq, true, b""));
        stack.poll(now);
        assert_eq!(stack.tcp_socket(tcp).state(), State::Established);
        assert_eq!(tx.borrow_mut().drain(..).count(), 1);

        // An out-of-order segment takes the free buffer, and still gets its
        // duplicate ACK.
        rx.borrow_mut()
            .push_back(segment(remote_seq + 1 + 3, local_seq, false, b"def"));
        stack.poll(now);
        {
            let mut tx = tx.borrow_mut();
            assert_eq!(tx.len(), 1);
            assert_eq!(ack_number(&mut tx[0]), remote_seq + 1);
            tx.clear();
        }

        // The segment that fills the gap, while the device has no room. Then the
        // device has room but the pool has no buffer, and the stack asks to be
        // polled again soon to retry.
        room.set(Some(0));
        rx.borrow_mut()
            .push_back(segment(remote_seq + 1, local_seq, false, b"abc"));
        stack.poll(now);
        assert!(tx.borrow().is_empty());
        room.set(None);
        again.push(POOL.alloc().unwrap());
        let retry = now + Duration::from_millis(1);
        assert_eq!(stack.poll(now), retry);
        assert!(tx.borrow().is_empty());

        // A buffer is free by the retry, which sends the ACK.
        drop(again.pop());
        stack.poll(retry);
        {
            let mut tx = tx.borrow_mut();
            assert_eq!(tx.len(), 1);
            assert_eq!(ack_number(&mut tx[0]), remote_seq + 1 + 6);
        }
        let mut data = [0; 6];
        assert_eq!(stack.tcp_socket(tcp).recv_slice(&mut data), Ok(6));
        assert_eq!(&data, b"abcdef");
    }
}
