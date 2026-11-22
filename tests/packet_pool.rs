//! Packet pool exhaustion, the way an application causes it: by keeping the
//! buffers it allocates. Each stack has a pool of its own.

use xarxa::iface::Medium;
use xarxa::udp::SendError;
use xarxa::udp::UdpHandle;
use xarxa::wire::{HardwareAddress, IpCidr, Ipv4Addr, ListenSocketAddr, SocketAddr};
use xarxa::{Buf, Stack, StaticPool};

use test_device::TestDevice;

// The mock device the library's own unit tests use. It lives in `src/` so that both
// can share it; it is written against the public API, so including it here works.
#[path = "../src/test_device.rs"]
mod test_device;

/// A pool for one stack.
fn pool() -> &'static mut StaticPool {
    Box::leak(Box::new(StaticPool::new()))
}

/// A stack with one IP interface that owns 192.168.1.1/24, and a UDP socket on
/// port 1234.
fn ip_stack(device: TestDevice) -> (Stack<'static>, UdpHandle) {
    let mut stack = Stack::new(pool(), 0x1234_5678_dead_beef);
    let iface = device.install(&mut stack, HardwareAddress::Ip);
    stack
        .iface(iface)
        .add_ip_addr(IpCidr::new(Ipv4Addr::new(192, 168, 1, 1).into(), 24))
        .unwrap();
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();
    (stack, udp)
}

/// Take every buffer the application can get.
fn take_all(stack: &mut Stack, udp: UdpHandle) -> Vec<Buf> {
    core::iter::from_fn(|| stack.udp_socket(udp).alloc_buf()).collect()
}

fn dst() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(192, 168, 1, 2).into(), 5678)
}

#[test]
fn sends() {
    // The device copies out and drops (frees) whatever it is given.
    let (mut stack, udp) = ip_stack(TestDevice::new(Medium::Ip));

    // Sends work while the pool has buffers. The device drops what it is given,
    // so a send leaves the pool as it found it.
    stack.udp_socket(udp).send_slice(b"hello", dst()).unwrap();

    // Take every buffer.
    let mut held = take_all(&mut stack, udp);
    assert_eq!(held.len(), 16);

    // A send now fails, and the socket is unharmed.
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst()),
        Err(SendError::NoBuffer)
    );
    assert!(stack.udp_socket(udp).is_open());

    // An owned send needs no free buffer.
    let mut buf = held.pop().unwrap();
    buf.set_len(5);
    buf.copy_from_slice(b"hello");
    stack.udp_socket(udp).send_buf(buf, dst()).unwrap();
    let mut buf = stack.udp_socket(udp).alloc_buf().unwrap();
    assert!(buf.is_empty());
    assert!(buf.headroom() >= test_device::TX_HEADROOM + 20 + 8);
    buf.set_len(5);
    buf.copy_from_slice(b"hello");
    stack.udp_socket(udp).send_buf(buf, dst()).unwrap();
    held.push(stack.udp_socket(udp).alloc_buf().unwrap());
    assert!(stack.udp_socket(udp).alloc_buf().is_none());

    // Freeing one buffer is enough for a send. Taking it back starves sends again.
    drop(held.pop());
    stack.udp_socket(udp).send_slice(b"hello", dst()).unwrap();
    held.push(stack.udp_socket(udp).alloc_buf().unwrap());
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst()),
        Err(SendError::NoBuffer)
    );

    // Everything freed: the pool is whole again.
    let count = held.len();
    drop(held);
    assert_eq!(take_all(&mut stack, udp).len(), count);
}

/// Nothing waits for a buffer on behalf of a socket. The send waker is not
/// woken, and the stack doesn't ask to be polled for the send.
#[cfg(feature = "async")]
#[test]
fn send_waits_for_nothing() {
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

    let (mut stack, udp) = ip_stack(TestDevice::new(Medium::Ip));
    let _held = take_all(&mut stack, udp);
    let now = Instant::from_secs(1);
    let deadline = stack.poll(now);
    assert_eq!(
        stack.udp_socket(udp).send_slice(b"hello", dst()),
        Err(SendError::NoBuffer)
    );
    let wakes = Arc::new(WakeCount::default());
    stack.udp_socket(udp).register_send_waker(&Waker::from(wakes.clone()));
    assert_eq!(stack.poll(now), deadline);
    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
}

/// A router solicitation that can't be built doesn't count as sent. It stays
/// due, and the stack asks to be polled again 1 ms later to retry it, since
/// nothing signals a freed buffer. So do the multicast reports for the
/// interface's groups.
#[cfg(all(feature = "slaac", feature = "medium-ethernet"))]
#[test]
fn solicitation_waits() {
    use xarxa::iface::slaac::SlaacConfig;
    use xarxa::time::{Duration, Instant};
    use xarxa::wire::EthernetAddress;

    let mut stack = Stack::new(pool(), 0x1234_5678_dead_beef);
    let hw = HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01]));
    let device = TestDevice::new(Medium::Ethernet);
    let tx = device.tx.clone();
    let iface = device.install(&mut stack, hw);
    let udp = stack.add_udp_socket().unwrap();
    stack.udp_socket(udp).bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();
    let mut held = take_all(&mut stack, udp);

    stack.iface(iface).set_slaac(Some(SlaacConfig::default())).unwrap();
    let now = Instant::from_secs(1);
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(now), retry);
    assert_eq!(stack.poll(retry), retry + Duration::from_millis(1));
    assert!(tx.borrow().is_empty());

    // A buffer is free by the next retry: everything that was due goes out,
    // the solicitation among it, and its retry timer runs from then, 4 s.
    drop(held.pop());
    let retry = retry + Duration::from_millis(1);
    assert_eq!(stack.poll(retry), retry + Duration::from_secs(4));
    assert!(!tx.borrow().is_empty());
}

/// A TCP SYN is held back, and the stack asks to be polled again 1 ms later to
/// retry it, since nothing signals a freed buffer.
#[cfg(feature = "tcp")]
#[test]
fn syn_waits() {
    use xarxa::time::{Duration, Instant};

    let device = TestDevice::new(Medium::Ip);
    let tx = device.tx.clone();
    let (mut stack, udp) = ip_stack(device);
    let tcp = stack
        .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
        .unwrap();
    let mut held = take_all(&mut stack, udp);
    stack.tcp_socket(tcp).connect(dst(), 0).unwrap();

    let now = Instant::from_secs(1);
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(now), retry);
    assert!(tx.borrow().is_empty());

    // A buffer is free by the retry, which sends the SYN. The retransmit timer
    // is the deadline from then on.
    drop(held.pop());
    let deadline = stack.poll(retry);
    assert_eq!(tx.borrow().len(), 1);
    assert!(deadline > retry + Duration::from_millis(1));
}

/// The fragments of a datagram wait for buffers the same way. With one free
/// buffer, the datagram takes it and none is left for the fragments.
#[cfg(feature = "ipv4-fragmentation")]
#[test]
fn fragments_wait() {
    use xarxa::time::{Duration, Instant};

    let device = TestDevice::new(Medium::Ip).with_mtu(600);
    let tx = device.tx.clone();
    let (mut stack, udp) = ip_stack(device);
    let mut held = take_all(&mut stack, udp);

    drop(held.pop());
    stack.udp_socket(udp).send_slice(&[0; 800], dst()).unwrap();
    assert!(tx.borrow().is_empty());

    let now = Instant::from_secs(1);
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(now), retry);
    assert!(tx.borrow().is_empty());

    // A buffer is back by the retry. The device frees each fragment's buffer as
    // it takes it, so the one buffer carries both fragments.
    drop(held.pop());
    // Nothing left to do: the stack asks to be polled again in a day.
    assert_eq!(stack.poll(retry), retry + Duration::from_secs(24 * 60 * 60));
    assert_eq!(tx.borrow().len(), 2);
}

/// A TCP segment held back behind fragments that wait for a buffer waits for a
/// buffer too. It is retried soon even if the fragments get their buffer later in
/// the same poll: the device never said no, so no wakeup would bring a poll.
#[cfg(all(feature = "tcp", feature = "ipv4-fragmentation"))]
#[test]
fn held_back_behind_fragments() {
    use xarxa::driver::{Capabilities, Driver, DriverBuf};
    use xarxa::time::{Duration, Instant};

    /// Hands the stack one junk frame, which it drops. That frees a buffer in
    /// the middle of a poll, as a driver reclaiming a sent frame would.
    struct Junk(Option<DriverBuf>);
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
        fn rx_give(&mut self, _buf: DriverBuf) {}
        fn receive(&mut self) -> Option<DriverBuf> {
            self.0.take()
        }
        fn can_transmit(&mut self) -> bool {
            true
        }
        fn transmit(&mut self, _buf: DriverBuf) -> Result<(), DriverBuf> {
            Ok(())
        }
    }

    let device = TestDevice::new(Medium::Ip).with_mtu(600);
    let tx = device.tx.clone();
    let (mut stack, udp) = ip_stack(device);
    let tcp = stack
        .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
        .unwrap();

    // The datagram takes the one free buffer, and its fragments wait.
    let mut held = take_all(&mut stack, udp);
    drop(held.pop());
    stack.udp_socket(udp).send_slice(&[0; 800], dst()).unwrap();
    assert!(tx.borrow().is_empty());
    stack.tcp_socket(tcp).connect(dst(), 0).unwrap();

    // The second interface is polled after the first one's fragments tried and
    // failed, and before they try again at the end of the poll.
    let junk = Junk(Some(held.pop().unwrap().into_driver_buf()));
    stack.add_iface_borrowed(Box::leak(Box::new(junk))).unwrap();

    let now = Instant::from_secs(1);
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(now), retry);
    assert_eq!(tx.borrow().len(), 2);

    // The retry sends the SYN.
    stack.poll(retry);
    assert_eq!(tx.borrow().len(), 3);
}

/// The ACKs that received TCP segments call for right away wait for a buffer
/// too. The segment's own buffer is free again by the time they are built, so
/// one free buffer is enough to receive a segment and answer it.
#[cfg(feature = "tcp")]
#[test]
fn acks_wait() {
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

    let device = TestDevice::new(Medium::Ip);
    let (rx, tx, room) = (device.rx.clone(), device.tx.clone(), device.room.clone());
    let (mut stack, udp) = ip_stack(device);
    let tcp = stack
        .add_tcp_socket_with_bufs(vec![0; 1024].leak(), vec![0; 1024].leak())
        .unwrap();

    // One free buffer from here on.
    let mut held = take_all(&mut stack, udp);
    drop(held.pop());

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
    held.push(stack.udp_socket(udp).alloc_buf().unwrap());
    let retry = now + Duration::from_millis(1);
    assert_eq!(stack.poll(now), retry);
    assert!(tx.borrow().is_empty());

    // A buffer is free by the retry, which sends the ACK.
    drop(held.pop());
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
