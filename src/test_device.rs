//! The mock [`Driver`] the tests drive the stack with.
//!
//! One device covers every test: it hands the stack the frames pushed into its
//! receive queue, records the ones it transmits, refuses to transmit when asked
//! to, and carries packet metadata in both directions. Everything a test looks
//! at is behind an `Rc`, so the handles stay usable after the device is given to
//! a stack.
//!
//! This file is compiled into the library's own unit tests and `#[path]`-included
//! by the integration tests, so it is written against the public API only.

#![allow(dead_code)]

use std::boxed::Box;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::vec::Vec;

use xarxa::Stack;
use xarxa::driver::Capabilities;
use xarxa::driver::PacketBuf;
#[cfg(feature = "packetmeta-id")]
use xarxa::driver::PacketMeta;
use xarxa::driver::{ChecksumCapabilities, Driver, LinkState};
#[cfg(feature = "packetmeta-timestamp")]
use xarxa::driver::{Timestamp, TxTimestamp};
use xarxa::iface::IfaceHandle;
use xarxa::iface::Medium;
use xarxa::wire::HardwareAddress;

/// Frames waiting to be received, oldest first.
pub type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// Frames transmitted so far, oldest first.
pub type Sent = Rc<RefCell<Vec<Vec<u8>>>>;

/// The metadata of the transmitted frames, oldest first.
#[cfg(feature = "packetmeta-id")]
pub type SentMeta = Rc<RefCell<Vec<PacketMeta>>>;

/// How many more frames the device accepts. `None` is unlimited.
pub type Room = Rc<Cell<Option<usize>>>;

/// Control over the link state the device reports, shared with the test.
pub type Link = Rc<Cell<LinkState>>;

/// The multicast filter updates reported so far, oldest first. `true` is add.
pub type McastFilter = Rc<RefCell<Vec<Vec<[u8; 6]>>>>;

/// A mock network device.
///
/// Build one with [`TestDevice::new`] plus the `with_*` setters, then give it to
/// a stack with [`TestDevice::install`]. The configuration is read at install
/// time; the queues are shared, so keep the device around and read `rx`, `tx`,
/// `tx_meta` and `room` through it.
#[derive(Clone)]
pub struct TestDevice {
    /// The medium it reports.
    pub medium: Medium,
    /// The MTU it reports.
    pub mtu: usize,
    /// The checksums it claims to compute and verify itself.
    pub checksum: ChecksumCapabilities,
    /// Frames to hand to the stack, oldest first.
    pub rx: Queue,
    /// Frames the stack transmitted, oldest first.
    pub tx: Sent,
    /// The metadata of those frames.
    #[cfg(feature = "packetmeta-id")]
    pub tx_meta: SentMeta,
    /// How many more frames it accepts.
    pub room: Room,
    /// The hardware address it reports. Set by [`TestDevice::install`].
    pub hardware_addr: HardwareAddress,
    /// The link state it reports.
    pub link: Link,
    /// Multicast filter lists the stack set, oldest first.
    pub mcast_filter: McastFilter,
    /// Metadata stamped onto every received packet.
    #[cfg(feature = "packetmeta-id")]
    pub rx_meta: PacketMeta,
    /// Reported as the transmit timestamp of packets that ask for one.
    #[cfg(feature = "packetmeta-timestamp")]
    tx_stamp: Option<Timestamp>,
    /// Transmit timestamps not yet polled.
    #[cfg(feature = "packetmeta-timestamp")]
    tx_stamps: VecDeque<TxTimestamp>,
}

impl TestDevice {
    /// A device of the given medium, with a 1500-byte MTU and unlimited
    /// transmit room, receiving nothing.
    pub fn new(medium: Medium) -> Self {
        Self {
            medium,
            mtu: 1500,
            checksum: ChecksumCapabilities::default(),
            rx: Rc::new(RefCell::new(VecDeque::new())),
            tx: Rc::new(RefCell::new(Vec::new())),
            #[cfg(feature = "packetmeta-id")]
            tx_meta: Rc::new(RefCell::new(Vec::new())),
            room: Rc::new(Cell::new(None)),
            mcast_filter: Rc::new(RefCell::new(Vec::new())),
            hardware_addr: match medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => {
                    HardwareAddress::Ethernet(xarxa::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
                }
                #[cfg(feature = "medium-ip")]
                Medium::Ip => HardwareAddress::Ip,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => HardwareAddress::Ieee802154(xarxa::wire::Ieee802154Address::Extended([
                    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ])),
            },
            link: Rc::new(Cell::new(LinkState::Up)),
            #[cfg(feature = "packetmeta-id")]
            rx_meta: PacketMeta::default(),
            #[cfg(feature = "packetmeta-timestamp")]
            tx_stamp: None,
            #[cfg(feature = "packetmeta-timestamp")]
            tx_stamps: VecDeque::new(),
        }
    }

    /// Sets the MTU it reports.
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Sets the checksums it claims to compute and verify itself.
    pub fn with_checksum(mut self, checksum: ChecksumCapabilities) -> Self {
        self.checksum = checksum;
        self
    }

    /// Stamps every received packet with this metadata.
    #[cfg(feature = "packetmeta-id")]
    pub fn with_rx_meta(mut self, meta: PacketMeta) -> Self {
        self.rx_meta = meta;
        self
    }

    /// Reports this as the transmit timestamp of packets that ask for one.
    #[cfg(feature = "packetmeta-timestamp")]
    pub fn with_tx_stamp(mut self, stamp: Timestamp) -> Self {
        self.tx_stamp = Some(stamp);
        self
    }

    /// Adds the device to `stack` as an interface with hardware address `hw`.
    ///
    /// The stack gets its own copy, sharing this one's queues. It is leaked, so
    /// the interface lives as long as the test wants it to.
    pub fn install(&self, stack: &mut Stack<'_>, hw: HardwareAddress) -> IfaceHandle {
        let mut driver = self.clone();
        driver.hardware_addr = hw;
        stack.add_iface_borrowed(Box::leak(Box::new(driver))).unwrap()
    }
}

impl Driver for TestDevice {
    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::default();
        caps.medium = self.medium.into();
        caps.max_transmission_unit = self.mtu;
        caps.checksum = self.checksum;
        caps
    }

    fn hardware_address(&self) -> xarxa::driver::HardwareAddress {
        self.hardware_addr.to_driver().unwrap()
    }

    fn link_state(&mut self) -> LinkState {
        self.link.get()
    }

    fn receive(&mut self) -> Option<PacketBuf> {
        let bytes = self.rx.borrow_mut().pop_front()?;
        let mut buf = PacketBuf::try_new().unwrap();
        buf.set_len(bytes.len());
        buf.copy_from_slice(&bytes);
        #[cfg(feature = "packetmeta-id")]
        {
            *buf.meta_mut() = self.rx_meta;
        }
        Some(buf)
    }

    fn can_transmit(&mut self) -> bool {
        self.room.get().is_none_or(|room| room > 0)
    }

    fn transmit(&mut self, buf: PacketBuf) -> Result<(), PacketBuf> {
        if !self.can_transmit() {
            return Err(buf);
        }
        if let Some(room) = self.room.get() {
            self.room.set(Some(room - 1));
        }
        #[cfg(feature = "packetmeta-id")]
        {
            let meta = buf.meta();
            self.tx_meta.borrow_mut().push(meta);
            #[cfg(feature = "packetmeta-timestamp")]
            if meta.request_timestamp
                && let Some(timestamp) = self.tx_stamp
            {
                self.tx_stamps.push_back(TxTimestamp { id: meta.id, timestamp });
            }
        }
        self.tx.borrow_mut().push(buf.to_vec());
        Ok(())
    }

    #[cfg(feature = "packetmeta-timestamp")]
    fn poll_tx_timestamp(&mut self) -> Option<TxTimestamp> {
        self.tx_stamps.pop_front()
    }

    fn set_multicast_filter(&mut self, addrs: &[[u8; 6]]) {
        self.mcast_filter.borrow_mut().push(addrs.to_vec());
    }
}
