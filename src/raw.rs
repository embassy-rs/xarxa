//! Raw sockets.
//!
//! A raw socket sends and receives whole packets, headers included.
//!
//! Raw sockets can be bound in two modes, each behind its own cargo feature:
//!
//! - **Ethernet mode** (`RawMode::Ethernet`, feature `raw-ethernet`): whole Ethernet
//!   frames, optionally filtered by ethertype.
//! - **IP mode** (`RawMode::Ip`, feature `raw-ip`): whole IP packets on all
//!   interfaces. The socket may be bound to an IP version and/or an IP protocol,
//!   both optional.

use xarxa_driver::config::PACKET_BUF_DRIVER_HEADROOM;

use crate::config::RAW_RX_QUEUE_COUNT;
use crate::storage::BoundedDeque;
use core::fmt;

use crate::driver::PacketBuf;
use crate::driver::PacketMeta;
use crate::iface::IfaceHandle;
#[cfg(feature = "raw-ethernet")]
use crate::iface::Medium;
use crate::stack::{IfaceBinding, Stack, TxContext};
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
#[cfg(all(feature = "raw-ip", feature = "ipv4"))]
use crate::wire::Ipv4Packet;
#[cfg(all(feature = "raw-ip", feature = "ipv6"))]
use crate::wire::Ipv6Packet;
#[cfg(feature = "raw-ethernet")]
use crate::wire::{EthernetFrame, EthernetProtocol};
#[cfg(feature = "raw-ip")]
use crate::wire::{IpAddr, IpProtocol, IpVersion, LINK_HEADER_LEN};

define_handle! {
    /// A handle to a raw socket added to a [`Stack`].
    ///
    /// [`Stack`]: crate::Stack
    RawHandle(crate::config::raw_index)
}

/// The mode of a raw socket, set by [`RawSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawMode {
    /// Send and receive whole Ethernet frames. Feature `raw-ethernet`.
    ///
    /// The socket receives frames from every Ethernet-medium interface and
    /// sends out of the first one, unless it is bound to one interface with
    /// `bind_to_iface` (feature `iface-bind`).
    #[cfg(feature = "raw-ethernet")]
    Ethernet {
        /// If set, only frames with this ethertype are received, and only frames
        /// with this ethertype may be sent.
        ethertype: Option<EthernetProtocol>,
    },
    /// Send and receive whole IP packets, on all interfaces, or on the one
    /// bound with `bind_to_iface` (feature `iface-bind`). Feature `raw-ip`.
    #[cfg(feature = "raw-ip")]
    Ip {
        /// If set, only packets of this IP version are received, and only packets
        /// of this version may be sent.
        version: Option<IpVersion>,
        /// If set, only packets with this IP protocol are received, and only
        /// packets with this protocol may be sent.
        protocol: Option<IpProtocol>,
    },
}

/// Error returned by [`RawSocket::bind`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BindError {
    /// The socket is already bound.
    InvalidState,
    /// An Ethernet-mode bind on a socket bound to an interface whose medium is
    /// not [`Medium::Ethernet`].
    #[cfg(feature = "raw-ethernet")]
    InvalidMedium,
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindError::InvalidState => write!(f, "invalid state"),
            #[cfg(feature = "raw-ethernet")]
            BindError::InvalidMedium => write!(f, "invalid medium"),
        }
    }
}

impl core::error::Error for BindError {}

/// Error returned by [`RawSocket::send_slice`] and [`RawSocket::send_with`].
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SendError {
    /// The socket is not bound.
    InvalidState,
    /// There is no route to the packet's destination (IP mode), or no Ethernet
    /// interface to send on (Ethernet mode).
    Unaddressable,
    /// The packet does not fit in a packet buffer.
    BufferFull,
    /// No packet buffer is free.
    ///
    /// Retry later. Note the socket's send waker is **not** woken when a buffer is freed.
    NoBuffer,
    /// The interface the packet would go out of has no room for it right now.
    ///
    /// Retry once it has room. With the `async` feature, the socket's send
    /// waker is woken when room becomes available.
    DeviceBusy,
    /// The packet fails basic validation (too short for an Ethernet header in
    /// Ethernet mode, malformed IP header in IP mode), or does not match the
    /// socket's bind filters.
    Malformed,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::InvalidState => write!(f, "invalid state"),
            SendError::Unaddressable => write!(f, "unaddressable"),
            SendError::BufferFull => write!(f, "buffer full"),
            SendError::NoBuffer => write!(f, "no buffer"),
            SendError::DeviceBusy => write!(f, "device busy"),
            SendError::Malformed => write!(f, "malformed"),
        }
    }
}

impl core::error::Error for SendError {}

/// Error returned by [`RawSocket::recv`] and the peek methods.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RecvError {
    /// The socket is not bound.
    InvalidState,
    /// The RX queue is empty.
    Exhausted,
    /// The provided slice is smaller than the packet. (The packet is dropped by
    /// `recv_slice`, but not by `peek_slice`.)
    Truncated,
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::InvalidState => write!(f, "invalid state"),
            RecvError::Exhausted => write!(f, "exhausted"),
            RecvError::Truncated => write!(f, "truncated"),
        }
    }
}

impl core::error::Error for RecvError {}

/// Raw socket state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct RawSocketState {
    mode: Option<RawMode>,
    /// The interface the socket is bound to. Zero-sized without `iface-bind`.
    binding: IfaceBinding,
    rx_queue: BoundedDeque<PacketBuf, RAW_RX_QUEUE_COUNT>,
    #[cfg(feature = "async")]
    rx_waker: WakerRegistration,
    #[cfg(feature = "async")]
    pub(crate) tx_waker: WakerRegistration,
    /// The interface the last send found busy. `Stack::poll` wakes `tx_waker` once
    /// it has room.
    #[cfg(feature = "async")]
    pub(crate) tx_blocked_on: Option<IfaceHandle>,
}

impl RawSocketState {
    /// Create an unbound raw socket.
    pub(crate) fn new() -> RawSocketState {
        RawSocketState {
            mode: None,
            binding: IfaceBinding::Any,
            rx_queue: BoundedDeque::new(),
            #[cfg(feature = "async")]
            rx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_waker: WakerRegistration::new(),
            #[cfg(feature = "async")]
            tx_blocked_on: None,
        }
    }

    /// Queue an ingress packet. `buf` must be a whole Ethernet frame or IP packet,
    /// headers included, matching the socket's mode.
    pub(crate) fn rx_enqueue(&mut self, buf: PacketBuf) {
        if self.rx_queue.push_back(buf).is_err() {
            trace!("raw: rx queue full, dropping packet");
            return;
        }
        #[cfg(feature = "async")]
        self.rx_waker.wake();
    }
}

/// Copy a packet into a freshly allocated buffer. Used when both a raw socket and
/// the stack's own protocol handlers want an ingress packet. `None` if the pool
/// is empty: the socket misses the packet, the stack still processes it.
fn copy_packet(buf: &PacketBuf) -> Option<PacketBuf> {
    let Some(mut copy) = PacketBuf::try_new() else {
        trace!("raw: no packet buffer for a copy, socket misses the packet");
        return None;
    };
    copy.set_len(buf.len());
    copy.copy_from_slice(buf);
    // The copy is the same packet: it carries the same metadata (arrival timestamp,
    // driver-assigned id).
    copy.set_meta(buf.meta());
    Some(copy)
}

/// Parse the destination address and protocol out of an outgoing IP packet,
/// verifying that the IP header is well-formed. Returns `None` if it is not.
#[cfg(feature = "raw-ip")]
fn parse_ip_headers(buf: &mut [u8]) -> Option<(IpAddr, IpProtocol)> {
    if buf.is_empty() {
        return None;
    }
    match IpVersion::of_packet(buf).ok()? {
        #[cfg(feature = "ipv4")]
        IpVersion::V4 => {
            let packet = Ipv4Packet::new_checked(buf).ok()?;
            Some((packet.dst_addr().into(), packet.next_header()))
        }
        #[cfg(feature = "ipv6")]
        IpVersion::V6 => {
            let packet = Ipv6Packet::new_checked(buf).ok()?;
            Some((packet.dst_addr().into(), packet.next_header()))
        }
    }
}

/// A raw socket borrowed from a [`Stack`], returned by [`Stack::raw_socket`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::raw_socket`]: crate::Stack::raw_socket
pub struct RawSocket<'a, 'd> {
    pub(crate) state: &'a mut RawSocketState,
    pub(crate) tx: TxContext<'a, 'd>,
}

impl RawSocket<'_, '_> {
    /// Return the mode the socket is bound to, or `None` if it is unbound.
    #[inline]
    pub fn mode(&self) -> Option<RawMode> {
        self.state.mode
    }

    /// Bind the socket to an interface, or unbind it with `None`.
    ///
    /// A socket bound to an interface only sends and receives packets on it:
    /// - Destinations must be on-link on that iface, or have a route through it.
    /// - Broadcast and multicast destinations go out on that iface only
    ///
    /// In Ethernet mode the bound interface's medium must be
    /// [`Medium::Ethernet`], checked at [`bind`](Self::bind).
    ///
    /// The socket must be unbound (no mode set). The binding is kept across
    /// [`close`](Self::close).
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is bound.
    #[cfg(feature = "iface-bind")]
    pub fn bind_to_iface(&mut self, iface: Option<IfaceHandle>) -> Result<(), BindError> {
        if self.is_open() {
            return Err(BindError::InvalidState);
        }
        self.state.binding = iface.into();
        Ok(())
    }

    /// Return the interface the socket is bound to, or `None`.
    ///
    /// See [`bind_to_iface`](Self::bind_to_iface).
    #[cfg(feature = "iface-bind")]
    pub fn bound_iface(&self) -> Option<IfaceHandle> {
        self.state.binding.iface()
    }

    /// Bind the socket to the given mode.
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is already bound (see
    ///   [is_open](#method.is_open)).
    /// - `InvalidMedium`: if an Ethernet-mode bind is made on a socket bound
    ///   (with `bind_to_iface`, feature `iface-bind`) to an interface whose
    ///   medium is not [`Medium::Ethernet`].
    ///
    /// # Panics
    /// Panics if the socket is bound to a stale interface handle.
    pub fn bind(&mut self, mode: RawMode) -> Result<(), BindError> {
        if self.is_open() {
            return Err(BindError::InvalidState);
        }
        #[cfg(feature = "raw-ethernet")]
        if let RawMode::Ethernet { .. } = mode
            && let Some(iface) = self.state.binding.iface()
            && self.tx.ifaces.get(iface.index()).medium() != Medium::Ethernet
        {
            return Err(BindError::InvalidMedium);
        }
        self.state.mode = Some(mode);
        // Sends are possible now, and receives can start failing differently.
        #[cfg(feature = "async")]
        {
            self.state.rx_waker.wake();
            self.state.tx_waker.wake();
        }
        Ok(())
    }

    /// Close the socket, unbinding it and dropping any queued packets.
    pub fn close(&mut self) {
        self.state.mode = None;
        self.state.rx_queue.clear();
        // Wake the tasks waiting, so they can notice the socket is closed.
        #[cfg(feature = "async")]
        {
            self.state.tx_blocked_on = None;
            self.state.rx_waker.wake();
            self.state.tx_waker.wake();
        }
    }

    /// Check whether the socket is open (bound to a mode).
    #[inline]
    pub fn is_open(&self) -> bool {
        self.state.mode.is_some()
    }

    /// Register a waker for receive operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `recv` calls, such as receiving a packet, or the socket closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   incoming data may wake it again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `recv`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_recv_waker(&mut self, waker: &core::task::Waker) {
        self.state.rx_waker.register(waker)
    }

    /// Register a waker for send operations.
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `send` calls, such as:
    /// - the socket is bound or closed.
    /// - A send failed with [`SendError::DeviceBusy`] and the driver becomes no longer busy.
    ///
    /// It is not woken when a packet buffer is freed after
    /// [`SendError::NoBuffer`]. Retry that on your own.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   it may be woken again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of `send`
    ///   has changed.
    #[cfg(feature = "async")]
    pub fn register_send_waker(&mut self, waker: &core::task::Waker) {
        self.state.tx_waker.register(waker)
    }

    /// Check whether the RX queue is not empty.
    #[inline]
    pub fn can_recv(&self) -> bool {
        !self.state.rx_queue.is_empty()
    }

    /// Dequeue a received packet.
    ///
    /// The buffer holds the whole Ethernet frame (Ethernet mode) or IP packet (IP
    /// mode), headers included, exactly as received. This is zero-copy: the
    /// returned value is the buffer the packet arrived in, and dropping it frees it.
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is not bound.
    /// - `Exhausted`: if the RX queue is empty.
    pub fn recv(&mut self) -> Result<PacketBuf, RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        self.state.rx_queue.pop_front().ok_or(RecvError::Exhausted)
    }

    /// Dequeue a received packet, copying it into the given slice, and return the
    /// number of octets copied.
    ///
    /// See also [recv](#method.recv).
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is not bound.
    /// - `Exhausted`: if the RX queue is empty.
    /// - `Truncated`: if `data` is smaller than the packet. The packet is
    ///   dropped.
    pub fn recv_slice(&mut self, data: &mut [u8]) -> Result<usize, RecvError> {
        let packet = self.recv()?;
        if data.len() < packet.len() {
            return Err(RecvError::Truncated);
        }
        data[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }

    /// Peek at the next received packet without dequeueing it, as a borrow into the
    /// queue.
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is not bound.
    /// - `Exhausted`: if the RX queue is empty.
    pub fn peek(&self) -> Result<&[u8], RecvError> {
        if !self.is_open() {
            return Err(RecvError::InvalidState);
        }
        match self.state.rx_queue.front() {
            Some(buf) => Ok(buf),
            None => Err(RecvError::Exhausted),
        }
    }

    /// Peek at the next received packet without dequeueing it, copying it into the
    /// given slice.
    ///
    /// See also [peek](#method.peek).
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is not bound.
    /// - `Exhausted`: if the RX queue is empty.
    /// - `Truncated`: if `data` is smaller than the packet. No data is copied
    ///   and the packet stays in the queue.
    pub fn peek_slice(&self, data: &mut [u8]) -> Result<usize, RecvError> {
        let packet = self.peek()?;
        if data.len() < packet.len() {
            return Err(RecvError::Truncated);
        }
        data[..packet.len()].copy_from_slice(packet);
        Ok(packet.len())
    }

    /// Send a packet, copying it from a slice.
    ///
    /// See [send_with](#method.send_with).
    pub fn send_slice(&mut self, data: &[u8]) -> Result<(), SendError> {
        self.send_slice_with_meta(data, PacketMeta::default())
    }

    /// Send a packet with the given [`PacketMeta`] attached, copying it from a slice.
    ///
    /// See [send_with_meta](#method.send_with_meta).
    pub fn send_slice_with_meta(&mut self, data: &[u8], meta: PacketMeta) -> Result<(), SendError> {
        self.send_with_meta(data.len(), meta, |buf| {
            buf.copy_from_slice(data);
            data.len()
        })
    }

    /// Send a packet, building it in place.
    ///
    /// The closure gets a `max_size`-byte slice inside a freshly allocated packet
    /// buffer, and returns how many bytes it wrote. The packet is then sent
    /// immediately.
    ///
    /// The packet must be complete, headers included:
    ///
    /// - In Ethernet mode, a whole Ethernet frame (including header, not including FCS). It
    ///   is transmitted as-is, on the bound interface if the socket is bound to
    ///   one, else on the first Ethernet interface.
    /// - In IP mode, a whole IP packet, with checksum calculated. The destination
    ///   address is read from the IP header, and the packet is routed like any
    ///   other egress packet (through the bound interface only, if the socket is bound to one).
    ///
    /// # Errors
    /// - `InvalidState`: if the socket is not bound.
    /// - `Unaddressable`: if there is no route to the
    ///   packet's destination or the destination is the unspecified address (IP
    ///   mode), or no Ethernet interface to send on (Ethernet mode).
    /// - `Malformed`: if the packet fails basic validation (too short for an
    ///   Ethernet header in Ethernet mode, malformed IP header in IP mode), or
    ///   does not match the socket's bind filters.
    /// - `BufferFull`: if the packet cannot fit in a packet buffer.
    /// - `NoBuffer`: if every packet buffer is in use.
    /// - `DeviceBusy`: if the interface the packet would go out of has no room
    ///   for it right now.
    ///
    /// # Panics
    /// Panics if the socket is bound to an interface that has been removed.
    pub fn send_with(&mut self, max_size: usize, f: impl FnOnce(&mut [u8]) -> usize) -> Result<(), SendError> {
        self.send_with_meta(max_size, PacketMeta::default(), f)
    }

    /// Send a packet with the given [`PacketMeta`] attached, building it in place.
    ///
    /// The metadata is handed to the driver along with the frame. This is how a
    /// packet is tagged with an id, or a transmit timestamp is requested for it (see
    /// [`Stack::poll_tx_timestamp`]). Everything else is exactly
    /// [`send_with`](Self::send_with).
    pub fn send_with_meta(
        &mut self,
        max_size: usize,
        meta: PacketMeta,
        f: impl FnOnce(&mut [u8]) -> usize,
    ) -> Result<(), SendError> {
        let Some(mode) = self.state.mode else {
            return Err(SendError::InvalidState);
        };

        // Ethernet frames go out as-is. IP packets get an Ethernet header prepended
        // on Ethernet mediums, so they need headroom for it.
        let headroom = match mode {
            #[cfg(feature = "raw-ethernet")]
            RawMode::Ethernet { .. } => 0,
            #[cfg(feature = "raw-ip")]
            RawMode::Ip { .. } => LINK_HEADER_LEN,
        };

        // Ethernet frames carry no routing information: a bound socket sends on
        // its interface, an unbound one on the first Ethernet interface. The
        // interface is known up front, so ask it for room before building. An
        // IP-mode packet names its destination inside, so it is built first and
        // routed after.
        #[cfg(feature = "raw-ethernet")]
        let eth_iface = match mode {
            RawMode::Ethernet { .. } => {
                let iface = match self.state.binding.iface() {
                    Some(iface) => iface,
                    None => self.tx.first_ethernet_iface().ok_or(SendError::Unaddressable)?,
                };
                if self.tx.can_transmit(iface).is_err() {
                    // `Stack::poll` wakes the socket once the interface has room.
                    #[cfg(feature = "async")]
                    {
                        self.state.tx_blocked_on = Some(iface);
                    }
                    return Err(SendError::DeviceBusy);
                }
                Some(iface)
            }
            #[cfg(feature = "raw-ip")]
            RawMode::Ip { .. } => None,
        };

        let Some(mut buf) = PacketBuf::try_new() else {
            return Err(SendError::NoBuffer);
        };
        if max_size > buf.capacity() - headroom {
            return Err(SendError::BufferFull);
        }
        buf.set_meta(meta);
        buf.reserve(PACKET_BUF_DRIVER_HEADROOM + headroom);
        buf.set_len(max_size);
        let size = f(&mut buf);
        assert!(size <= max_size);
        buf.set_len(size);

        match mode {
            #[cfg(feature = "raw-ethernet")]
            RawMode::Ethernet { ethertype } => {
                {
                    let Ok(frame) = EthernetFrame::new_checked(&mut buf) else {
                        return Err(SendError::Malformed);
                    };
                    if ethertype.is_some_and(|t| t != frame.ethertype()) {
                        return Err(SendError::Malformed);
                    }
                }
                trace!("raw: sending {} octet frame", buf.len());
                self.tx.transmit_ethernet(unwrap!(eth_iface), buf);
                Ok(())
            }
            #[cfg(feature = "raw-ip")]
            RawMode::Ip { version, protocol } => {
                let Some((dst_addr, next_header)) = parse_ip_headers(&mut buf) else {
                    return Err(SendError::Malformed);
                };
                if version.is_some_and(|v| v != dst_addr.version()) || protocol.is_some_and(|p| p != next_header) {
                    return Err(SendError::Malformed);
                }
                // The unspecified address is never a destination (RFC 1122
                // §3.2.1.3, RFC 4291 §2.5.2).
                if dst_addr.is_unspecified() {
                    return Err(SendError::Unaddressable);
                }
                let route = self
                    .tx
                    .route(self.state.binding, &dst_addr)
                    .ok_or(SendError::Unaddressable)?;
                if self.tx.can_transmit(route.iface).is_err() {
                    // `Stack::poll` wakes the socket once the interface has room.
                    #[cfg(feature = "async")]
                    {
                        self.state.tx_blocked_on = Some(route.iface);
                    }
                    return Err(SendError::DeviceBusy);
                }
                trace!("raw: sending {} octets to {}", buf.len(), dst_addr);
                self.tx.transmit_raw_ip(&route, buf, dst_addr);
                Ok(())
            }
        }
    }
}

impl Stack<'_> {
    /// Offer an ingress Ethernet frame to the raw sockets. `buf` is the whole
    /// frame, Ethernet header included. `iface` is the interface it arrived on.
    ///
    /// The first Ethernet-mode socket whose interface binding and ethertype
    /// filter match receives it. If `stack_wants` is set (the stack itself
    /// processes this ethertype), the socket receives a copy and the original is
    /// returned for further processing. Otherwise the socket takes the buffer
    /// zero-copy and `None` is returned.
    #[cfg(feature = "raw-ethernet")]
    pub(crate) fn process_raw_ethernet(
        &mut self,
        iface: IfaceHandle,
        ethertype: EthernetProtocol,
        stack_wants: bool,
        buf: PacketBuf,
    ) -> Option<PacketBuf> {
        for (_, socket) in self.sockets.raw.iter_mut() {
            let Some(RawMode::Ethernet {
                ethertype: bound_ethertype,
            }) = socket.mode
            else {
                continue;
            };
            if !socket.binding.matches(iface) {
                continue;
            }
            if bound_ethertype.is_some_and(|t| t != ethertype) {
                continue;
            }

            trace!("raw: receiving {} octet frame (ethertype {})", buf.len(), ethertype);
            if stack_wants {
                if let Some(copy) = copy_packet(&buf) {
                    socket.rx_enqueue(copy);
                }
                return Some(buf);
            } else {
                socket.rx_enqueue(buf);
                return None;
            }
        }
        Some(buf)
    }

    /// Offer an ingress IP packet to the raw sockets. `buf` is the whole packet,
    /// IP header included, already trimmed of link-layer padding. `iface` is the
    /// interface it arrived on.
    ///
    /// The first socket whose interface/version/protocol filters match receives
    /// it. If `stack_wants` is set (the stack itself processes this protocol),
    /// the socket receives a copy and the original is returned for further
    /// processing. Otherwise the socket takes the buffer zero-copy and `None` is
    /// returned.
    ///
    /// The returned flag records whether a socket received (a copy of) the packet.
    /// The stack suppresses its own error replies (ICMP port unreachable) for
    /// packets an application is handling through a raw socket.
    #[cfg(feature = "raw-ip")]
    pub(crate) fn process_raw_ip(
        &mut self,
        iface: IfaceHandle,
        version: IpVersion,
        protocol: IpProtocol,
        stack_wants: bool,
        buf: PacketBuf,
    ) -> Option<(PacketBuf, bool)> {
        for (_, socket) in self.sockets.raw.iter_mut() {
            let Some(RawMode::Ip {
                version: bound_version,
                protocol: bound_protocol,
            }) = socket.mode
            else {
                continue;
            };
            if !socket.binding.matches(iface) {
                continue;
            }
            if bound_version.is_some_and(|v| v != version) {
                continue;
            }
            if bound_protocol.is_some_and(|p| p != protocol) {
                continue;
            }

            trace!("raw: receiving {} octets ({} {})", buf.len(), version, protocol);
            if stack_wants {
                if let Some(copy) = copy_packet(&buf) {
                    socket.rx_enqueue(copy);
                }
                return Some((buf, true));
            } else {
                socket.rx_enqueue(buf);
                return None;
            }
        }
        Some((buf, false))
    }
}

/// Iterator over the raw sockets of a [`Stack`], returned by [`Stack::raw_sockets`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.raw_sockets();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.can_recv());
/// }
/// # }
/// ```
pub struct RawSocketIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> RawSocketIter<'_, 'd> {
    /// Get the next raw socket, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(RawHandle, RawSocket<'_, 'd>)> {
        let index = self.stack.sockets.raw.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = RawHandle::new(index);
        Some((handle, self.stack.raw_socket(handle)))
    }
}

#[cfg(all(
    test,
    feature = "raw-ethernet",
    feature = "raw-ip",
    feature = "medium-ethernet",
    feature = "medium-ip",
    feature = "ipv4",
    feature = "ipv6"
))]
mod test {

    use super::*;
    use crate::stack::Stack;
    use crate::test_device::{Sent, TestDevice};
    use crate::wire::{
        ETHERNET_HEADER_LEN, EthernetAddress, HardwareAddress, IPV4_HEADER_LEN, IPV6_HEADER_LEN, Icmpv4Message,
        Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpCidr, Ipv4Addr, Ipv6Addr,
    };

    fn add_test_iface(stack: &mut Stack, medium: Medium, ip_addrs: Vec<IpCidr>) -> (IfaceHandle, Sent) {
        let driver = TestDevice::new(medium);
        let tx = driver.tx.clone();
        let handle = driver.install(
            stack,
            match medium {
                Medium::Ethernet => HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01])),
                Medium::Ip => HardwareAddress::Ip,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => unreachable!(),
            },
        );
        stack.iface(handle).set_ip_addrs(ip_addrs).unwrap();
        (handle, tx)
    }

    const IP_PROTO: IpProtocol = IpProtocol(63);
    const ETHERTYPE_CUSTOM: EthernetProtocol = EthernetProtocol(0x88b5);

    /// A whole IPv4 packet with an arbitrary protocol. The header checksum is left
    /// zero, so tests double as proof that nothing rewrites the header.
    fn ipv4_packet(protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV4_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(4);
            ip.set_header_len(IPV4_HEADER_LEN as u8);
            ip.set_total_len((IPV4_HEADER_LEN + payload.len()) as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(Ipv4Addr::new(192, 168, 69, 1));
            ip.set_dst_addr(Ipv4Addr::new(192, 168, 69, 2));
        }
        bytes[IPV4_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn ipv6_packet(protocol: IpProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; IPV6_HEADER_LEN + payload.len()];
        {
            let mut ip = Ipv6Packet::new_unchecked(&mut bytes[..]);
            ip.set_version(6);
            ip.set_payload_len(payload.len() as u16);
            ip.set_next_header(protocol);
            ip.set_hop_limit(64);
            ip.set_src_addr(Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1));
            ip.set_dst_addr(Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2));
        }
        bytes[IPV6_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn eth_frame(ethertype: EthernetProtocol, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; ETHERNET_HEADER_LEN + payload.len()];
        {
            let mut frame = EthernetFrame::new_unchecked(&mut bytes[..]);
            frame.set_dst_addr(EthernetAddress([0x02, 0, 0, 0, 0, 0x01]));
            frame.set_src_addr(EthernetAddress([0x02, 0, 0, 0, 0, 0x02]));
            frame.set_ethertype(ethertype);
        }
        bytes[ETHERNET_HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    fn buf_from(bytes: &[u8]) -> PacketBuf {
        let mut buf = PacketBuf::try_new().unwrap();
        buf.set_len(bytes.len());
        buf.copy_from_slice(bytes);
        buf
    }

    #[test]
    fn test_bind_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        assert!(!socket.is_open());
        assert_eq!(socket.mode(), None);

        let mode = RawMode::Ip {
            version: Some(IpVersion::V4),
            protocol: Some(IpProtocol::Icmp),
        };
        assert_eq!(socket.bind(mode), Ok(()));
        assert!(socket.is_open());
        assert_eq!(socket.mode(), Some(mode));
        assert_eq!(
            socket.bind(RawMode::Ip {
                version: None,
                protocol: None
            }),
            Err(BindError::InvalidState)
        );

        socket.close();
        assert!(!socket.is_open());
        assert_eq!(
            socket.bind(RawMode::Ip {
                version: None,
                protocol: None
            }),
            Ok(())
        );
    }

    #[test]
    fn test_bind_ethernet() {
        // An unbound Ethernet-mode bind is fine: the socket covers every
        // Ethernet interface.
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        assert_eq!(
            socket.bind(RawMode::Ethernet {
                ethertype: Some(ETHERTYPE_CUSTOM)
            }),
            Ok(())
        );
        assert!(socket.is_open());
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (eth_iface, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (ip_iface, _) = add_test_iface(&mut stack, Medium::Ip, vec![]);

        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);

        // An Ethernet-mode socket may only be bound to an Ethernet-medium
        // interface.
        socket.bind_to_iface(Some(ip_iface)).unwrap();
        assert_eq!(
            socket.bind(RawMode::Ethernet { ethertype: None }),
            Err(BindError::InvalidMedium)
        );
        assert!(!socket.is_open());

        socket.bind_to_iface(Some(eth_iface)).unwrap();
        assert_eq!(socket.bound_iface(), Some(eth_iface));
        assert_eq!(
            socket.bind(RawMode::Ethernet {
                ethertype: Some(ETHERTYPE_CUSTOM)
            }),
            Ok(())
        );
        assert!(socket.is_open());

        // The binding cannot change while the socket is bound, and is kept
        // across close.
        assert_eq!(socket.bind_to_iface(None), Err(BindError::InvalidState));
        socket.close();
        assert_eq!(socket.bound_iface(), Some(eth_iface));
    }

    #[test]
    fn test_recv() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);

        // Not bound yet.
        assert_eq!(socket.recv().err(), Some(RecvError::InvalidState));
        assert_eq!(socket.peek().err(), Some(RecvError::InvalidState));

        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        assert!(!socket.can_recv());
        assert_eq!(socket.recv().err(), Some(RecvError::Exhausted));
        assert_eq!(socket.peek().err(), Some(RecvError::Exhausted));

        let packet = ipv4_packet(IP_PROTO, b"abcdef");
        socket.state.rx_enqueue(buf_from(&packet));
        assert!(socket.can_recv());

        // The whole packet, header included, byte for byte.
        assert_eq!(socket.peek().unwrap(), &packet[..]);
        assert_eq!(&*socket.recv().unwrap(), &packet[..]);
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_peek_and_recv_slice() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        let packet = ipv4_packet(IP_PROTO, b"abcdef");
        socket.state.rx_enqueue(buf_from(&packet));

        let mut slice = [0; 64];
        // Peeking does not dequeue.
        assert_eq!(socket.peek_slice(&mut slice).unwrap(), packet.len());
        assert_eq!(&slice[..packet.len()], &packet[..]);

        let len = socket.recv_slice(&mut slice).unwrap();
        assert_eq!(&slice[..len], &packet[..]);
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Exhausted));
    }

    #[test]
    fn test_recv_slice_truncated() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        let mut socket = stack.raw_socket(handle);
        socket
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();
        socket.state.rx_enqueue(buf_from(&ipv4_packet(IP_PROTO, b"abcdef")));

        let mut slice = [0; 4];
        // peek_slice keeps the packet...
        assert_eq!(socket.peek_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(socket.can_recv());
        // ...recv_slice drops it.
        assert_eq!(socket.recv_slice(&mut slice).err(), Some(RecvError::Truncated));
        assert!(!socket.can_recv());
    }

    #[test]
    fn test_demux_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let h_icmp = stack.add_raw_socket().unwrap();
        let h_any = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(h_icmp)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V4),
                protocol: Some(IpProtocol::Icmp),
            })
            .unwrap();
        stack
            .raw_socket(h_any)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        // Not a stack protocol: the first matching socket takes the buffer.
        let packet = ipv4_packet(IP_PROTO, b"abcd");
        let res = stack.process_raw_ip(IfaceHandle::new(0), IpVersion::V4, IP_PROTO, false, buf_from(&packet));
        assert!(res.is_none());
        assert!(!stack.raw_socket(h_icmp).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &packet[..]);

        // A stack-handled protocol: the matching socket gets a copy, the original
        // is handed back for further processing.
        let packet = ipv4_packet(IpProtocol::Icmp, b"ping");
        let res = stack.process_raw_ip(
            IfaceHandle::new(0),
            IpVersion::V4,
            IpProtocol::Icmp,
            true,
            buf_from(&packet),
        );
        let (res_buf, handled) = res.unwrap();
        assert_eq!(&*res_buf, &packet[..]);
        assert!(handled);
        assert_eq!(&*stack.raw_socket(h_icmp).recv().unwrap(), &packet[..]);
        assert!(!stack.raw_socket(h_any).can_recv());

        // Version filter: an IPv6 packet skips the IPv4-bound socket.
        let packet = ipv6_packet(IpProtocol::Icmp, b"six");
        let res = stack.process_raw_ip(
            IfaceHandle::new(0),
            IpVersion::V6,
            IpProtocol::Icmp,
            false,
            buf_from(&packet),
        );
        assert!(res.is_none());
        assert!(!stack.raw_socket(h_icmp).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &packet[..]);

        // No socket matches: the buffer is handed back.
        stack.raw_socket(h_any).close();
        let packet = ipv4_packet(IP_PROTO, b"nobody");
        let res = stack.process_raw_ip(IfaceHandle::new(0), IpVersion::V4, IP_PROTO, false, buf_from(&packet));
        let (res_buf, handled) = res.unwrap();
        assert_eq!(&*res_buf, &packet[..]);
        assert!(!handled);
    }

    /// Packet metadata reaches a raw socket on the zero-copy ingress path *and* on
    /// the copy the socket gets when the stack also wants the packet, and rides back
    /// out to the device on send.
    #[cfg(feature = "packetmeta-id")]
    #[test]
    fn test_packet_meta() {
        let driver = TestDevice::new(Medium::Ethernet);
        let sent = driver.tx_meta.clone();
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let iface = driver.install(
            &mut stack,
            HardwareAddress::Ethernet(EthernetAddress([0x02, 0, 0, 0, 0, 0x01])),
        );

        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();

        // Zero-copy ingress: the socket takes the very buffer the driver filled.
        let mut buf = buf_from(&eth_frame(ETHERTYPE_CUSTOM, b"abcd"));
        buf.meta_mut().id = 0x1111;
        let res = stack.process_raw_ethernet(iface, ETHERTYPE_CUSTOM, false, buf);
        assert!(res.is_none());
        assert_eq!(stack.raw_socket(handle).recv().unwrap().meta().id, 0x1111);

        // Copied ingress (the stack wants the ethertype too): the copy is the same
        // packet, so it carries the same metadata.
        let mut buf = buf_from(&eth_frame(EthernetProtocol::Arp, b"abcd"));
        buf.meta_mut().id = 0x2222;
        let res = stack.process_raw_ethernet(iface, EthernetProtocol::Arp, true, buf);
        assert_eq!(res.unwrap().meta().id, 0x2222);
        assert_eq!(stack.raw_socket(handle).recv().unwrap().meta().id, 0x2222);

        // Egress: the metadata handed to send reaches the device, and a plain send
        // carries the default.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"out");
        let mut meta = PacketMeta::default();
        meta.id = 0x3333;
        stack.raw_socket(handle).send_slice_with_meta(&frame, meta).unwrap();
        stack.raw_socket(handle).send_slice(&frame).unwrap();
        assert_eq!(&*sent.borrow(), &[meta, PacketMeta::default()]);
    }

    #[test]
    fn test_demux_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (iface_a, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (iface_b, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);

        let h_custom = stack.add_raw_socket().unwrap();
        let h_any = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(h_custom)
            .bind(RawMode::Ethernet {
                ethertype: Some(ETHERTYPE_CUSTOM),
            })
            .unwrap();
        stack
            .raw_socket(h_any)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();

        // Unbound sockets receive from every Ethernet interface; the first
        // matching socket takes the frame.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        let res = stack.process_raw_ethernet(iface_a, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert!(res.is_none());
        assert_eq!(&*stack.raw_socket(h_custom).recv().unwrap(), &frame[..]);
        assert!(!stack.raw_socket(h_any).can_recv());
        let res = stack.process_raw_ethernet(iface_b, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert!(res.is_none());
        assert_eq!(&*stack.raw_socket(h_custom).recv().unwrap(), &frame[..]);

        // A stack-handled ethertype skips the filtered socket, and the wildcard
        // socket gets a copy while the original is handed back.
        let frame = eth_frame(EthernetProtocol::Arp, b"arp?");
        let res = stack.process_raw_ethernet(iface_a, EthernetProtocol::Arp, true, buf_from(&frame));
        assert_eq!(&*res.unwrap(), &frame[..]);
        assert!(!stack.raw_socket(h_custom).can_recv());
        assert_eq!(&*stack.raw_socket(h_any).recv().unwrap(), &frame[..]);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_ethernet_demux() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (iface_a, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (iface_b, _) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);

        let handle = stack.add_raw_socket().unwrap();
        stack.raw_socket(handle).bind_to_iface(Some(iface_a)).unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();

        // A frame on another interface does not match a bound socket.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        let res = stack.process_raw_ethernet(iface_b, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert_eq!(&*res.unwrap(), &frame[..]);
        assert!(!stack.raw_socket(handle).can_recv());

        // One on the bound interface does.
        let res = stack.process_raw_ethernet(iface_a, ETHERTYPE_CUSTOM, false, buf_from(&frame));
        assert!(res.is_none());
        assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &frame[..]);
    }

    #[test]
    fn test_send_ethernet() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_iface, tx) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let handle = stack.add_raw_socket().unwrap();

        // Not bound yet.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&frame),
            Err(SendError::InvalidState)
        );

        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet {
                ethertype: Some(ETHERTYPE_CUSTOM),
            })
            .unwrap();

        assert_eq!(stack.raw_socket(handle).send_slice(&frame), Ok(()));
        assert_eq!(*tx.borrow(), vec![frame.clone()]);

        // Shorter than an Ethernet header.
        assert_eq!(stack.raw_socket(handle).send_slice(&[0; 10]), Err(SendError::Malformed));
        // Ethertype filter mismatch.
        let wrong = eth_frame(EthernetProtocol::Ipv4, b"hello");
        assert_eq!(stack.raw_socket(handle).send_slice(&wrong), Err(SendError::Malformed));
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_send_ethernet_unbound_iface_selection() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();

        // No Ethernet interface at all: nothing to send on.
        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&frame),
            Err(SendError::Unaddressable)
        );

        // An unbound socket sends out the first Ethernet-medium interface. An
        // IP-medium one added earlier is skipped.
        let (_ip_iface, ip_tx) = add_test_iface(&mut stack, Medium::Ip, vec![]);
        let (_eth_iface, eth_tx) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        stack.raw_socket(handle).send_slice(&frame).unwrap();
        assert!(ip_tx.borrow().is_empty());
        assert_eq!(eth_tx.borrow().len(), 1);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_ethernet_send() {
        // A bound socket sends out its interface, not the first one.
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_eth_a, tx_a) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);
        let (eth_b, tx_b) = add_test_iface(&mut stack, Medium::Ethernet, vec![]);

        let handle = stack.add_raw_socket().unwrap();
        stack.raw_socket(handle).bind_to_iface(Some(eth_b)).unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ethernet { ethertype: None })
            .unwrap();

        let frame = eth_frame(ETHERTYPE_CUSTOM, b"hello");
        stack.raw_socket(handle).send_slice(&frame).unwrap();
        assert!(tx_a.borrow().is_empty());
        assert_eq!(tx_b.borrow().len(), 1);
    }

    #[test]
    fn test_send_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V4),
                protocol: None,
            })
            .unwrap();

        // No interface: no route to the destination.
        let packet = ipv4_packet(IP_PROTO, b"abcd");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet),
            Err(SendError::Unaddressable)
        );

        // An IP-medium interface with the destination on-link. The packet goes out
        // byte for byte, the zeroed header checksum proves nothing rewrites it.
        let (_iface, tx) = add_test_iface(
            &mut stack,
            Medium::Ip,
            vec![IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24)],
        );
        assert_eq!(stack.raw_socket(handle).send_slice(&packet), Ok(()));
        assert_eq!(*tx.borrow(), vec![packet.clone()]);

        // Malformed: empty, bogus version nibble, truncated header.
        assert_eq!(stack.raw_socket(handle).send_slice(&[]), Err(SendError::Malformed));
        assert_eq!(
            stack.raw_socket(handle).send_slice(&[0xf0; 40]),
            Err(SendError::Malformed)
        );
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet[..10]),
            Err(SendError::Malformed)
        );
        // Version filter mismatch: an IPv6 packet on an IPv4-bound socket.
        let v6 = ipv6_packet(IP_PROTO, b"abcd");
        assert_eq!(stack.raw_socket(handle).send_slice(&v6), Err(SendError::Malformed));
        // Too big for a packet buffer (IP mode leaves room for the Ethernet header).
        assert_eq!(
            stack.raw_socket(handle).send_with(
                crate::driver::config::PACKET_BUF_SIZE - LINK_HEADER_LEN + 1,
                |_| unreachable!()
            ),
            Err(SendError::BufferFull)
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    #[cfg(feature = "iface-bind")]
    #[test]
    fn test_bind_to_iface_ip() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (if0, tx0) = add_test_iface(&mut stack, Medium::Ip, vec![IpCidr::new(IpAddr::v4(10, 0, 0, 1), 24)]);
        let (if1, tx1) = add_test_iface(
            &mut stack,
            Medium::Ip,
            vec![IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24)],
        );

        let handle = stack.add_raw_socket().unwrap();
        stack.raw_socket(handle).bind_to_iface(Some(if1)).unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        // Ingress filter: a packet arriving on another interface is not
        // delivered, one on the bound interface is.
        let packet = ipv4_packet(IP_PROTO, b"abcd");
        let res = stack.process_raw_ip(if0, IpVersion::V4, IP_PROTO, false, buf_from(&packet));
        assert!(res.is_some_and(|(_, handled)| !handled));
        assert!(!stack.raw_socket(handle).can_recv());
        let res = stack.process_raw_ip(if1, IpVersion::V4, IP_PROTO, false, buf_from(&packet));
        assert!(res.is_none());
        assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &packet[..]);

        // Egress routes through the bound interface: the destination is
        // on-link for it, so the packet goes out of it.
        stack.raw_socket(handle).send_slice(&packet).unwrap();
        assert!(tx0.borrow().is_empty());
        assert_eq!(tx1.borrow().len(), 1);

        // Bound to the other interface, the same destination has no route.
        stack.raw_socket(handle).close();
        stack.raw_socket(handle).bind_to_iface(Some(if0)).unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet),
            Err(SendError::Unaddressable)
        );
    }

    #[test]
    fn test_send_ip_protocol_filter() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_iface, tx) = add_test_iface(
            &mut stack,
            Medium::Ip,
            vec![IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24)],
        );
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: Some(IP_PROTO),
            })
            .unwrap();

        assert_eq!(
            stack
                .raw_socket(handle)
                .send_slice(&ipv4_packet(IpProtocol::Tcp, b"nope")),
            Err(SendError::Malformed)
        );
        assert_eq!(
            stack.raw_socket(handle).send_slice(&ipv4_packet(IP_PROTO, b"yep")),
            Ok(())
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    const LOCAL_V4: IpCidr = IpCidr::new(IpAddr::v4(192, 168, 69, 1), 24);
    const LOCAL_V6: IpCidr = IpCidr::new(IpAddr::v6(0xfdaa, 0, 0, 0, 0, 0, 0, 1), 64);

    #[test]
    fn test_send_ipv6() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V6),
                protocol: Some(IP_PROTO),
            })
            .unwrap();

        // No interface owns an fdaa:: address: no route to the destination.
        let packet = ipv6_packet(IP_PROTO, b"abcd");
        assert_eq!(
            stack.raw_socket(handle).send_slice(&packet),
            Err(SendError::Unaddressable)
        );

        // With the destination on-link, the packet goes out byte for byte.
        let (_iface, tx) = add_test_iface(&mut stack, Medium::Ip, vec![LOCAL_V6]);
        // Adding an IPv6 address may make the stack transmit on its own.
        tx.borrow_mut().clear();
        assert_eq!(stack.raw_socket(handle).send_slice(&packet), Ok(()));
        assert_eq!(*tx.borrow(), vec![packet.clone()]);

        // Version filter mismatch: an IPv4 packet on an IPv6-bound socket.
        assert_eq!(
            stack.raw_socket(handle).send_slice(&ipv4_packet(IP_PROTO, b"abcd")),
            Err(SendError::Malformed)
        );
        // Protocol filter mismatch.
        assert_eq!(
            stack
                .raw_socket(handle)
                .send_slice(&ipv6_packet(IpProtocol::Tcp, b"abcd")),
            Err(SendError::Malformed)
        );
        // Too big for a packet buffer: IP mode leaves room for the link header,
        // whatever medium the packet ends up going out of.
        let max = crate::driver::config::PACKET_BUF_SIZE - LINK_HEADER_LEN;
        assert_eq!(
            stack.raw_socket(handle).send_with(max + 1, |_| unreachable!()),
            Err(SendError::BufferFull)
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    /// An ICMPv4 echo request: ident 0x1234, sequence 0x5678, 16 bytes of 0xff.
    fn icmpv4_echo_request() -> Vec<u8> {
        let mut bytes = vec![0xff; 24];
        let mut icmp = Icmpv4Packet::new_unchecked(&mut bytes[..]);
        icmp.set_msg_type(Icmpv4Message::EchoRequest);
        icmp.set_msg_code(0);
        icmp.set_echo_ident(0x1234);
        icmp.set_echo_seq_no(0x5678);
        icmp.fill_checksum();
        bytes
    }

    /// An ICMPv6 echo request, like [`icmpv4_echo_request`], with the checksum
    /// computed over the given addresses.
    fn icmpv6_echo_request(src_addr: &Ipv6Addr, dst_addr: &Ipv6Addr) -> Vec<u8> {
        let mut bytes = vec![0xff; 24];
        let mut icmp = Icmpv6Packet::new_unchecked(&mut bytes[..]);
        icmp.set_msg_type(Icmpv6Message::EchoRequest);
        icmp.set_msg_code(0);
        icmp.set_echo_ident(0x1234);
        icmp.set_echo_seq_no(0x5678);
        icmp.fill_checksum(src_addr, dst_addr);
        bytes
    }

    #[test]
    fn test_send_icmpv4_echo() {
        // Ping goes through a raw socket: the whole packet, ICMP header and
        // checksum included, is the user's and goes out untouched.
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_iface, tx) = add_test_iface(&mut stack, Medium::Ip, vec![LOCAL_V4]);
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V4),
                protocol: Some(IpProtocol::Icmp),
            })
            .unwrap();

        let packet = ipv4_packet(IpProtocol::Icmp, &icmpv4_echo_request());
        {
            let mut copy = packet.clone();
            let mut ip = Ipv4Packet::new_checked(&mut copy[..]).unwrap();
            let icmp = Icmpv4Packet::new_checked(ip.payload_mut()).unwrap();
            assert!(icmp.verify_checksum());
        }
        assert_eq!(stack.raw_socket(handle).send_slice(&packet), Ok(()));
        assert_eq!(*tx.borrow(), vec![packet.clone()]);

        // An unspecified destination is no destination.
        let mut unaddressable = packet.clone();
        Ipv4Packet::new_unchecked(&mut unaddressable[..]).set_dst_addr(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            stack.raw_socket(handle).send_slice(&unaddressable),
            Err(SendError::Unaddressable)
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_send_icmpv6_echo() {
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_iface, tx) = add_test_iface(&mut stack, Medium::Ip, vec![LOCAL_V6]);
        // Adding an IPv6 address may make the stack transmit on its own.
        tx.borrow_mut().clear();
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V6),
                protocol: Some(IpProtocol::Icmpv6),
            })
            .unwrap();

        let src_addr = Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 1);
        let dst_addr = Ipv6Addr::new(0xfdaa, 0, 0, 0, 0, 0, 0, 2);
        let packet = ipv6_packet(IpProtocol::Icmpv6, &icmpv6_echo_request(&src_addr, &dst_addr));
        {
            let mut copy = packet.clone();
            let mut ip = Ipv6Packet::new_checked(&mut copy[..]).unwrap();
            let icmp = Icmpv6Packet::new_checked(ip.payload_mut()).unwrap();
            assert!(icmp.verify_checksum(&src_addr, &dst_addr));
        }
        assert_eq!(stack.raw_socket(handle).send_slice(&packet), Ok(()));
        assert_eq!(*tx.borrow(), vec![packet.clone()]);

        // An unspecified destination is no destination.
        let mut unaddressable = packet.clone();
        Ipv6Packet::new_unchecked(&mut unaddressable[..]).set_dst_addr(Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            stack.raw_socket(handle).send_slice(&unaddressable),
            Err(SendError::Unaddressable)
        );
        assert_eq!(tx.borrow().len(), 1);
    }

    #[test]
    fn test_unfiltered_sends_all() {
        // One unfiltered socket sends packets of either IP version and any
        // protocol.
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let (_iface, tx) = add_test_iface(&mut stack, Medium::Ip, vec![LOCAL_V4, LOCAL_V6]);
        // Adding an IPv6 address may make the stack transmit on its own.
        tx.borrow_mut().clear();
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();

        let packets = [
            ipv4_packet(IpProtocol::Udp, b"v4 udp"),
            ipv4_packet(IpProtocol::Tcp, b"v4 tcp"),
            ipv6_packet(IpProtocol::Udp, b"v6 udp"),
            ipv6_packet(IpProtocol::Tcp, b"v6 tcp"),
        ];
        for packet in &packets {
            assert_eq!(stack.raw_socket(handle).send_slice(packet), Ok(()));
        }
        assert_eq!(*tx.borrow(), packets.to_vec());
    }

    #[test]
    fn test_unfiltered_accepts_all() {
        // Every one of these is a stack protocol, so ingress offers each socket a
        // copy and hands the original back for the stack's own processing.
        let mut stack = Stack::new(0x1234_5678_dead_beef);
        let iface = IfaceHandle::new(0);
        let packets = [
            (IpProtocol::Icmp, ipv4_packet(IpProtocol::Icmp, b"v4 icmp")),
            (IpProtocol::Tcp, ipv4_packet(IpProtocol::Tcp, b"v4 tcp")),
            (IpProtocol::Udp, ipv4_packet(IpProtocol::Udp, b"v4 udp")),
            (IpProtocol::Icmpv6, ipv6_packet(IpProtocol::Icmpv6, b"v6 icmp")),
            (IpProtocol::Tcp, ipv6_packet(IpProtocol::Tcp, b"v6 tcp")),
            (IpProtocol::Udp, ipv6_packet(IpProtocol::Udp, b"v6 udp")),
        ];

        // An unfiltered socket receives all of them.
        let handle = stack.add_raw_socket().unwrap();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: None,
                protocol: None,
            })
            .unwrap();
        for (protocol, packet) in &packets {
            let version = IpVersion::of_packet(packet).unwrap();
            let res = stack.process_raw_ip(iface, version, *protocol, true, buf_from(packet));
            let (res_buf, handled) = res.unwrap();
            assert_eq!(&*res_buf, &packet[..]);
            assert!(handled);
            assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &packet[..]);
        }

        // A socket filtered on (IPv6, ICMPv6) receives only that one.
        stack.raw_socket(handle).close();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V6),
                protocol: Some(IpProtocol::Icmpv6),
            })
            .unwrap();
        for (protocol, packet) in &packets {
            let version = IpVersion::of_packet(packet).unwrap();
            let res = stack.process_raw_ip(iface, version, *protocol, true, buf_from(packet));
            let (res_buf, handled) = res.unwrap();
            assert_eq!(&*res_buf, &packet[..]);
            let wanted = version == IpVersion::V6 && *protocol == IpProtocol::Icmpv6;
            assert_eq!(handled, wanted);
            assert_eq!(stack.raw_socket(handle).can_recv(), wanted);
            if wanted {
                assert_eq!(&*stack.raw_socket(handle).recv().unwrap(), &packet[..]);
            }
        }

        // A protocol filter does not override the version filter: an IPv4 packet
        // of the right protocol is not for an IPv6-bound socket.
        stack.raw_socket(handle).close();
        stack
            .raw_socket(handle)
            .bind(RawMode::Ip {
                version: Some(IpVersion::V6),
                protocol: Some(IP_PROTO),
            })
            .unwrap();
        let packet = ipv4_packet(IP_PROTO, b"v4 only");
        let res = stack.process_raw_ip(iface, IpVersion::V4, IP_PROTO, false, buf_from(&packet));
        let (res_buf, handled) = res.unwrap();
        assert_eq!(&*res_buf, &packet[..]);
        assert!(!handled);
        assert!(!stack.raw_socket(handle).can_recv());
    }
}
