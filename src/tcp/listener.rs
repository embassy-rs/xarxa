//! TCP listeners.

#[cfg(feature = "tcp-timestamps")]
use super::TcpTimestampRepr;
use super::{DEFAULT_MSS, ListenError, MIN_REMOTE_MSS, State, TcpControl, TcpRepr, TcpSocketState, Tuple};
use crate::config::{TCP_LISTENER_BACKLOG, TCP_LISTENER_COUNT};
use crate::iface::IfaceHandle;
use crate::rand::Rand;
use crate::stack::{IfaceBinding, Stack, addr_score};
use crate::storage::{BoundedVec, Slab};
use crate::tcp::TcpSeqNumber;
use crate::tcp::congestion::Controller as _;
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
use crate::wire::{IpAddr, ListenSocketAddr, SocketAddr};

define_handle! {
    /// A handle to a TCP listener added to a [`Stack`].
    ///
    /// [`Stack`]: crate::Stack
    TcpListenerHandle(crate::config::tcp_listener_index)
}

/// A SYN recorded in a listener's accept queue: the parsed handshake state
/// needed to create the connection socket at accept time.
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
struct PendingSyn {
    tuple: Tuple,
    /// RCV.NXT: the remote's initial sequence number plus one.
    recv_next: TcpSeqNumber,
    /// SND.WND: the remote window advertised in the SYN (never scaled).
    send_window: usize,
    /// Snd.Wind.Shift: the window scale the remote offered, if any.
    send_window_shift: Option<u8>,
    /// Whether the remote sent SACK-permitted.
    #[cfg(feature = "tcp-sack")]
    send_sack: bool,
    /// SendMSS: the MSS the remote advertised (clamped), or the default.
    send_mss: usize,
    /// The timestamp option of the SYN, if present.
    #[cfg(feature = "tcp-timestamps")]
    timestamp: Option<TcpTimestampRepr>,
}

/// TCP listener state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct TcpListenerState {
    /// The listened address. A zero port means the listener is closed. The
    /// address scopes the listen, from any address of any version down to one
    /// exact address.
    local: ListenSocketAddr,
    /// The interface the listener is bound to. Zero-sized without `iface-bind`.
    binding: IfaceBinding,
    /// The accept queue: SYNs waiting to be accepted, oldest first, deduplicated
    /// by 4-tuple.
    queue: BoundedVec<PendingSyn, TCP_LISTENER_BACKLOG>,
    #[cfg(feature = "async")]
    accept_waker: WakerRegistration,
}

impl TcpListenerState {
    pub(crate) fn new() -> TcpListenerState {
        TcpListenerState {
            local: ListenSocketAddr::UNSPECIFIED,
            binding: IfaceBinding::Any,
            queue: BoundedVec::new(),
            #[cfg(feature = "async")]
            accept_waker: WakerRegistration::new(),
        }
    }

    /// Score this listener against a segment to (`dst_addr`, `dst_port`)
    /// arriving on `arrival`.
    ///
    /// `None` if the listener does not match, else how specific the match is: an
    /// exact local-address match outscores a per-version one, which outscores a
    /// wildcard, and a listener bound to the arrival interface outscores an
    /// unbound one.
    pub(crate) fn match_score(&self, arrival: IfaceHandle, dst_addr: &IpAddr, dst_port: u16) -> Option<u8> {
        if self.local.port == 0 || dst_port != self.local.port {
            return None;
        }
        Some(self.binding.match_score(arrival)? + addr_score(&self.local, dst_addr)?)
    }

    /// Record a SYN aimed at this listener in the accept queue.
    ///
    /// The queue is deduplicated by 4-tuple, with the newest SYN winning: a
    /// retransmission (or a client aborting and reconnecting from the same
    /// port) updates the entry in place instead of queueing a duplicate. On a
    /// full queue the SYN is dropped silently, and the client retries. Nothing
    /// is ever transmitted in response. The SYN|ACK is sent by the socket the
    /// attempt is [`accept`](crate::tcp::TcpSocket::accept)ed into.
    fn record_syn(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr, repr: &TcpRepr) {
        debug_assert!(repr.control == TcpControl::Syn && repr.ack_number.is_none());
        let tuple = Tuple {
            local: SocketAddr::new(*dst_addr, repr.dst_port),
            remote: SocketAddr::new(*src_addr, repr.src_port),
        };
        let syn = PendingSyn {
            tuple,
            recv_next: repr.seq_number + 1,
            // The window field of a SYN is never scaled.
            send_window: repr.window_len as usize,
            send_window_shift: repr.window_scale,
            #[cfg(feature = "tcp-sack")]
            send_sack: repr.sack_permitted,
            send_mss: match repr.max_seg_size {
                // A zero MSS is treated as if the option were absent, a tiny
                // one is clamped.
                Some(mss) if mss != 0 => (mss as usize).max(MIN_REMOTE_MSS),
                _ => DEFAULT_MSS,
            },
            #[cfg(feature = "tcp-timestamps")]
            timestamp: repr.timestamp,
        };

        if let Some(entry) = self.queue.iter_mut().find(|s| s.tuple == tuple) {
            *entry = syn;
        } else {
            if self.queue.push(syn).is_err() {
                trace!(
                    "listener:{}: backlog full, dropping SYN from {}",
                    self.local, tuple.remote
                );
                return;
            }
            trace!("listener:{}: SYN from {}", self.local, tuple.remote);
            // There's a connection attempt to accept, notify the waiting task if any.
            #[cfg(feature = "async")]
            self.accept_waker.wake();
        }
    }

    /// Remove the queued SYN an RST is aimed at, if any, returning whether one
    /// was removed. The client gave up before we accepted. The only acceptable
    /// sequence number for a connection with nothing received past the SYN is
    /// exactly RCV.NXT.
    fn process_rst(&mut self, src_addr: &IpAddr, dst_addr: &IpAddr, repr: &TcpRepr) -> bool {
        debug_assert!(repr.control == TcpControl::Rst);
        let tuple = Tuple {
            local: SocketAddr::new(*dst_addr, repr.dst_port),
            remote: SocketAddr::new(*src_addr, repr.src_port),
        };
        // The queue holds at most one SYN per 4-tuple.
        match self.queue.iter().position(|s| s.tuple == tuple) {
            Some(i) if self.queue[i].recv_next == repr.seq_number => {
                self.queue.remove(i);
                trace!("listener: queued SYN {} reset by remote", tuple);
                true
            }
            _ => false,
        }
    }
}

/// Offer an ingress segment to the stack's listeners, returning whether it was
/// consumed.
///
/// The listeners consume exactly two things, and never reply to either. A SYN
/// to a listened address is recorded on the *most specific* matching listener,
/// where an exact local-address match beats a wildcard one, so a per-address
/// listener takes its address's connections away from an any-address one on the
/// same port. An RST aimed at a recorded SYN removes it. Everything else is
/// left to the caller's RST fallback.
pub(crate) fn process_listeners(
    listeners: &mut Slab<TcpListenerState, TCP_LISTENER_COUNT>,
    iface: IfaceHandle,
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    repr: &TcpRepr,
) -> bool {
    match repr.control {
        TcpControl::Syn if repr.ack_number.is_none() => {
            let mut best: Option<(usize, u8)> = None;
            for (index, listener) in listeners.iter() {
                if let Some(score) = listener.match_score(iface, dst_addr, repr.dst_port)
                    && best.is_none_or(|(_, best_score)| score > best_score)
                {
                    best = Some((index, score));
                }
            }
            if let Some((index, _)) = best {
                listeners.get_mut(index).record_syn(src_addr, dst_addr, repr);
                true
            } else {
                false
            }
        }
        TcpControl::Rst => listeners
            .iter_mut()
            .any(|(_, listener)| listener.binding.matches(iface) && listener.process_rst(src_addr, dst_addr, repr)),
        _ => false,
    }
}

/// A connection attempt accepted from a [`TcpListener`], returned by
/// [`TcpListener::accept`].
///
/// Pass it to [`TcpSocket::accept`] to set up a socket for it.
///
/// Dropping the token forgets the attempt. The client retransmits its SYN,
/// which queues the attempt on the listener again.
///
/// [`TcpSocket::accept`]: crate::tcp::TcpSocket::accept
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct AcceptToken {
    syn: PendingSyn,
    binding: IfaceBinding,
}

impl AcceptToken {
    /// The local address the client is connecting to.
    pub fn local_addr(&self) -> SocketAddr {
        self.syn.tuple.local
    }

    /// The remote address the connection attempt comes from.
    pub fn remote_addr(&self) -> SocketAddr {
        self.syn.tuple.remote
    }

    /// Set up a closed socket as the SYN-RECEIVED socket continuing the
    /// token's SYN. This mirrors what the SYN would have set up in a
    /// LISTEN-state socket: the SYN|ACK itself is built by the socket's
    /// dispatch from this state.
    ///
    /// The socket takes over the listener's interface binding, overwriting its
    /// own: the connection's traffic is on that link, and the SYN|ACK and
    /// everything after must leave through it.
    pub(crate) fn start_syn_received(self, s: &mut TcpSocketState<'_>, rand: &mut Rand) {
        debug_assert_eq!(s.state, State::Closed);
        let syn = self.syn;
        s.set_state(State::SynReceived);
        s.tuple = Some(syn.tuple);
        s.binding = self.binding;
        s.send_unack = TcpSocketState::random_seq_no(rand);
        s.recv_read = syn.recv_next;
        s.send_next = s.send_unack;
        #[cfg(feature = "tcp-sack")]
        {
            s.send_sack = syn.send_sack;
        }
        s.send_window_shift = syn.send_window_shift;
        // Remote doesn't support window scaling, don't do it.
        if syn.send_window_shift.is_none() {
            s.recv_window_shift = 0;
        }
        s.send_window = syn.send_window;
        s.send_window_max = syn.send_window;
        s.send_mss = syn.send_mss;
        s.congestion_controller.set_mss(syn.send_mss);
        // Answer with timestamps only if the SYN offered them.
        #[cfg(feature = "tcp-timestamps")]
        {
            s.send_ts_ok = syn.timestamp.is_some();
            s.ts_recent = syn.timestamp.map_or(0, |ts| ts.tsval);
            s.send_ts_offset = TcpSocketState::random_tsval_offset(rand);
        }
    }
}

/// A TCP listener borrowed from a [`Stack`], returned by [`Stack::tcp_listener`].
///
/// [`Stack`]: crate::Stack
/// [`Stack::tcp_listener`]: crate::Stack::tcp_listener
///
/// Use a [`TcpListener`] to accept incoming TCP connections.
///
/// A listener can be bound to a port and optionally an address.
/// It receives all incoming connection attempts and queues them.
/// Calling [`accept`](TcpListener::accept) pops an attempt from the queue as
/// an [`AcceptToken`]. Pass it to [`TcpSocket::accept`] to set up a socket for it.
///
/// Connection attempts (SYN packets) are not answered (with a SYN|ACK packet)
/// until a socket accepts them.
///
/// [`TcpSocket::accept`]: crate::tcp::TcpSocket::accept
pub struct TcpListener<'a> {
    pub(crate) listeners: &'a mut Slab<TcpListenerState, TCP_LISTENER_COUNT>,
    pub(crate) index: usize,
}

impl TcpListener<'_> {
    /// This listener's state in the slab.
    #[inline]
    fn inner(&self) -> &TcpListenerState {
        self.listeners.get(self.index)
    }

    /// Mutable variant of [`inner`](Self::inner).
    #[inline]
    fn inner_mut(&mut self) -> &mut TcpListenerState {
        self.listeners.get_mut(self.index)
    }

    /// Start listening on the given local address.
    ///
    /// # Errors
    /// - `Unaddressable`: if the port is zero.
    /// - `InvalidState`: if the listener is already listening (unless it is
    ///   listening on this same address, which is a no-op).
    /// - `InUse`: if another listener is bound to an identical address.
    ///   Listeners on the same port with *different* specificity (one wildcard,
    ///   one per-version, one per-address) may coexist, and so may listeners on
    ///   identical addresses bound to different interfaces.
    pub fn listen(&mut self, local: impl Into<ListenSocketAddr>) -> Result<(), ListenError> {
        let local = local.into();
        if local.port == 0 {
            return Err(ListenError::Unaddressable);
        }
        if self.is_open() {
            if self.inner().local == local {
                return Ok(());
            }
            return Err(ListenError::InvalidState);
        }
        let binding = self.inner().binding;
        if self
            .listeners
            .iter()
            .any(|(i, l)| i != self.index && l.local == local && l.binding == binding)
        {
            return Err(ListenError::InUse);
        }

        self.inner_mut().local = local;
        Ok(())
    }

    /// Bind the listener to an interface, or unbind it with `None`.
    ///
    /// A listener bound to an interface only accepts connection attempts that arrive on that interface.
    ///
    /// When accepting a connection, the sockets inherit the binding.
    ///
    /// The listener must be closed. The binding is kept across
    /// [`close`](Self::close).
    ///
    /// Two listeners on the same address can coexist if they are bound to different interfaces,
    /// or if one is not bound. In the latter case, the bound listener "wins" for incoming
    /// connections coming from the bound interface.
    ///
    /// # Errors
    /// - `InvalidState`: if the listener is open.
    #[cfg(feature = "iface-bind")]
    pub fn bind_to_iface(&mut self, iface: Option<IfaceHandle>) -> Result<(), ListenError> {
        if self.is_open() {
            return Err(ListenError::InvalidState);
        }
        self.inner_mut().binding = iface.into();
        Ok(())
    }

    /// Return the interface the listener is bound to, or `None`.
    ///
    /// See [`bind_to_iface`](Self::bind_to_iface).
    #[cfg(feature = "iface-bind")]
    pub fn bound_iface(&self) -> Option<IfaceHandle> {
        self.inner().binding.iface()
    }

    /// Stop listening, dropping all queued SYNs.
    ///
    /// The dropped SYNs are not reset. The clients' retransmissions are
    /// answered with an RST once the listener is gone.
    pub fn close(&mut self) {
        let state = self.inner_mut();
        state.local = ListenSocketAddr::UNSPECIFIED;
        state.queue.clear();
        // Wake the task waiting, so it can notice the listener is closed.
        #[cfg(feature = "async")]
        state.accept_waker.wake();
    }

    /// Whether the listener is listening.
    #[inline]
    pub fn is_open(&self) -> bool {
        self.inner().local.port != 0
    }

    /// Return the listened address. The address is the filter the listen scoped
    /// the listener to. A zero port means the listener is closed.
    #[inline]
    pub fn local_addr(&self) -> ListenSocketAddr {
        self.inner().local
    }

    /// Register a waker for [`accept`](Self::accept).
    ///
    /// The waker is woken on state changes that might affect the return value of
    /// `accept` calls, such as a SYN being queued, or the listener closing.
    ///
    /// Notes:
    ///
    /// - Only one waker can be registered at a time. If another waker was previously
    ///   registered, it is overwritten and will no longer be woken.
    /// - The Waker is woken only once. Once woken, you must register it again before
    ///   it may be woken again.
    /// - "Spurious wakes" are allowed: a wake doesn't guarantee the result of
    ///   `accept` has changed.
    #[cfg(feature = "async")]
    pub fn register_accept_waker(&mut self, waker: &core::task::Waker) {
        self.inner_mut().accept_waker.register(waker)
    }

    /// Whether a connection attempt is waiting to be [`accept`](Self::accept)ed.
    pub fn can_accept(&self) -> bool {
        !self.inner().queue.is_empty()
    }

    /// Accept a queued connection attempt.
    ///
    /// Returns an [`AcceptToken`], or `None` if none is
    /// queued.
    ///
    /// Pass it to [`TcpSocket::accept`] to set up a socket for the incoming connection.
    ///
    /// [`TcpSocket::accept`]: crate::tcp::TcpSocket::accept
    pub fn accept(&mut self) -> Option<AcceptToken> {
        let state = self.inner_mut();
        if state.queue.is_empty() {
            return None;
        }
        let syn = state.queue.remove(0);
        let binding = state.binding;
        trace!("listener:{}: accepting {}", state.local, syn.tuple);
        Some(AcceptToken { syn, binding })
    }
}

/// Iterator over the TCP listeners of a [`Stack`], returned by [`Stack::tcp_listeners`].
///
/// Each item borrows the stack, so only one can exist at a time. That is why this is
/// not an [`Iterator`] and cannot be used in a `for` loop. Use `while let`:
///
/// ```no_run
/// # use xarxa::Stack;
/// # fn f(stack: &mut Stack) {
/// let mut iter = stack.tcp_listeners();
/// while let Some((handle, item)) = iter.next() {
///     let _ = (handle, item.is_open());
/// }
/// # }
/// ```
pub struct TcpListenerIter<'a, 'd> {
    pub(crate) stack: &'a mut Stack<'d>,
    pub(crate) next: usize,
}

impl<'d> TcpListenerIter<'_, 'd> {
    /// Get the next TCP listener, with its handle.
    ///
    /// Returns `None` when there are no more.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<(TcpListenerHandle, TcpListener<'_>)> {
        let index = self.stack.sockets.tcp_listeners.next_occupied(self.next)?;
        self.next = index + 1;
        let handle = TcpListenerHandle::new(index);
        Some((handle, self.stack.tcp_listener(handle)))
    }
}
