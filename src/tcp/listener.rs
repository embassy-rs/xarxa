//! TCP listeners.

#[cfg(feature = "tcp-timestamps")]
use super::TcpTimestampRepr;
use super::{DEFAULT_MSS, ListenError, MIN_REMOTE_MSS, State, TcpControl, TcpRepr, TcpSocketState, Tuple};
use crate::config::{TCP_LISTENER_BACKLOG, TCP_LISTENER_COUNT};
use crate::iface::IfaceHandle;
use crate::rand::Rand;
use crate::stack::{IfaceBinding, Stack, addr_score};
use crate::storage::{BoundedDeque, Slab};
use crate::tcp::TcpSeqNumber;
use crate::tcp::congestion::Controller as _;
#[cfg(feature = "async")]
use crate::waker::WakerRegistration;
use crate::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

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
    /// The remote's initial sequence number plus one.
    remote_seq_no: TcpSeqNumber,
    /// The remote window advertised in the SYN (never scaled).
    remote_win_len: usize,
    /// The window scale the remote offered, if any.
    remote_win_scale: Option<u8>,
    /// Whether the remote supports selective ACK.
    #[cfg(feature = "tcp-sack")]
    remote_has_sack: bool,
    /// The MSS the remote advertised (clamped), or the default.
    remote_mss: usize,
    /// The timestamp option of the SYN, if present.
    #[cfg(feature = "tcp-timestamps")]
    timestamp: Option<TcpTimestampRepr>,
}

/// TCP listener state, stored inside the stack.
#[derive(Debug)]
pub(crate) struct TcpListenerState {
    /// The listened endpoint. A zero port means the listener is closed. The
    /// address scopes the listen, from any address of any version down to one
    /// exact address.
    local: IpListenEndpoint,
    /// The interface the listener is bound to. Zero-sized without `iface-bind`.
    binding: IfaceBinding,
    /// The accept queue: SYNs waiting to be accepted, deduplicated by 4-tuple.
    queue: BoundedDeque<PendingSyn, TCP_LISTENER_BACKLOG>,
    #[cfg(feature = "async")]
    accept_waker: WakerRegistration,
}

impl TcpListenerState {
    pub(crate) fn new() -> TcpListenerState {
        TcpListenerState {
            local: IpListenEndpoint::UNSPECIFIED,
            binding: IfaceBinding::Any,
            queue: BoundedDeque::new(),
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
    pub(crate) fn match_score(&self, arrival: IfaceHandle, dst_addr: &IpAddress, dst_port: u16) -> Option<u8> {
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
    fn record_syn(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress, repr: &TcpRepr) {
        debug_assert!(repr.control == TcpControl::Syn && repr.ack_number.is_none());
        let tuple = Tuple {
            local: IpEndpoint::new(*dst_addr, repr.dst_port),
            remote: IpEndpoint::new(*src_addr, repr.src_port),
        };
        let syn = PendingSyn {
            tuple,
            remote_seq_no: repr.seq_number + 1,
            // The window field of a SYN is never scaled.
            remote_win_len: repr.window_len as usize,
            remote_win_scale: repr.window_scale,
            #[cfg(feature = "tcp-sack")]
            remote_has_sack: repr.sack_permitted,
            remote_mss: match repr.max_seg_size {
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
            if self.queue.push_back(syn).is_err() {
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
    fn process_rst(&mut self, src_addr: &IpAddress, dst_addr: &IpAddress, repr: &TcpRepr) -> bool {
        debug_assert!(repr.control == TcpControl::Rst);
        let tuple = Tuple {
            local: IpEndpoint::new(*dst_addr, repr.dst_port),
            remote: IpEndpoint::new(*src_addr, repr.src_port),
        };
        let before = self.queue.len();
        self.queue
            .retain(|s| !(s.tuple == tuple && repr.seq_number == s.remote_seq_no));
        if self.queue.len() != before {
            trace!("listener: queued SYN {} reset by remote", tuple);
            true
        } else {
            false
        }
    }
}

/// Offer an ingress segment to the stack's listeners, returning whether it was
/// consumed.
///
/// The listeners consume exactly two things, and never reply to either. A SYN
/// to a listened endpoint is recorded on the *most specific* matching listener,
/// where an exact local-address match beats a wildcard one, so a per-address
/// listener takes its address's connections away from an any-address one on the
/// same port. An RST aimed at a recorded SYN removes it. Everything else is
/// left to the caller's RST fallback.
pub(crate) fn process_listeners(
    listeners: &mut Slab<TcpListenerState, TCP_LISTENER_COUNT>,
    iface: IfaceHandle,
    src_addr: &IpAddress,
    dst_addr: &IpAddress,
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
    /// The local endpoint the client is connecting to.
    pub fn local_endpoint(&self) -> IpEndpoint {
        self.syn.tuple.local
    }

    /// The remote endpoint the connection attempt comes from.
    pub fn remote_endpoint(&self) -> IpEndpoint {
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
        s.local_seq_no = TcpSocketState::random_seq_no(rand);
        s.remote_seq_no = syn.remote_seq_no;
        s.remote_last_seq = s.local_seq_no;
        #[cfg(feature = "tcp-sack")]
        {
            s.remote_has_sack = syn.remote_has_sack;
        }
        s.remote_win_scale = syn.remote_win_scale;
        // Remote doesn't support window scaling, don't do it.
        if syn.remote_win_scale.is_none() {
            s.remote_win_shift = 0;
        }
        s.remote_win_len = syn.remote_win_len;
        s.remote_mss = syn.remote_mss;
        s.congestion_controller.set_mss(syn.remote_mss);
        // Answer with timestamps only if the SYN offered them.
        #[cfg(feature = "tcp-timestamps")]
        {
            s.timestamps = syn.timestamp.is_some();
            s.last_remote_tsval = syn.timestamp.map_or(0, |ts| ts.tsval);
            s.tsval_offset = TcpSocketState::random_tsval_offset(rand);
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

    /// Start listening on the given endpoint.
    ///
    /// Returns:
    /// - `Err(ListenError::Unaddressable)` if the port is zero.
    /// - `Err(ListenError::InvalidState)` if the listener is already listening
    ///   (unless it is listening on this same endpoint, which is a no-op).
    /// - `Err(ListenError::InUse)` if another listener is bound to an identical
    ///   endpoint. Listeners on the same port with *different* specificity (one
    ///   wildcard, one per-version, one per-address) may coexist, and so may
    ///   listeners on identical endpoints bound to different interfaces.
    pub fn listen(&mut self, local_endpoint: impl Into<IpListenEndpoint>) -> Result<(), ListenError> {
        let local = local_endpoint.into();
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
    /// Two listeners on the same endpoint can coexist if they are bound to different interfaces,
    /// or if one is not bound. In the latter case, the bound listener "wins" for incoming
    /// connections coming from the bound interface.
    ///
    /// Returns `Err(ListenError::InvalidState)` if the listener is open.
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
        state.local = IpListenEndpoint::UNSPECIFIED;
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

    /// Return the listened endpoint. The address is the filter the listen scoped
    /// the listener to. A zero port means the listener is closed.
    #[inline]
    pub fn local_endpoint(&self) -> IpListenEndpoint {
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
        let syn = state.queue.pop_front()?;
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
