package ssh

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// ErrServerClosed is returned by the Server's Serve, ListenAndServe,
// and ListenAndServeTLS methods after a call to Shutdown or Close.
var ErrServerClosed = errors.New("ssh: Server closed")

// openChannelSet tracks accepted channels for a connection so that
// connectionKeepAlive can mirror OpenSSH's client_alive_check() behavior:
// when at least one channel is open, send the keepalive as a channel
// request on that channel; otherwise fall back to a global request.
type openChannelSet struct {
	mu    sync.Mutex
	chans []gossh.Channel
}

func (s *openChannelSet) add(c gossh.Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chans = append(s.chans, c)
}

func (s *openChannelSet) any() gossh.Channel {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chans) == 0 {
		return nil
	}
	return s.chans[0]
}

func (s *openChannelSet) remove(c gossh.Channel) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ch := range s.chans {
		if ch == c {
			s.chans = append(s.chans[:i], s.chans[i+1:]...)
			return
		}
	}
}

// trackingNewChannel wraps a gossh.NewChannel so that successful Accept
// calls register the underlying channel with an openChannelSet. The
// ChannelHandler API receives a gossh.NewChannel and typically calls
// Accept() inside the handler, so wrapping at HandleConn dispatch time is
// the only place to observe acceptance for arbitrary external handlers
// without modifying them.
//
// The per-channel request stream returned by Accept is also wrapped so
// that close of the underlying gossh stream (channel teardown) drops the
// channel from the openChannelSet, and so each inbound request bumps the
// keep-alive activity marker.
type trackingNewChannel struct {
	gossh.NewChannel
	set              *openChannelSet
	onAccept         func(gossh.Channel)
	onClose          func(gossh.Channel)
	notePeerActivity func()
	ctx              Context
}

// trackingChanReqBuffer matches gossh's per-channel request channel
// buffer (see chanSize in golang.org/x/crypto/ssh/handshake.go). Keeping
// the size in sync avoids changing back-pressure semantics for handlers
// that did not previously block on a full request channel.
const trackingChanReqBuffer = 16

func (t *trackingNewChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	ch, reqs, err := t.NewChannel.Accept()
	if err != nil {
		return ch, reqs, err
	}
	if t.onAccept != nil {
		t.onAccept(ch)
	}
	wrapped := make(chan *gossh.Request, trackingChanReqBuffer)
	go func() {
		defer close(wrapped)
		defer func() {
			if t.onClose != nil {
				t.onClose(ch)
			}
		}()
		ctxDone := t.ctx.Done()
		for r := range reqs {
			if t.notePeerActivity != nil {
				t.notePeerActivity()
			}
			select {
			case wrapped <- r:
			case <-ctxDone:
				// Handler stopped draining and the connection is
				// going away. Negatively reply to any want-reply
				// request we were holding, then drain upstream so
				// gossh's per-channel request goroutine doesn't
				// leak, replying false to any subsequent
				// want-reply requests as we go.
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
				for r2 := range reqs {
					if r2.WantReply {
						_ = r2.Reply(false, nil)
					}
				}
				return
			}
		}
	}()
	return ch, wrapped, nil
}

// NewChannelUnwrapper is implemented by NewChannel implementations that
// wrap another NewChannel for internal bookkeeping. Channel handlers
// that need access to the underlying gossh.NewChannel (e.g., to type-
// assert against a custom implementation) can call Unwrap to recover
// it. This is needed because the library wraps every incoming
// NewChannel to track per-channel keep-alive activity; the wrapper is
// otherwise transparent.
type NewChannelUnwrapper interface {
	Unwrap() gossh.NewChannel
}

// Unwrap returns the underlying gossh.NewChannel. See NewChannelUnwrapper.
func (t *trackingNewChannel) Unwrap() gossh.NewChannel {
	return t.NewChannel
}

// SubsystemHandler is a callback for handling SSH subsystem requests.
type SubsystemHandler func(s Session)

// DefaultSubsystemHandlers is the default set of subsystem handlers.
var DefaultSubsystemHandlers = map[string]SubsystemHandler{}

// RequestHandler is a callback for handling global SSH requests.
type RequestHandler func(ctx Context, srv *Server, req *gossh.Request) (ok bool, payload []byte)

// DefaultRequestHandlers is the default set of global request handlers.
var DefaultRequestHandlers = map[string]RequestHandler{
	keepAliveRequestType: KeepAliveRequestHandler,
}

// ChannelHandler is a callback for handling SSH channel requests.
type ChannelHandler func(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context)

// DefaultChannelHandlers is the default set of channel handlers.
var DefaultChannelHandlers = map[string]ChannelHandler{
	"session": DefaultSessionHandler,
}

// Server defines parameters for running an SSH server. The zero value for
// Server is a valid configuration. When both PasswordHandler and
// PublicKeyHandler are nil, no client authentication is performed.
type Server struct {
	Addr        string   // TCP address to listen on, ":22" if empty
	Handler     Handler  // handler to invoke, ssh.DefaultHandler if nil
	HostSigners []Signer // private keys for the host key, must have at least one
	Version     string   // server version to be sent before the initial handshake

	KeyboardInteractiveHandler    KeyboardInteractiveHandler    // keyboard-interactive authentication handler
	PasswordHandler               PasswordHandler               // password authentication handler
	PublicKeyHandler              PublicKeyHandler              // public key authentication handler
	PtyCallback                   PtyCallback                   // callback for allowing PTY sessions, allows all if nil
	X11ForwardingCallback         X11Callback                   // callback for allowing X11 display forwarding (x11-req), denies all if nil
	ConnCallback                  ConnCallback                  // optional callback for wrapping net.Conn before handling
	LocalPortForwardingCallback   LocalPortForwardingCallback   // callback for allowing local port forwarding, denies all if nil
	LocalUnixForwardingCallback   LocalUnixForwardingCallback   // callback for allowing local unix forwarding (direct-streamlocal@openssh.com), denies all if nil
	ReversePortForwardingCallback ReversePortForwardingCallback // callback for allowing reverse port forwarding, denies all if nil
	ReverseUnixForwardingCallback ReverseUnixForwardingCallback // callback for allowing reverse unix forwarding (streamlocal-forward@openssh.com), denies all if nil
	ServerConfigCallback          ServerConfigCallback          // callback for configuring detailed SSH options
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions

	// server calls Failed callback for connections that fail initial handshake, and Complete callback for those that
	// succeed, never both.
	ConnectionFailedCallback   ConnectionFailedCallback   // callback to report connection failures
	ConnectionCompleteCallback ConnectionCompleteCallback // callback to report connection completion
	ConnectionClosingCallback  ConnectionClosingCallback  // see ConnectionClosingCallback type doc

	IdleTimeout time.Duration // connection timeout when no activity, none if empty
	MaxTimeout  time.Duration // absolute connection timeout, none if empty

	// ChannelHandlers allow overriding the built-in session handlers or provide
	// extensions to the protocol, such as tcpip forwarding. By default only the
	// "session" handler is enabled.
	//
	// The gossh.NewChannel value passed to handlers may be wrapped by this
	// package for keep-alive bookkeeping (tracking open channels and noting
	// inbound activity). Handlers that need access to the unwrapped
	// underlying value can type-assert to NewChannelUnwrapper and call
	// Unwrap.
	ChannelHandlers map[string]ChannelHandler

	// RequestHandlers allow overriding the server-level request handlers or
	// provide extensions to the protocol, such as tcpip forwarding. By default
	// no handlers are enabled.
	RequestHandlers map[string]RequestHandler

	// SubsystemHandlers are handlers which are similar to the usual SSH command
	// handlers, but handle named subsystems.
	SubsystemHandlers map[string]SubsystemHandler

	ClientAliveInterval time.Duration
	ClientAliveCountMax int

	listenerWg sync.WaitGroup
	mu         sync.RWMutex
	listeners  map[net.Listener]struct{}
	conns      map[*gossh.ServerConn]struct{}
	connWg     sync.WaitGroup
	doneChan   chan struct{}
}

func (srv *Server) ensureHostSigner() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.HostSigners) == 0 {
		signer, err := generateSigner()
		if err != nil {
			return err
		}
		srv.HostSigners = append(srv.HostSigners, signer)
	}
	return nil
}

func (srv *Server) ensureHandlers() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.RequestHandlers == nil {
		srv.RequestHandlers = map[string]RequestHandler{}
		for k, v := range DefaultRequestHandlers {
			srv.RequestHandlers[k] = v
		}
	}
	if srv.ChannelHandlers == nil {
		srv.ChannelHandlers = map[string]ChannelHandler{}
		for k, v := range DefaultChannelHandlers {
			srv.ChannelHandlers[k] = v
		}
	}
	if srv.SubsystemHandlers == nil {
		srv.SubsystemHandlers = map[string]SubsystemHandler{}
		for k, v := range DefaultSubsystemHandlers {
			srv.SubsystemHandlers[k] = v
		}
	}
}

func (srv *Server) config(ctx Context) *gossh.ServerConfig {
	srv.mu.RLock()
	defer srv.mu.RUnlock()

	var config *gossh.ServerConfig
	if srv.ServerConfigCallback == nil {
		config = &gossh.ServerConfig{}
	} else {
		config = srv.ServerConfigCallback(ctx)
	}
	for _, signer := range srv.HostSigners {
		config.AddHostKey(signer)
	}
	if srv.PasswordHandler == nil && srv.PublicKeyHandler == nil &&
		srv.KeyboardInteractiveHandler == nil {
		config.NoClientAuth = true
	}
	if srv.Version != "" {
		config.ServerVersion = "SSH-2.0-" + srv.Version
	}
	if srv.PasswordHandler != nil {
		config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.PasswordHandler(ctx, string(password)); !ok {
				return ctx.Permissions().Permissions, fmt.Errorf("permission denied")
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.PublicKeyHandler != nil {
		config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.PublicKeyHandler(ctx, key); !ok {
				return ctx.Permissions().Permissions, fmt.Errorf("permission denied")
			}
			ctx.SetValue(ContextKeyPublicKey, key)
			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.KeyboardInteractiveHandler != nil {
		config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.KeyboardInteractiveHandler(ctx, challenger); !ok {
				return ctx.Permissions().Permissions, fmt.Errorf("permission denied")
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	return config
}

// Handle sets the Handler for the server.
func (srv *Server) Handle(fn Handler) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.Handler = fn
}

// Close immediately closes all active listeners and all active
// connections.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.closeDoneChanLocked()
	err := srv.closeListenersLocked()
	for c := range srv.conns {
		_ = c.Close()
		delete(srv.conns, c)
	}
	return err
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, and then waiting indefinitely for connections to close.
// If the provided context expires before the shutdown is complete,
// then the context's error is returned.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.mu.Lock()
	lnerr := srv.closeListenersLocked()
	srv.closeDoneChanLocked()
	srv.mu.Unlock()

	finished := make(chan struct{}, 1)
	go func() {
		srv.listenerWg.Wait()
		srv.connWg.Wait()
		finished <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finished:
		return lnerr
	}
}

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions.
//
// Serve always returns a non-nil error.
func (srv *Server) Serve(l net.Listener) error {
	if (srv.ClientAliveInterval != 0 && srv.ClientAliveCountMax == 0) ||
		(srv.ClientAliveInterval == 0 && srv.ClientAliveCountMax != 0) {
		return fmt.Errorf("ClientAliveInterval and ClientAliveCountMax must be set together")
	}

	srv.ensureHandlers()
	defer func() { _ = l.Close() }()
	if err := srv.ensureHostSigner(); err != nil {
		return err
	}
	if srv.Handler == nil {
		srv.Handler = DefaultHandler
	}
	var tempDelay time.Duration

	srv.trackListener(l, true)
	defer srv.trackListener(l, false)
	for {
		conn, e := l.Accept()
		if e != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := e.(net.Error); ok &&
				ne.Temporary() { //nolint:staticcheck // classic accept-loop backoff pattern
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if maxDelay := 1 * time.Second; tempDelay > maxDelay {
					tempDelay = maxDelay
				}
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		go srv.HandleConn(conn)
	}
}

// HandleConn serves an SSH connection on the given net.Conn.
func (srv *Server) HandleConn(newConn net.Conn) {
	ctx, cancel := newContext(srv)
	if srv.ConnCallback != nil {
		cbConn := srv.ConnCallback(ctx, newConn)
		if cbConn == nil {
			_ = newConn.Close()
			return
		}
		newConn = cbConn
	}
	conn := &serverConn{
		Conn:          newConn,
		idleTimeout:   srv.IdleTimeout,
		closeCanceler: cancel,
	}
	if srv.MaxTimeout > 0 {
		conn.maxDeadline = time.Now().Add(srv.MaxTimeout)
	}
	defer func() { _ = conn.Close() }()
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, srv.config(ctx))
	if err != nil {
		if srv.ConnectionFailedCallback != nil {
			srv.ConnectionFailedCallback(conn, err)
		}
		return
	}
	if srv.ConnectionCompleteCallback != nil {
		defer func() {
			srv.ConnectionCompleteCallback(sshConn, sshConn.Wait())
		}()
	}

	srv.trackConn(sshConn, true)
	defer srv.trackConn(sshConn, false)

	ctx.SetValue(ContextKeyConn, sshConn)
	applyConnMetadata(ctx, sshConn)
	// To prevent race conditions, we need to configure the keep-alive before goroutines kick off
	applyKeepAlive(ctx, srv.ClientAliveInterval, srv.ClientAliveCountMax)
	openChans := &openChannelSet{}
	ctx.SetValue(contextKeyOpenChannels, openChans)

	// Connection-level keep-alive: runs for the lifetime of the transport,
	// independent of whether any session is active. This is what detects a
	// dead transport between sessions (e.g., an idle ControlMaster whose
	// outer ssh has been -O exit'd but whose ProxyCommand chain hasn't
	// propagated EOF). On timeout we close sshConn so HandleConn's
	// `for ch := range chans` loop unblocks and the closing/complete
	// callbacks can fire.
	keepAliveDone := make(chan struct{})
	go srv.connectionKeepAlive(ctx, sshConn, keepAliveDone)
	defer close(keepAliveDone)

	// go gossh.DiscardRequests(reqs)
	go srv.handleRequests(ctx, reqs)
	for ch := range chans {
		handler := srv.ChannelHandlers[ch.ChannelType()]
		if handler == nil {
			handler = srv.ChannelHandlers["default"]
		}
		if handler == nil {
			_ = ch.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		tracked := &trackingNewChannel{
			NewChannel: ch,
			set:        openChans,
			onAccept:   openChans.add,
			onClose:    openChans.remove,
			notePeerActivity: func() {
				if ka := ctx.KeepAlive(); ka != nil {
					ka.notePeerActivity()
				}
			},
			ctx: ctx,
		}
		go handler(srv, sshConn, tracked, ctx)
	}

	// Fire the closing callback synchronously, before any deferred cleanup
	// runs, so downstream callers have a deterministic hook the moment the
	// channels stream ends. Deferred hooks that block on the transport
	// (e.g., waiting on the mux) may be delayed indefinitely on a stuck
	// transport; this path is not.
	if srv.ConnectionClosingCallback != nil {
		srv.ConnectionClosingCallback(ctx, sshConn)
	}
}

// connectionKeepAlive drives transport-level keep-alive pings for the life
// of sshConn. It mirrors OpenSSH's client_alive_check(): if at least one
// channel is open, the keepalive is sent as a SSH2_MSG_CHANNEL_REQUEST on
// that channel; otherwise it falls back to a SSH2_MSG_GLOBAL_REQUEST. After
// ClientAliveCountMax consecutive intervals with no successful reply,
// sshConn is closed so HandleConn unblocks. Stops when `done` closes
// (HandleConn returning).
func (srv *Server) connectionKeepAlive(
	ctx Context,
	sshConn *gossh.ServerConn,
	done <-chan struct{},
) {
	countMax := srv.ClientAliveCountMax
	if srv.ClientAliveInterval <= 0 || countMax <= 0 {
		return
	}

	// Reuse the SessionKeepAlive already stashed on ctx so request-handler
	// resets (KeepAliveRequestHandler) and metrics keep working.
	//
	// Do NOT Close() the SessionKeepAlive when this function returns: other
	// goroutines (Server.handleRequests, trackingNewChannel.Accept's
	// forwarder, and any in-flight probe goroutine spawned below) may still
	// be calling notePeerActivity / Reset after we return. The ticker is
	// no longer referenced once HandleConn returns and is GC'd.
	keepAlive := ctx.KeepAlive()

	openChans := ctx.Value(contextKeyOpenChannels).(*openChannelSet)

	inFlight := make(chan struct{}, 1)
	for {
		select {
		case <-done:
			return
		case <-keepAlive.Ticks():
			if keepAlive.TimeIsUp() {
				log.Printf(
					"ssh: connection keep-alive timeout after %d intervals; closing transport",
					countMax,
				)
				if err := sshConn.Close(); err != nil {
					log.Printf("ssh: failed to close stalled transport: %v", err)
				}
				return
			}
			select {
			case inFlight <- struct{}{}:
			default:
				continue
			}
			go func() {
				defer func() { <-inFlight }()
				keepAlive.ServerRequestedKeepAliveCallback()
				// Mirror OpenSSH client_alive_check(): prefer a channel
				// request on an open channel; fall back to a global
				// request if no channel is open or the channel send
				// fails (channel was closed mid-flight).
				//
				// No outer timeout is needed here: the inFlight semaphore
				// already prevents overlapping probes, TimeIsUp() at the
				// next tick enforces the deadline, and if SendRequest
				// hangs forever it will be unblocked when the TimeIsUp
				// branch closes sshConn.
				var err error
				ch := openChans.any()
				if ch != nil {
					_, err = ch.SendRequest(keepAliveRequestType, true, nil)
					if err != nil {
						openChans.remove(ch)
						ch = nil
					}
				}
				if ch == nil {
					_, _, err = sshConn.SendRequest(keepAliveRequestType, true, nil)
				}
				if err == nil {
					keepAlive.Reset()
				} else {
					log.Printf("ssh: keepalive request failed: %v", err)
				}
			}()
		}
	}
}

func (srv *Server) handleRequests(ctx Context, in <-chan *gossh.Request) {
	for req := range in {
		if ka := ctx.KeepAlive(); ka != nil {
			ka.notePeerActivity()
		}
		handler := srv.RequestHandlers[req.Type]
		if handler == nil {
			handler = srv.RequestHandlers["default"]
		}
		if handler == nil {
			_ = req.Reply(false, nil)
			continue
		}
		/*reqCtx, cancel := context.WithCancel(ctx)
		defer cancel() */
		ret, payload := handler(ctx, srv, req)
		_ = req.Reply(ret, payload)
	}
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle incoming connections. If srv.Addr is blank, ":22" is used.
// ListenAndServe always returns a non-nil error.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":22"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// AddHostKey adds a private key as a host key. If an existing host key exists
// with the same algorithm, it is overwritten. Each server config must have at
// least one host key.
func (srv *Server) AddHostKey(key Signer) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	// these are later added via AddHostKey on ServerConfig, which performs the
	// check for one of every algorithm.

	// This check is based on the AddHostKey method from the x/crypto/ssh
	// library. This allows us to only keep one active key for each type on a
	// server at once. So, if you're dynamically updating keys at runtime, this
	// list will not keep growing.
	for i, k := range srv.HostSigners {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			srv.HostSigners[i] = key
			return
		}
	}

	srv.HostSigners = append(srv.HostSigners, key)
}

// SetOption runs a functional option against the server.
func (srv *Server) SetOption(option Option) error {
	// NOTE: there is a potential race here for any option that doesn't call an
	// internal method. We can't actually lock here because if something calls
	// (as an example) AddHostKey, it will deadlock.

	// srv.mu.Lock()
	// defer srv.mu.Unlock()

	return option(srv)
}

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by srv.mu.
		close(ch)
	}
}

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cerr := ln.Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(srv.listeners, ln)
	}
	return err
}

func (srv *Server) trackListener(ln net.Listener, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listeners == nil {
		srv.listeners = make(map[net.Listener]struct{})
	}
	if add {
		// If the *Server is being reused after a previous
		// Close or Shutdown, reset its doneChan:
		if len(srv.listeners) == 0 && len(srv.conns) == 0 {
			srv.doneChan = nil
		}
		srv.listeners[ln] = struct{}{}
		srv.listenerWg.Add(1)
	} else {
		delete(srv.listeners, ln)
		srv.listenerWg.Done()
	}
}

func (srv *Server) trackConn(c *gossh.ServerConn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.conns == nil {
		srv.conns = make(map[*gossh.ServerConn]struct{})
	}
	if add {
		srv.conns[c] = struct{}{}
		srv.connWg.Add(1)
	} else {
		delete(srv.conns, c)
		srv.connWg.Done()
	}
}
