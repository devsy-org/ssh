package ssh

import (
	"crypto/subtle"
	"net"

	gossh "golang.org/x/crypto/ssh"
)

// Signal represents an SSH signal as defined in RFC 4254, Section 6.10.
type Signal string

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT Signal = "ABRT"
	SIGALRM Signal = "ALRM"
	SIGFPE  Signal = "FPE"
	SIGHUP  Signal = "HUP"
	SIGILL  Signal = "ILL"
	SIGINT  Signal = "INT"
	SIGKILL Signal = "KILL"
	SIGPIPE Signal = "PIPE"
	SIGQUIT Signal = "QUIT"
	SIGSEGV Signal = "SEGV"
	SIGTERM Signal = "TERM"
	SIGUSR1 Signal = "USR1"
	SIGUSR2 Signal = "USR2"
)

// DefaultHandler is the default Handler used by Serve.
var DefaultHandler Handler

// Option is a functional option handler for Server.
type Option func(*Server) error

// Handler is a callback for handling established SSH sessions.
type Handler func(Session)

// PublicKeyHandler is a callback for performing public key authentication.
type PublicKeyHandler func(ctx Context, key PublicKey) bool

// PasswordHandler is a callback for performing password authentication.
type PasswordHandler func(ctx Context, password string) bool

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive authentication.
type KeyboardInteractiveHandler func(ctx Context, challenger gossh.KeyboardInteractiveChallenge) bool

// PtyCallback is a hook for allowing PTY sessions.
type PtyCallback func(ctx Context, pty Pty) bool

// X11Callback is a hook for allowing X11 forwarding.
type X11Callback func(ctx Context, x11 X11) bool

// X11ForwardingCallback is an alias for backward compatibility.
type X11ForwardingCallback = X11Callback

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
type SessionRequestCallback func(sess Session, requestType string) bool

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
type ConnCallback func(ctx Context, conn net.Conn) net.Conn

// LocalPortForwardingCallback is a hook for allowing port forwarding.
type LocalPortForwardingCallback func(ctx Context, destinationHost string, destinationPort uint32) bool

// LocalUnixForwardingCallback is a hook for allowing unix forwarding.
// (direct-streamlocal@openssh.com).
type LocalUnixForwardingCallback func(ctx Context, socketPath string) bool

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding.
type ReversePortForwardingCallback func(ctx Context, bindHost string, bindPort uint32) bool

// ReverseUnixForwardingCallback is a hook for allowing reverse unix forwarding
// (streamlocal-forward@openssh.com).
type ReverseUnixForwardingCallback func(ctx Context, socketPath string) bool

// ServerConfigCallback is a hook for creating custom default server configs.
type ServerConfigCallback func(ctx Context) *gossh.ServerConfig

// ConnectionFailedCallback is a hook for reporting failed connections.
// Please note: the net.Conn is likely to be closed at this point.
type ConnectionFailedCallback func(conn net.Conn, err error)

// ConnectionCompleteCallback is a hook for reporting connections that
// complete. The included error is from the underlying SSH transport
// protocol mux (golang.org/x/crypto/ssh), and is non-nil, even for
// normal termination.
//
// Please note: the ServerConn is closed at this point.
type ConnectionCompleteCallback func(conn *gossh.ServerConn, err error)

// ConnectionClosingCallback is invoked synchronously the moment HandleConn
// observes the inbound channels stream close (i.e., the SSH transport is
// ending), BEFORE sshConn.Wait() is called and BEFORE any deferred cleanup
// runs. Use it for fast-path resource cleanup. Note: this fires when
// HandleConn observes the channels stream close. If the transport is
// permanently stuck and ClientAliveInterval is unset, neither this callback
// nor ConnectionCompleteCallback will fire — configure keep-alive to bound
// the wait. The Context is the same one threaded through auth and channel
// handlers, so per-connection state stashed via ctx.SetValue is reachable
// without an external sync.Map keyed by *gossh.ServerConn.
//
// Note: channel handler goroutines spawned by HandleConn may still be
// running and mutating per-connection state when this callback fires.
// The callback is intentionally synchronous and pre-defer; it does NOT
// imply that all per-connection work has finished. For "all work done"
// semantics, use ConnectionCompleteCallback (which runs after
// sshConn.Wait).
type ConnectionClosingCallback func(ctx Context, conn *gossh.ServerConn)

// Window represents the size of a PTY window.
//
// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
//
// Zero dimension parameters MUST be ignored. The character/row dimensions
// override the pixel dimensions (when nonzero). Pixel dimensions refer
// to the drawable area of the window.
type Window struct {
	// Width is the number of columns.
	Width int
	// Height is the number of rows.
	Height int
	// WidthPixels is the drawable width of the window, in pixels.
	WidthPixels int
	// HeightPixels is the drawable height of the window, in pixels.
	HeightPixels int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	// Term is the TERM environment variable value.
	Term string
	// Window is the Window sent as part of the pty-req.
	Window Window
	// Modes represent a mapping of Terminal Mode opcode to value as it was
	// requested by the client as part of the pty-req. These are outlined as
	// part of https://datatracker.ietf.org/doc/html/rfc4254#section-8.
	//
	// The opcodes are defined as constants in golang.org/x/crypto/ssh (VINTR,VQUIT,etc.).
	// Boolean opcodes have values 0 or 1.
	Modes gossh.TerminalModes
}

// X11 represents an X11 forwarding request and configuration.
type X11 struct {
	SingleConnection bool
	AuthProtocol     string
	AuthData         string
	ScreenNumber     int
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used.
func Serve(l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used.
func ListenAndServe(addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe()
}

// Handle registers the handler as the DefaultHandler.
func Handle(handler Handler) {
	DefaultHandler = handler
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk PublicKey) bool {
	// avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return (len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1)
}
