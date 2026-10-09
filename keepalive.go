package ssh

import (
	"sync"
	"time"
)

// SessionKeepAlive tracks the keep-alive state for an SSH connection.
type SessionKeepAlive struct {
	clientAliveInterval time.Duration
	clientAliveCountMax int

	ticker       *time.Ticker
	tickerCh     <-chan time.Time
	lastReceived time.Time

	metrics KeepAliveMetrics

	m      sync.Mutex
	closed bool
}

// NewSessionKeepAlive creates a new SessionKeepAlive.
func NewSessionKeepAlive(
	clientAliveInterval time.Duration,
	clientAliveCountMax int,
) *SessionKeepAlive {
	var t *time.Ticker
	var tickerCh <-chan time.Time
	if clientAliveInterval > 0 {
		t = time.NewTicker(clientAliveInterval)
		tickerCh = t.C
	}

	return &SessionKeepAlive{
		clientAliveInterval: clientAliveInterval,
		clientAliveCountMax: clientAliveCountMax,
		ticker:              t,
		tickerCh:            tickerCh,
		lastReceived:        time.Now(),
	}
}

// RequestHandlerCallback is called when a client-initiated keep-alive is received.
func (ska *SessionKeepAlive) RequestHandlerCallback() {
	ska.m.Lock()
	ska.metrics.RequestHandlerCalled++
	ska.m.Unlock()

	ska.Reset()
}

// ServerRequestedKeepAliveCallback is called when the server sends a keep-alive.
func (ska *SessionKeepAlive) ServerRequestedKeepAliveCallback() {
	ska.m.Lock()
	defer ska.m.Unlock()

	ska.metrics.ServerRequestedKeepAlive++
}

// Reset resets the keep-alive timer after a reply to a server-requested
// keepalive is received. Both positive and negative SSH replies prove peer
// liveness; callers should invoke Reset whenever the request completed without
// a transport error.
func (ska *SessionKeepAlive) Reset() {
	ska.m.Lock()
	defer ska.m.Unlock()

	ska.metrics.KeepAliveReplyReceived++

	if ska.ticker != nil && !ska.closed {
		ska.lastReceived = time.Now()
		ska.ticker.Reset(ska.clientAliveInterval)
	}
}

// notePeerActivity records inbound request activity that this package can
// directly observe, such as global requests and per-channel requests. Ordinary
// SSH channel payload is consumed inside golang.org/x/crypto/ssh and is not
// visible here. Transport liveness does not depend on observing all payload
// traffic because server keepalive replies independently refresh the deadline.
func (ska *SessionKeepAlive) notePeerActivity() {
	ska.m.Lock()
	defer ska.m.Unlock()
	if ska.ticker != nil && !ska.closed {
		ska.lastReceived = time.Now()
		ska.ticker.Reset(ska.clientAliveInterval)
	}
}

// Ticks returns the channel that fires on each keep-alive interval.
func (ska *SessionKeepAlive) Ticks() <-chan time.Time {
	return ska.tickerCh
}

// TimeIsUp returns true if the keep-alive deadline has passed.
func (ska *SessionKeepAlive) TimeIsUp() bool {
	ska.m.Lock()
	defer ska.m.Unlock()

	return ska.lastReceived.Add(time.Duration(ska.clientAliveCountMax) * ska.clientAliveInterval).
		Before(time.Now())
}

// Close stops the keep-alive ticker.
func (ska *SessionKeepAlive) Close() {
	ska.m.Lock()
	defer ska.m.Unlock()

	if ska.ticker != nil {
		ska.ticker.Stop()
	}
	ska.closed = true
}

// Metrics returns the current keep-alive metrics.
func (ska *SessionKeepAlive) Metrics() KeepAliveMetrics {
	ska.m.Lock()
	defer ska.m.Unlock()

	return ska.metrics
}

// KeepAliveMetrics tracks keep-alive statistics.
type KeepAliveMetrics struct {
	RequestHandlerCalled     int
	KeepAliveReplyReceived   int
	ServerRequestedKeepAlive int
}
