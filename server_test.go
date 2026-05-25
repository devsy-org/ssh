package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func TestAddHostKey(t *testing.T) {
	s := Server{}
	signer, err := generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly added")
	}
	signer, err = generateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s.AddHostKey(signer)
	if len(s.HostSigners) != 1 {
		t.Fatal("Key was not properly replaced")
	}
}

func TestServerShutdown(t *testing.T) {
	l := newLocalTCPListener()
	testBytes := []byte("Hello world\n")
	s := &Server{
		Handler: func(s Session) {
			_, _ = s.Write(testBytes)
			time.Sleep(50 * time.Millisecond)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
		}
	}()
	sessDone := make(chan struct{})
	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(sessDone)
		var stdout bytes.Buffer
		sess.Stdout = &stdout
		if err := sess.Run(""); err != nil {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
			return
		}
		if !bytes.Equal(stdout.Bytes(), testBytes) {
			t.Errorf("expected = %s; got %s", testBytes, stdout.Bytes())
		}
	}()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		err := s.Shutdown(context.Background())
		if err != nil {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
		}
	}()

	timeout := time.After(2 * time.Second)
	select {
	case <-timeout:
		t.Fatal("timeout")
		return
	case <-srvDone:
		// TODO: add timeout for sessDone
		<-sessDone
		return
	}
}

// TestConnectionClosingCallback verifies the closing callback fires
// synchronously when HandleConn observes the channels stream close, even
// when the client disconnects abruptly. It must fire before
// ConnectionCompleteCallback (which blocks on sshConn.Wait()).
func TestConnectionClosingCallback(t *testing.T) {
	t.Parallel()

	// Use a single ordered channel so a regression that swapped the order of
	// the two callbacks would be caught. Reading from independent channels
	// with separate timeouts would not detect such a swap.
	events := make(chan string, 2)
	var closingCtx atomic.Value // ssh.Context observed at callback time

	srv := &Server{
		Handler: func(s Session) {
			_, _ = io.WriteString(s, "hi")
		},
		ConnectionClosingCallback: func(ctx Context, _ *gossh.ServerConn) {
			closingCtx.Store(ctx)
			events <- "closing"
		},
		ConnectionCompleteCallback: func(_ *gossh.ServerConn, _ error) {
			events <- "complete"
		},
	}

	l := newLocalTCPListener()
	go func() { _ = srv.serveOnce(l) }()

	sess, client, _ := newClientSession(t, l.Addr().String(), nil)
	if err := sess.Run(""); err != nil && err != io.EOF {
		t.Fatalf("session run: %v", err)
	}
	_ = sess.Close()
	_ = client.Close()

	readEvent := func() string {
		select {
		case ev := <-events:
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for callback event")
			return ""
		}
	}

	if first := readEvent(); first != "closing" {
		t.Fatalf("expected first event to be \"closing\", got %q", first)
	}
	if second := readEvent(); second != "complete" {
		t.Fatalf("expected second event to be \"complete\", got %q", second)
	}

	if got := closingCtx.Load(); got == nil {
		t.Fatal("ConnectionClosingCallback received nil Context")
	}
}

// TestConnectionKeepAliveClosesStalledConn is the regression test for the
// connection-level keep-alive: when a client stops responding to keepalive
// global requests (e.g., idle ControlMaster whose peer is wedged) and no
// session is open, the server's connectionKeepAlive goroutine must close
// sshConn after roughly ClientAliveInterval * ClientAliveCountMax, which
// unblocks HandleConn's `for ch := range chans` loop and fires
// ConnectionClosingCallback. Before the fix, the keep-alive was only driven
// from within an active session, so an idle-but-stuck transport would
// linger forever.
//
// We dial with a raw gossh.NewClientConn and intentionally do NOT reply to
// the incoming requests channel, simulating a stuck peer. We do not open a
// session — the bug is specifically about the no-session case.
func TestConnectionKeepAliveClosesStalledConn(t *testing.T) {
	t.Parallel()

	closingFired := make(chan struct{})

	srv := &Server{
		Handler:             func(_ Session) {},
		ClientAliveInterval: 100 * time.Millisecond,
		ClientAliveCountMax: 2,
		ConnectionClosingCallback: func(_ Context, _ *gossh.ServerConn) {
			close(closingFired)
		},
	}

	l := newLocalTCPListener()
	defer func() { _ = l.Close() }()
	go func() { _ = srv.serveOnce(l) }()

	cfg := &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test code
	}
	netConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sshConn, chans, reqs, err := gossh.NewClientConn(netConn, l.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	defer func() { _ = sshConn.Close() }()

	// Drain both streams WITHOUT replying. By not calling req.Reply on
	// incoming global requests (including keepalive@openssh.com), we
	// simulate a stuck peer. The server's SendRequest with wantReply=true
	// will not see a response and connectionKeepAlive will eventually
	// close sshConn after ClientAliveCountMax intervals.
	go func() {
		for range chans { //nolint:revive // intentional drain
		}
	}()
	go func() {
		for req := range reqs {
			_ = req // intentionally never reply
		}
	}()

	// 100ms * 2 = 200ms expected; allow generous slack for CI scheduling
	// and any per-SendRequest timeout the other agent may layer on.
	select {
	case <-closingFired:
	case <-time.After(5 * time.Second):
		t.Fatal("ConnectionClosingCallback did not fire; " +
			"stalled client was not torn down by connection-level keep-alive")
	}
}

// TestConnectionKeepAliveUsesChannelRequestWhenSessionOpen verifies that the
// server's connection-level keepalive mirrors OpenSSH's client_alive_check():
// while at least one channel is open it sends keepalive@openssh.com as a
// channel request on that channel; after the channel closes it falls back
// to a global request.
func TestConnectionKeepAliveUsesChannelRequestWhenSessionOpen(t *testing.T) {
	t.Parallel()

	srv := &Server{
		Handler: func(s Session) {
			<-s.Context().Done()
		},
		ClientAliveInterval: 100 * time.Millisecond,
		ClientAliveCountMax: 100, // generous so the conn doesn't get torn down mid-test
	}

	l := newLocalTCPListener()
	defer func() { _ = l.Close() }()
	go func() { _ = srv.serveOnce(l) }()

	cfg := &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test code
	}
	netConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sshConn, chans, globalReqs, err := gossh.NewClientConn(netConn, l.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	defer func() { _ = sshConn.Close() }()
	go func() {
		for range chans { //nolint:revive // intentional drain
		}
	}()

	var globalCount, channelCount atomic.Int64
	go func() {
		for req := range globalReqs {
			if req.Type == "keepalive@openssh.com" {
				globalCount.Add(1)
			}
			_ = req.Reply(true, nil)
		}
	}()

	ch, chReqs, err := sshConn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("OpenChannel: %v", err)
	}
	chDone := make(chan struct{})
	go func() {
		defer close(chDone)
		for req := range chReqs {
			if req.Type == "keepalive@openssh.com" {
				channelCount.Add(1)
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()

	// Observe ~10 intervals with the channel open.
	time.Sleep(1 * time.Second)
	if got := channelCount.Load(); got < 1 {
		t.Fatalf("expected >=1 channel-typed keepalive while channel open, got %d", got)
	}
	if got := globalCount.Load(); got != 0 {
		t.Fatalf("expected 0 global-typed keepalives while channel open, got %d", got)
	}

	// Close the channel and observe the fallback to global requests.
	_ = ch.Close()
	<-chDone
	before := globalCount.Load()
	time.Sleep(1 * time.Second)
	if got := globalCount.Load() - before; got < 1 {
		t.Fatalf("expected >=1 global-typed keepalive after channel close, got %d", got)
	}
}

// TestConnectionKeepAlivePrunesClosedChannels verifies that the
// per-channel close hook prunes channels from the openChannelSet as
// soon as the client closes them, BEFORE the next keepalive probe
// fires. This is a regression test for the case where openChans.any()
// returned a dead channel because per-channel removal only happened on
// SendRequest failure (i.e., one probe was wasted on a dead channel
// before the prune-on-failure path kicked in).
//
// Strategy: use a long ClientAliveInterval (3s) so we can observe the
// state of openChans in the window between channel close and the first
// post-close probe. We capture the openChannelSet from inside the
// session handler so the test can inspect it without exporting helpers.
func TestConnectionKeepAlivePrunesClosedChannels(t *testing.T) {
	t.Parallel()

	openChansCh := make(chan *openChannelSet, 1)
	srv := &Server{
		Handler: func(s Session) {
			ctx := s.Context()
			if oc, ok := ctx.Value(ContextKeyOpenChannels).(*openChannelSet); ok {
				select {
				case openChansCh <- oc:
				default:
				}
			}
			<-ctx.Done()
		},
		ClientAliveInterval: 3 * time.Second,
		ClientAliveCountMax: 100, // generous so the conn isn't torn down mid-test
	}

	l := newLocalTCPListener()
	defer func() { _ = l.Close() }()
	go func() { _ = srv.serveOnce(l) }()

	cfg := &gossh.ClientConfig{
		User:            "testuser",
		Auth:            []gossh.AuthMethod{gossh.Password("testpass")},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(), //nolint:gosec // test code
	}
	netConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	sshConn, chans, globalReqs, err := gossh.NewClientConn(netConn, l.Addr().String(), cfg)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	defer func() { _ = sshConn.Close() }()
	go func() {
		for range chans { //nolint:revive // intentional drain
		}
	}()

	var globalCount atomic.Int64
	go func() {
		for req := range globalReqs {
			if req.Type == "keepalive@openssh.com" {
				globalCount.Add(1)
			}
			_ = req.Reply(true, nil)
		}
	}()

	// Open three sessions so that the server handler runs and registers
	// channels in openChans. Use a "shell" request so DefaultSessionHandler
	// considers the session "handled" and our top-level Handler runs.
	var chReqWg [3]chan struct{}
	channels := make([]gossh.Channel, 0, 3)
	for i := 0; i < 3; i++ {
		ch, chReqs, err := sshConn.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("OpenChannel[%d]: %v", i, err)
		}
		done := make(chan struct{})
		chReqWg[i] = done
		go func() {
			defer close(done)
			for req := range chReqs {
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			}
		}()
		// Send a shell request to trigger the user Handler so it can
		// publish openChans into openChansCh.
		if _, err := ch.SendRequest("shell", true, nil); err != nil {
			t.Fatalf("shell request[%d]: %v", i, err)
		}
		channels = append(channels, ch)
	}

	// Grab the openChannelSet from the first session that ran.
	var openChans *openChannelSet
	select {
	case openChans = <-openChansCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("never received openChannelSet from handler")
	}

	// Sanity: all three channels are registered.
	openChans.mu.Lock()
	regBefore := len(openChans.chans)
	openChans.mu.Unlock()
	if regBefore != 3 {
		t.Fatalf("expected 3 channels registered before close, got %d", regBefore)
	}

	// Close all channels.
	for _, ch := range channels {
		_ = ch.Close()
	}
	for i := 0; i < 3; i++ {
		<-chReqWg[i]
	}

	// Poll for the close hook to drain. ClientAliveInterval is 3s, so we
	// have ample time to observe the prune BEFORE the next probe fires.
	// If the close hook works, len(openChans.chans) drops to 0 quickly
	// (just goroutine scheduling). If the hook is broken, it stays at 3
	// until the next keepalive tick fires and SendRequest fails.
	//
	// We use a 500ms poll deadline — well above goroutine-scheduling
	// jitter but well below the 3s tick interval. This guarantees the
	// assertion is unambiguous: it passes ONLY if the close hook ran,
	// not because a keepalive tick happened to fire and the
	// prune-on-failure path cleared the set.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		openChans.mu.Lock()
		n := len(openChans.chans)
		openChans.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	openChans.mu.Lock()
	regAfter := len(openChans.chans)
	openChans.mu.Unlock()
	// Invariant: no keepalive tick should have fired during the 500ms
	// window (interval is 3s). If one did, the test result is
	// ambiguous — the prune may have happened via the
	// SendRequest-failure path instead of the close hook.
	if globalCount.Load() != 0 {
		t.Fatalf(
			"keepalive tick fired before assertion window (globalCount=%d); test invalid",
			globalCount.Load(),
		)
	}
	if regAfter != 0 {
		t.Fatalf(
			"openChannelSet still has %d entries 500ms after close; close hook did not run",
			regAfter,
		)
	}

	// And verify that the next keepalive probe (which fires ~3s after the
	// last reset) goes out as a global request — confirming behavior
	// end-to-end. Wait 4s to leave room for at least one tick after the
	// 3s interval.
	before := globalCount.Load()
	time.Sleep(4 * time.Second)
	if got := globalCount.Load() - before; got < 1 {
		t.Fatalf("expected >=1 global-typed keepalive after channels closed, got %d", got)
	}
}

func TestServerClose(t *testing.T) {
	l := newLocalTCPListener()
	s := &Server{
		Handler: func(_ Session) {
			time.Sleep(5 * time.Second)
		},
	}
	go func() {
		err := s.Serve(l)
		if err != nil && err != ErrServerClosed {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
		}
	}()

	clientDoneChan := make(chan struct{})
	closeDoneChan := make(chan struct{})

	sess, _, cleanup := newClientSession(t, l.Addr().String(), nil)
	go func() {
		defer cleanup()
		defer close(clientDoneChan)
		<-closeDoneChan
		if err := sess.Run(""); err != nil && err != io.EOF {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
		}
	}()

	go func() {
		err := s.Close()
		if err != nil {
			t.Error(err) //nolint:staticcheck // best-effort from goroutine
		}
		close(closeDoneChan)
	}()

	timeout := time.After(100 * time.Millisecond)
	select {
	case <-timeout:
		t.Error("timeout")
		return
	case <-s.getDoneChan():
		<-clientDoneChan
		return
	}
}
