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
