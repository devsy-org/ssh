package ssh

import (
	"bytes"
	"context"
	"io"
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

	closingFired := make(chan struct{})
	completeFired := make(chan struct{})
	var closingCtx atomic.Value // ssh.Context observed at callback time

	srv := &Server{
		Handler: func(s Session) {
			_, _ = io.WriteString(s, "hi")
		},
		ConnectionClosingCallback: func(ctx Context, _ *gossh.ServerConn) {
			closingCtx.Store(ctx)
			close(closingFired)
		},
		ConnectionCompleteCallback: func(_ *gossh.ServerConn, _ error) {
			close(completeFired)
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

	select {
	case <-closingFired:
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectionClosingCallback did not fire within 2s of client disconnect")
	}

	if got := closingCtx.Load(); got == nil {
		t.Fatal("ConnectionClosingCallback received nil Context")
	}

	// Complete callback should also fire after closing (Wait returns once
	// the underlying TCP closes); it should not race ahead of closing.
	select {
	case <-completeFired:
	case <-time.After(2 * time.Second):
		t.Fatal("ConnectionCompleteCallback did not fire")
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
