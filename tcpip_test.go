package ssh

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleTCPSocketServer() net.Listener {
	l := newLocalTCPListener()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(sampleServerResponse)
		_ = conn.Close()
	}()

	return l
}

func newTestSessionWithForwarding(
	t *testing.T,
	forwardingEnabled bool,
) (net.Listener, *gossh.Client, func()) {
	l := sampleTCPSocketServer()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(_ Session) {},
		LocalPortForwardingCallback: func(_ Context, destinationHost string, destinationPort uint32) bool {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		_ = l.Close()
	}
}

func TestLocalPortForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}
}

func TestBicopyPreservesHalfClose(t *testing.T) {
	t.Parallel()

	c1, c1Peer := newTCPConnPair(t)
	c2, c2Peer := newTCPConnPair(t)
	defer func() {
		_ = c1Peer.Close()
		_ = c2Peer.Close()
	}()

	done := make(chan struct{})
	go func() {
		bicopy(context.Background(), c1, c2)
		close(done)
	}()

	if _, err := c1Peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c1Peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := c2Peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(c2Peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(request) != "request" {
		t.Fatalf("request = %q; want %q", request, "request")
	}

	if _, err := c2Peer.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if err := c2Peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if err := c1Peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(c1Peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q; want %q", response, "response")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bicopy did not finish after both directions reached EOF")
	}
}

func newTCPConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()

	accepted := make(chan *net.TCPConn)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	select {
	case conn := <-accepted:
		return conn, peer
	case err := <-acceptErr:
		_ = peer.Close()
		t.Fatal(err)
		return nil, nil
	}
}

func TestLocalPortForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "port forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestReverseTCPForwardingWorks(t *testing.T) {
	t.Parallel()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(_ Session) {},
		ReversePortForwardingCallback: func(_ Context, bindHost string, bindPort uint32) bool {
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return true
		},
	}, nil)
	defer cleanup()

	l, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on a random TCP port over SSH: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write(sampleServerResponse)
		_ = conn.Close()
	}()

	// Dial the listener that should've been created by the server.
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}

	// Close the listener and make sure that the port is no longer in use.
	err = l.Close()
	if err != nil {
		t.Fatalf("failed to close remote listener: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var d net.Dialer
	_, err = d.DialContext(ctx, "tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("expected error connecting to %v but it succeeded", l.Addr().String())
	}
}

func TestReverseTCPForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	var called int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(_ Session) {},
		ReversePortForwardingCallback: func(_ Context, bindHost string, bindPort uint32) bool {
			atomic.AddInt64(&called, 1)
			if bindHost != "127.0.0.1" {
				panic("unexpected bindHost: " + bindHost)
			}
			if bindPort != 0 {
				panic("unexpected bindPort: " + strconv.Itoa(int(bindPort)))
			}
			return false
		},
	}, nil)
	defer cleanup()

	_, err := client.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		t.Fatalf("Expected error listening on random port but it succeeded")
	}

	if atomic.LoadInt64(&called) != 1 {
		t.Fatalf("Expected callback to be called once but it was called %d times", called)
	}
}
