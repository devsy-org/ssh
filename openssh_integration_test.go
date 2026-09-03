//go:build openssh_integration

package ssh

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func TestOpenSSHDynamicForwardingSurvivesKeepAliveDeadline(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("OpenSSH client not available")
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go serveEcho(echoLn)

	sshLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		Handler:              func(Session) {},
		ClientAliveInterval:  100 * time.Millisecond,
		ClientAliveCountMax:  3,
		ChannelHandlers:      map[string]ChannelHandler{"direct-tcpip": DirectTCPIPHandler},
		LocalPortForwardingCallback: func(Context, string, uint32) bool { return true },
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(sshLn) }()
	defer func() {
		_ = srv.Close()
		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
			t.Error("SSH server did not stop")
		}
	}()

	socksPort := reserveTCPPort(t)
	_, sshPortText, err := net.SplitHostPort(sshLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh",
		"-F", "/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "PreferredAuthentications=none",
		"-o", "PubkeyAuthentication=no",
		"-o", "PasswordAuthentication=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ExitOnForwardFailure=yes",
		"-N",
		"-D", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
		"-p", sshPortText,
		"test@127.0.0.1",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()

	if err := waitForTCP(net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 5*time.Second); err != nil {
		b, _ := io.ReadAll(stderr)
		t.Fatalf("OpenSSH SOCKS listener did not start: %v: %s", err, b)
	}

	// The server timeout window is 300ms. OpenSSH normally responds to the
	// unsupported keepalive@openssh.com request with a negative SSH reply.
	// Remaining connected for more than three timeout windows protects the
	// v1.2.7 regression where negative replies were incorrectly treated as
	// missed keepalives.
	time.Sleep(1 * time.Second)
	select {
	case err := <-waitDone:
		b, _ := io.ReadAll(stderr)
		t.Fatalf("OpenSSH exited after keepalive deadline: %v: %s", err, b)
	default:
	}

	for i := 0; i < 10; i++ {
		payload := fmt.Sprintf("forward-%d", i)
		got, err := socksRoundTrip(
			net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
			echoLn.Addr().String(),
			payload,
		)
		if err != nil {
			t.Fatalf("forward %d: %v", i, err)
		}
		if got != payload {
			t.Fatalf("forward %d: got %q, want %q", i, got, payload)
		}
	}

	// Exercise another idle period after channel churn, then prove the parent
	// SSH connection can still create a fresh direct-tcpip channel.
	time.Sleep(1 * time.Second)
	if got, err := socksRoundTrip(
		net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)),
		echoLn.Addr().String(),
		"after-idle",
	); err != nil || got != "after-idle" {
		t.Fatalf("forward after idle: got %q err=%v", got, err)
	}

	cancel()
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("OpenSSH process did not exit after cancellation")
	}
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForTCP(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

func serveEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func socksRoundTrip(socksAddr, targetAddr, payload string) (string, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	r := bufio.NewReader(conn)
	method := make([]byte, 2)
	if _, err := io.ReadFull(r, method); err != nil {
		return "", err
	}
	if method[0] != 0x05 || method[1] != 0x00 {
		return "", fmt.Errorf("unexpected SOCKS method response %v", method)
	}

	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return "", fmt.Errorf("target is not IPv4: %s", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", err
	}
	request := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(request); err != nil {
		return "", err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", err
	}
	if header[1] != 0x00 {
		return "", fmt.Errorf("SOCKS connect failed with status %d", header[1])
	}
	var addrLen int
	switch header[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		addrLen = int(b)
	default:
		return "", fmt.Errorf("unknown SOCKS address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, r, int64(addrLen+2)); err != nil {
		return "", err
	}

	if _, err := io.WriteString(conn, payload); err != nil {
		return "", err
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
