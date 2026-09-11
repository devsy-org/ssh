package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2.
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// DirectTCPIPHandler can be enabled by adding it to the server's
// ChannelHandlers under direct-tcpip.
func DirectTCPIPHandler(
	srv *Server,
	_ *gossh.ServerConn,
	newChan gossh.NewChannel,
	ctx Context,
) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil ||
		!srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	bicopy(ctx, ch, dconn)
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// ForwardedTCPHandler can be enabled by creating a ForwardedTCPHandler and
// adding the HandleSSHRequest callback to the server's RequestHandlers under
// tcpip-forward and cancel-tcpip-forward.
type ForwardedTCPHandler struct {
	forwards map[string]net.Listener
	sync.Mutex
}

// HandleSSHRequest handles tcpip-forward and cancel-tcpip-forward requests.
func (h *ForwardedTCPHandler) HandleSSHRequest(
	ctx Context,
	srv *Server,
	req *gossh.Request,
) (bool, []byte) {
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]net.Listener)
	}
	h.Unlock()
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		if srv.ReversePortForwardingCallback == nil ||
			!srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// TODO: log listen failure
			return false, []byte{}
		}

		// If the bind port was port 0, we need to use the actual port in the
		// listener map.
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)
		if reqPayload.BindPort == 0 {
			addr = net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(destPort))
		}
		h.Lock()
		h.forwards[addr] = ln
		h.Unlock()
		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[addr]
			h.Unlock()
			if ok {
				_ = ln.Close()
			}
		}()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					// TODO: log accept failure
					break
				}
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr: reqPayload.BindAddr,
					DestPort: uint32( //nolint:gosec // port range validated by net.Listen
						destPort,
					),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort), //nolint:gosec // port from net.SplitHostPort
				})
				go func() {
					ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
					if err != nil {
						// TODO: log failure to open channel
						log.Println(err)
						_ = c.Close()
						return
					}
					go gossh.DiscardRequests(reqs)
					bicopy(ctx, ch, c)
				}()
			}
			h.Lock()
			delete(h.forwards, addr)
			h.Unlock()
		}()
		return true, gossh.Marshal(
			&remoteForwardSuccess{
				uint32(destPort), //nolint:gosec // port range validated by net.Listen
			},
		)

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			// TODO: log parse failure
			return false, []byte{}
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		h.Lock()
		ln, ok := h.forwards[addr]
		h.Unlock()
		if ok {
			_ = ln.Close()
		}
		return true, nil
	default:
		return false, nil
	}
}

// bicopy copies all of the data between the two connections. When one
// direction reaches EOF, it half-closes the destination's write side and keeps
// the reverse direction running. Both connections are fully closed after both
// directions finish, or when the context is canceled or a copy fails.
func bicopy(ctx context.Context, c1, c2 io.ReadWriteCloser) {
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	results := make(chan copyResult, 2)
	go copyAndHalfClose(c1, c2, "c2->c1", results)
	go copyAndHalfClose(c2, c1, "c1->c2", results)

	completed := 0
	aborted := false
	for completed < 2 {
		select {
		case <-ctx.Done():
			if !aborted {
				aborted = true
				_ = c1.Close()
				_ = c2.Close()
			}
		case result := <-results:
			completed++
			if result.err != nil && !aborted {
				aborted = true
				_ = c1.Close()
				_ = c2.Close()
			}
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

type copyResult struct {
	direction string
	err       error
}

func copyAndHalfClose(
	dst io.WriteCloser,
	src io.Reader,
	direction string,
	results chan<- copyResult,
) {
	_, err := io.Copy(dst, src)
	if err == nil {
		cw, ok := dst.(closeWriter)
		if !ok {
			err = fmt.Errorf("%s: destination does not support CloseWrite", direction)
		} else {
			err = cw.CloseWrite()
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
	}

	results <- copyResult{direction: direction, err: err}
}
