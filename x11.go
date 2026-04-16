//go:build !windows

package ssh

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	gossh "golang.org/x/crypto/ssh"
)

// X11 forwarding constants.
const (
	x11ChannelType = "x11"

	X11DisplayHost     = "localhost"
	X11DisplayBasePort = 6000
	X11DisplayOffset   = 10
)

type x11ChannelData struct {
	OriginAddr string
	OriginPort uint32
}

// XAuthority represents an X11 authentication entry.
type XAuthority struct {
	Family    uint16
	AddrLen   uint16
	Addr      string
	NumberLen uint16
	Number    string
	NameLen   uint16
	Name      string
	DataLen   uint16
	Data      string
}

// isLittleEndian returns whether the host architecture uses little-endian.
func isLittleEndian() bool {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i) //nolint:gosec // required for endianness detection
	pb := (*byte)(u)
	b := *pb
	return b == 0x04
}

// prepareXAuthority returns the content of an .Xauthority file that can be
// used to connect to the proxied X11 display, using the fake authentication
// data created by the SSH client.
func prepareXAuthority(request X11, seat int) ([]byte, error) {
	data, err := hex.DecodeString(request.AuthData)
	if err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	family := uint16(syscall.AF_LOCAL)
	number := strconv.Itoa(seat)

	addrLen := uint16(len(hostname))             //nolint:gosec // hostname length fits uint16
	numberLen := uint16(len(number))             //nolint:gosec // seat number string fits uint16
	nameLen := uint16(len(request.AuthProtocol)) //nolint:gosec // protocol name fits uint16
	dataLen := uint16(len(data))                 //nolint:gosec // auth data length fits uint16

	buf := make([]byte, addrLen+numberLen+nameLen+dataLen+10)
	pos := uint16(0)

	if isLittleEndian() {
		binary.LittleEndian.PutUint16(buf[pos:], family)
	} else {
		binary.BigEndian.PutUint16(buf[pos:], family)
	}
	pos += 2

	binary.BigEndian.PutUint16(buf[pos:], addrLen)
	pos += 2
	copy(buf[pos:], []byte(hostname))
	pos += addrLen

	binary.BigEndian.PutUint16(buf[pos:], numberLen)
	pos += 2
	copy(buf[pos:], []byte(number))
	pos += numberLen

	binary.BigEndian.PutUint16(buf[pos:], nameLen)
	pos += 2
	copy(buf[pos:], []byte(request.AuthProtocol))
	pos += nameLen

	binary.BigEndian.PutUint16(buf[pos:], dataLen)
	pos += 2
	copy(buf[pos:], data)
	return buf, nil
}

// NewX11Forwarder sets up a temporary TCP socket that can be communicated
// to the session environment and used for forwarding X11 traffic.
// It also sets up an Xauthority file with appropriate authentication data.
func NewX11Forwarder(request X11) (net.Listener, *os.File, error) {
	var err error

	xauthFile, err := os.CreateTemp("", ".Xauthority")
	if err != nil {
		return nil, nil, err
	}

	// Try to find an available port to proxy X11 connections.
	// X11DisplayOffset is used to limit the risk of a conflict with
	// the host's X11 seats.
	for i := 0; i < 50; i++ {
		port := int(X11DisplayBasePort + X11DisplayOffset + i)
		addr := net.JoinHostPort(X11DisplayHost, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			buf, err := prepareXAuthority(request, X11DisplayOffset+i)
			if err != nil {
				_ = ln.Close()
				_ = os.Remove(xauthFile.Name())
				return nil, nil, err
			}

			err = os.WriteFile(xauthFile.Name(), buf, 0o600)
			if err != nil {
				_ = ln.Close()
				_ = os.Remove(xauthFile.Name())
				return nil, nil, err
			}

			return ln, xauthFile, nil
		}
		log.Println(err)
	}

	_ = os.Remove(xauthFile.Name())
	return nil, nil, err
}

// ForwardX11Connections takes X11 connections from a listener and proxies them
// through the SSH tunnel to the client's DISPLAY.
func ForwardX11Connections(l net.Listener, xauth *os.File, s Session) {
	defer func() { _ = os.Remove(xauth.Name()) }()
	sshConn := s.Context().Value(ContextKeyConn).(gossh.Conn)
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer func() { _ = conn.Close() }()
			originAddr, originPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
			originPort, _ := strconv.Atoi(originPortStr)
			payload := gossh.Marshal(&x11ChannelData{
				OriginAddr: originAddr,
				OriginPort: uint32(originPort), //nolint:gosec // port from net.SplitHostPort
			})
			channel, reqs, err := sshConn.OpenChannel(x11ChannelType, payload)
			if err != nil {
				return
			}
			defer func() { _ = channel.Close() }()
			go gossh.DiscardRequests(reqs)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				_, _ = io.Copy(conn, channel)
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.CloseWrite()
				}
				wg.Done()
			}()
			go func() {
				_, _ = io.Copy(channel, conn)
				_ = channel.CloseWrite()
				wg.Done()
			}()
			wg.Wait()
		}(conn)
	}
}
