package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"

	"golang.org/x/crypto/ssh"
)

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func parsePtyRequest(payload []byte) (pty Pty, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
	term, rem, ok := parseString(payload)
	if !ok {
		return
	}
	win, rem, ok := parseWindow(rem)
	if !ok {
		return
	}
	modes, ok := parseTerminalModes(rem)
	if !ok {
		return
	}
	pty = Pty{
		Term:   term,
		Window: win,
		Modes:  modes,
	}
	return
}

func parseX11Request(s []byte) (x11 X11, ok bool) {
	single, s, ok := parseBool(s)
	if !ok {
		return
	}
	protocol, s, ok := parseString(s)
	if !ok {
		return
	}
	data, s, ok := parseString(s)
	if !ok {
		return
	}
	screen, _, ok := parseUint32(s)
	if !ok {
		return
	}
	x11 = X11{
		SingleConnection: single,
		AuthProtocol:     protocol,
		AuthData:         data,
		ScreenNumber:     int(screen),
	}
	return
}

func parseTerminalModes(in []byte) (modes ssh.TerminalModes, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-8
	_, rem, ok := parseUint32(in)
	if !ok {
		return
	}
	const ttyOpEnd = 0
	for len(rem) > 0 {
		if modes == nil {
			modes = make(ssh.TerminalModes)
		}
		code := uint8(rem[0])
		rem = rem[1:]
		if code == ttyOpEnd || code > 160 {
			break
		}
		var val uint32
		val, rem, ok = parseUint32(rem)
		if !ok {
			return
		}
		modes[code] = val
	}
	ok = true
	return
}

func parseWindow(s []byte) (win Window, rem []byte, ok bool) {
	// See https://datatracker.ietf.org/doc/html/rfc4254#section-6.7
	wCols, rem, ok := parseUint32(s)
	if !ok {
		return
	}
	hRows, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	wPixels, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	hPixels, rem, ok := parseUint32(rem)
	if !ok {
		return
	}
	win = Window{
		Width:        int(wCols),
		Height:       int(hRows),
		WidthPixels:  int(wPixels),
		HeightPixels: int(hPixels),
	}
	return
}

func parseString(in []byte) (out string, rem []byte, ok bool) {
	length, rem, ok := parseUint32(in)
	if uint32(len(rem)) < length || !ok {
		ok = false
		return
	}
	out, rem = string(rem[:length]), rem[length:]
	ok = true
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseBool(in []byte) (bool, []byte, bool) {
	if len(in) < 1 {
		return false, nil, false
	}
	return uint8(in[0]) == 1, in[1:], true
}
