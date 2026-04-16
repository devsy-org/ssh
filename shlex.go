package ssh

// shelxSplit performs POSIX shell-like word splitting on s.
//
// This is an inlined and simplified version of github.com/anmitsu/go-shlex
// (MIT license, Copyright (c) anmitsu <anmitsu.s@gmail.com>).
// Only the posix + whitespace-split code path is retained since that is the
// only mode used by this package.

import (
	"bufio"
	"io"
	"strings"
	"unicode"
)

func shlexSplit(s string) ([]string, error) {
	r := bufio.NewReader(strings.NewReader(s))
	var result []string
	for {
		token, err := shlexReadToken(r)
		if token != "" {
			result = append(result, token)
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return result, err
		}
	}
	return result, nil
}

func shlexIsQuote(r rune) bool  { return r == '\'' || r == '"' }
func shlexIsEscape(r rune) bool { return r == '\\' }

func shlexReadToken(r *bufio.Reader) (string, error) {
	token := ""
	quoted := false
	state := ' '
	escapedstate := ' '

scanning:
	for {
		next, _, err := r.ReadRune()
		if err != nil {
			if shlexIsQuote(state) || shlexIsEscape(state) {
				return token, err
			}
			return token, err
		}

		switch {
		case unicode.IsSpace(state): // whitespace state
			switch {
			case unicode.IsSpace(next):
				break scanning
			case shlexIsEscape(next):
				escapedstate = 'a'
				state = next
			case shlexIsQuote(next):
				state = next
			default:
				token += string(next)
				state = 'a'
			}

		case shlexIsQuote(state): // inside quotes
			quoted = true
			switch {
			case next == state:
				state = 'a'
			case shlexIsEscape(next) && state == '"':
				escapedstate = state
				state = next
			default:
				token += string(next)
			}

		case shlexIsEscape(state): // after backslash
			if shlexIsQuote(escapedstate) && next != state && next != escapedstate {
				token += string(state)
			}
			token += string(next)
			state = escapedstate

		default: // word state
			switch {
			case unicode.IsSpace(next):
				if token != "" || quoted {
					break scanning
				}
			case shlexIsQuote(next):
				state = next
			case shlexIsEscape(next):
				escapedstate = 'a'
				state = next
			default:
				token += string(next)
			}
		}
	}
	return token, nil
}
