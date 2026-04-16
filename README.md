# skevetter/ssh

[![Go Reference](https://pkg.go.dev/badge/github.com/skevetter/ssh.svg)](https://pkg.go.dev/github.com/skevetter/ssh)

A higher-level Go API for building SSH servers, wrapping
[golang.org/x/crypto/ssh](https://pkg.go.dev/golang.org/x/crypto/ssh).
Designed to feel as simple as `net/http`.

This is a maintained fork of [gliderlabs/ssh](https://github.com/gliderlabs/ssh).

## Quick Start

```go
package main

import (
    "io"
    "log"

    "github.com/skevetter/ssh"
)

func main() {
    ssh.Handle(func(s ssh.Session) {
        io.WriteString(s, "Hello world\n")
    })

    log.Fatal(ssh.ListenAndServe(":2222", nil))
}
```

## Install

```
go get github.com/skevetter/ssh
```

Requires Go 1.25+. The only runtime dependency is `golang.org/x/crypto`.

## Features

- Simple `Handler` / `ListenAndServe` API mirroring `net/http`
- Password, public key, and keyboard-interactive authentication
- PTY requests and window-change events
- Session environment variables, signals, and break requests
- Local and reverse TCP port forwarding
- Unix domain socket (streamlocal) forwarding
- SSH agent forwarding
- X11 forwarding
- Subsystem handlers (e.g. SFTP)
- Keep-alive support
- Graceful shutdown and connection draining
- Custom server configuration via `ServerConfigCallback`

## Usage

### Authentication

```go
ssh.ListenAndServe(":2222", nil,
    ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
        return pass == "secret"
    }),
)
```

```go
ssh.ListenAndServe(":2222", nil,
    ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
        // compare against allowed key
        return ssh.KeysEqual(key, allowedKey)
    }),
)
```

### Host Keys

```go
// From a PEM file
ssh.ListenAndServe(":2222", nil, ssh.HostKeyFile("/path/to/key"))

// Or configure a Server directly
srv := &ssh.Server{Addr: ":2222", Handler: handler}
srv.AddHostKey(signer)
log.Fatal(srv.ListenAndServe())
```

If no host key is specified, one is generated at startup (useful for development).

### PTY Handling

```go
ssh.Handle(func(s ssh.Session) {
    ptyReq, winCh, isPty := s.Pty()
    if !isPty {
        io.WriteString(s, "No PTY requested.\n")
        s.Exit(1)
        return
    }
    // ptyReq.Term, ptyReq.Window, winCh for resize events
})
```

### Port Forwarding

Enable local (direct-tcpip) and reverse (tcpip-forward) port forwarding by
setting the appropriate callbacks on the server:

```go
srv := &ssh.Server{
    Handler: handler,
    LocalPortForwardingCallback: func(ctx ssh.Context, host string, port uint32) bool {
        return true // allow all
    },
    ReversePortForwardingCallback: func(ctx ssh.Context, host string, port uint32) bool {
        return true
    },
}
```

## Examples

See the [`_examples`](./_examples) directory for working demos:

| Directory | Description |
|-----------|-------------|
| `ssh-simple` | Minimal echo server |
| `ssh-pty` | PTY with terminal emulation |
| `ssh-publickey` | Public key authentication |
| `ssh-remoteforward` | Reverse port forwarding |
| `ssh-forwardagent` | SSH agent forwarding |
| `ssh-sftpserver` | SFTP subsystem |
| `ssh-docker` | Docker-backed SSH sessions |
| `ssh-timeouts` | Idle and max-deadline timeouts |

## API Reference

[pkg.go.dev/github.com/skevetter/ssh](https://pkg.go.dev/github.com/skevetter/ssh)

## Contributing

Pull requests are welcome. For API design changes, please open an issue first
to discuss.

## License

[BSD](LICENSE)
