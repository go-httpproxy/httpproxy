package httpproxy

import (
	"io"
	"net"
	"os"
	"syscall"
)

var (
	ErrResponseWrite       = NewError("response write")
	ErrRequestRead         = NewError("request read")
	ErrRemoteConnect       = NewError("remote connect")
	ErrNotSupportHijacking = NewError("httpserver does not support hijacking")
	ErrTLSSignHost         = NewError("TLS sign host")
	ErrTLSHandshake        = NewError("TLS handshake")
	ErrAbsURLAfterCONNECT  = NewError("absolute URL after CONNECT")
	ErrRoundTrip           = NewError("round trip")
)

type Error struct {
	ErrString string
}

func NewError(errString string) *Error {
	return &Error{errString}
}

func (e *Error) Error() string {
	return e.ErrString
}

func isConnectionClosed(error error) bool {
	if error == nil {
		return false
	}
	if error == io.EOF {
		return true
	}
	if err, ok := error.(*net.OpError); ok {
		if err, ok := err.Err.(*os.SyscallError); ok && (err.Err == syscall.EPIPE || err.Err == syscall.ECONNRESET ||
			err.Err == syscall.EPROTOTYPE) {
			return true
		}
	}
	return false
}
