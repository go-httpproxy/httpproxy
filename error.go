package httpproxy

import (
	"io"
	"net"
	"os"
	"syscall"
)

// Library specific errors.
var (
	ErrPanic                       = NewError("panic")
	ErrResponseWrite               = NewError("response write")
	ErrRequestRead                 = NewError("request read")
	ErrRemoteConnect               = NewError("remote connect")
	ErrNotSupportHijacking         = NewError("httpserver does not support hijacking")
	ErrTLSSignHost                 = NewError("TLS sign host")
	ErrTLSHandshake                = NewError("TLS handshake")
	ErrAbsURLAfterCONNECT          = NewError("absolute URL after CONNECT")
	ErrRoundTrip                   = NewError("round trip")
	ErrUnsupportedTransferEncoding = NewError("unsupported transfer encoding")
)

// Error struct is base of library specific errors.
type Error struct {
	ErrString string
}

// NewError returns a new Error.
func NewError(errString string) *Error {
	return &Error{errString}
}

// Error implements error interface.
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
