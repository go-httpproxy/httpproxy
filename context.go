package httpproxy

import (
	"bufio"
	"crypto/tls"
	"net/http"
)

// Context defines context of each proxy connection.
type Context struct {
	Prx           *Proxy
	SessionNo     int64
	ConnectAction ConnectAction
	ConnectReq    *http.Request
	ConnectHost   string
	UserData      interface{}
	hijTlsConn    *tls.Conn
	hijTlsReader  *bufio.Reader
}
