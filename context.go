package httpproxy

import "net/http"

// Context defines context of each proxy connection.
type Context struct {
	Prx           *Proxy
	SessionNo     int64
	ConnectAction ConnectAction
	ConnectReq    *http.Request
	UserData      interface{}
}
