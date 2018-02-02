package httpproxy

import "net/http"

type Context struct {
	Prx           *Proxy
	SessionNo     int64
	ConnectAction ConnectAction
	ConnectReq    *http.Request
	UserData      interface{}
}
