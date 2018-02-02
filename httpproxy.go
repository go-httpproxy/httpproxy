package httpproxy

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
)

// ConnectAction specifies action of after the CONNECT.
type ConnectAction int

// Constants of ConnectAction type.
const (
	ConnectNone = ConnectAction(iota)
	ConnectProxy
	ConnectMitm
)

// Proxy defines parameters for running an HTTP Proxy. Also implements http.Handler interface for ListenAndServe function.
type Proxy struct {
	SessionNo  int64
	Rt         http.RoundTripper
	Ca         tls.Certificate
	UserData   interface{}
	OnError    func(ctx *Context, when string, err *Error, opErr error)
	OnAccept   func(ctx *Context, req *http.Request) *http.Response
	OnAuth     func(ctx *Context, user string, pass string) bool
	OnConnect  func(ctx *Context, host string) (ConnectAction, string)
	OnRequest  func(ctx *Context, req *http.Request) *http.Response
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)
}

// NewProxy returns a new Proxy has defaults.
func NewProxy() (*Proxy, error) {
	return NewProxyWithCert(nil, nil)
}

// NewProxyWithCert returns a new Proxy given certificate and key.
func NewProxyWithCert(caCert, caKey []byte) (result *Proxy, error error) {
	result = &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyFromEnvironment},
	}
	if caCert == nil {
		caCert = DefaultCaCert
	}
	if caKey == nil {
		caKey = DefaultCaKey
	}
	result.Ca, error = tls.X509KeyPair(caCert, caKey)
	if error != nil {
		return
	}
	return
}

// ServeHTTP has been needed for implementing http.Handler.
func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &Context{Prx: prx, SessionNo: atomic.AddInt64(&prx.SessionNo, 1)}

	if doAccept(ctx, w, r) {
		return
	}

	if doAuth(ctx, w, r) {
		return
	}
	removeProxyHeaders(r)

	if w2, r2 := doConnect(ctx, w, r); r2 != nil {
		if r != r2 {
			ctx.ConnectReq = r
		}
		w, r = w2, r2
	} else {
		return
	}

	if doRequest(ctx, w, r) {
		if w2, ok := w.(*ConnResponseWriter); ok {
			w2.Close()
		}
		return
	}

	doResponse(ctx, w, r)
	if w2, ok := w.(*ConnResponseWriter); ok {
		w2.Close()
	}
}
