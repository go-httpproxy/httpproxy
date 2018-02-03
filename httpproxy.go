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
	SessionNo   int64
	Rt          http.RoundTripper
	Ca          tls.Certificate
	UserData    interface{}
	OnError     func(ctx *Context, when string, err *Error, opErr error)
	OnAccept    func(ctx *Context, req *http.Request) *http.Response
	OnAuth      func(ctx *Context, user string, pass string) bool
	OnConnect   func(ctx *Context, host string) (ConnectAction, string)
	OnRequest   func(ctx *Context, req *http.Request) *http.Response
	OnResponse  func(ctx *Context, req *http.Request, resp *http.Response)
	MitmChunked bool
}

// NewProxy returns a new Proxy has default certificate and key.
func NewProxy() (*Proxy, error) {
	return NewProxyCert(nil, nil)
}

// NewProxyCert returns a new Proxy given certificate and key.
func NewProxyCert(caCert, caKey []byte) (result *Proxy, error error) {
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

	if w2 := doConnect(ctx, w, r); w2 != nil {
		w = w2
	} else {
		return
	}

	for {
		var cyclic = false
		if ctx.ConnectAction == ConnectMitm {
			if prx.MitmChunked {
				cyclic = true
			}
			r = doMitm(ctx, w)
		}
		if r == nil {
			break
		}
		ctx.SubSessionNo += 1
		if b, err := doRequest(ctx, w, r); err != nil {
			break
		} else {
			if b {
				if !cyclic {
					break
				} else {
					continue
				}
			}
		}
		if b, err := doResponse(ctx, w, r); err != nil || !b || !cyclic {
			break
		}
	}

	if w2, ok := w.(*ConnResponseWriter); ok {
		w2.Close()
	}
}
