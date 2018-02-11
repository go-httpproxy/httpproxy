/*
Package httpproxy provides a customizable HTTP proxy;
supports HTTP, HTTPS through CONNECT. And also provides HTTPS connection
using "Man in the Middle" style attack.

It's easy to use. `httpproxy.Proxy` implements `Handler` interface of `net/http`
package to offer `http.ListenAndServe` function.
*/
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
	// ConnectNone specifies that proxy request is not CONNECT.
	// If it returned in OnConnect, proxy connection closes immediately.
	ConnectNone = ConnectAction(iota)

	// ConnectProxy specifies directly socket proxy after the CONNECT.
	ConnectProxy

	// ConnectMitm specifies proxy "Man in the Middle" style attack
	// after the CONNECT.
	ConnectMitm
)

// Proxy defines parameters for running an HTTP Proxy. It implements
// http.Handler interface for ListenAndServe function. If you need, you must
// fill Proxy struct before handling requests.
type Proxy struct {
	// Session number of last proxy request.
	SessionNo int64

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Rt http.RoundTripper

	// Certificate key pair.
	Ca tls.Certificate

	// User data to use free.
	UserData interface{}

	// Error handler.
	OnError func(ctx *Context, when string, err *Error, opErr error)

	// Accept handler. It greets proxy request like ServeHTTP function of
	// http.Handler.
	// If it returns true, stops processing proxy request.
	OnAccept func(ctx *Context, w http.ResponseWriter, r *http.Request) bool

	// Auth handler. If you need authentication, set this handler.
	// If it returns true, authentication succeeded.
	OnAuth func(ctx *Context, user string, pass string) bool

	// Connect handler. It sets connect action and new host.
	// If len(newhost) > 0, host changes.
	OnConnect func(ctx *Context, host string) (ConnectAction ConnectAction,
		newHost string)

	// Request handler. It greets remote request.
	// If it returns non-nil response, stops processing remote request.
	OnRequest func(ctx *Context, req *http.Request) (resp *http.Response)

	// Response handler. It greets remote response.
	// Remote response sends after this handler.
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)

	// If ConnectAction is ConnectMitm, it sets chunked to Transfer-Encoding.
	// By default, it is true.
	MitmChunked bool

	AuthType string
}

// NewProxy returns a new Proxy has default CA certificate and key.
func NewProxy() (*Proxy, error) {
	return NewProxyCert(nil, nil)
}

// NewProxyCert returns a new Proxy given CA certificate and key.
func NewProxyCert(caCert, caKey []byte) (result *Proxy, error error) {
	result = &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyFromEnvironment}, MitmChunked: true,
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

// ServeHTTP implements http.Handler.
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
		if w != w2 {
			w = w2
			r = nil
		}
	} else {
		return
	}

	for {
		var cyclic = false
		switch ctx.ConnectAction {
		case ConnectMitm:
			if prx.MitmChunked {
				cyclic = true
			}
			r = doMitm(ctx, w)
		}
		if r == nil {
			break
		}
		ctx.SubSessionNo++
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
