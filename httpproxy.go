package httpproxy

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"strings"
	"sync/atomic"
)

type ConnectAction int

const (
	ConnectAccept = ConnectAction(iota)
	ConnectReject
	ConnectMitm
)

type Proxy struct {
	SessionNo  int64
	Rt         http.RoundTripper
	UserData   interface{}
	OnError    func(ctx *Context, error error)
	OnAccept   func(ctx *Context, req *http.Request) *http.Response
	OnAuth     func(ctx *Context, user string, pass string) bool
	OnConnect  func(ctx *Context, host string) (ConnectAction, string)
	OnRequest  func(ctx *Context, req *http.Request) (*http.Request, *http.Response)
	OnResponse func(ctx *Context, resp *http.Response) *http.Response
}

func doError(ctx *Context, error error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, error)
}

func doAccept(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	if ctx.Prx.OnAccept == nil {
		return false
	}
	resp := ctx.Prx.OnAccept(ctx, r)
	if resp == nil {
		return false
	}
	if r.Close {
		defer r.Body.Close()
	}
	err := ServeResponse(w, resp)
	if err != nil {
		doError(ctx, err)
	}
	return true
}

func doAuth(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	if ctx.Prx.OnAuth == nil {
		return false
	}
	authparts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authparts) >= 2 {
		switch authparts[0] {
		case "Basic":
			userpassraw, err := base64.StdEncoding.DecodeString(authparts[1])
			if err == nil {
				userpass := strings.SplitN(string(userpassraw), ":", 2)
				if len(userpass) >= 2 && ctx.Prx.OnAuth(ctx, userpass[0], userpass[1]) {
					return false
				}
			}
		}
	}
	if r.Close {
		defer r.Body.Close()
	}
	err := ServeInMemory(w, 407, nil, []byte("Proxy Authentication Required"))
	if err != nil {
		doError(ctx, err)
	}
	return true
}

func NewProxy() (*Proxy, error) {
	result := &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: http.ProxyFromEnvironment},
	}
	return result, nil
}

func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &Context{Prx: prx, SessionNo: atomic.AddInt64(&prx.SessionNo, 1)}

	if doAccept(ctx, w, r) {
		return
	}

	if doAuth(ctx, w, r) {
		return
	}
}
