package httpproxy

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

type ConnectAction int

const (
	ConnectNone = ConnectAction(iota)
	ConnectOk
	ConnectMitm
)

var hasPort = regexp.MustCompile(`:\d+$`)

type Proxy struct {
	SessionNo  int64
	Rt         http.RoundTripper
	UserData   interface{}
	OnError    func(ctx *Context, error error)
	OnAccept   func(ctx *Context, req *http.Request) *http.Response
	OnAuth     func(ctx *Context, user string, pass string) bool
	OnConnect  func(ctx *Context, host string) (ConnectAction, string)
	OnRequest  func(ctx *Context, req *http.Request) *http.Response
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)
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

func doConnect(ctx *Context, w http.ResponseWriter, r *http.Request) (w2 http.ResponseWriter, r2 *http.Request) {
	if r.Method != "CONNECT" {
		w2, r2 = w, r
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Close {
			defer r.Body.Close()
		}
		err := fmt.Errorf("httpserver does not support hijacking")
		doError(ctx, err)
		return
	}
	hijConn, _, err := hij.Hijack()
	if err != nil {
		if r.Close {
			defer r.Body.Close()
		}
		doError(ctx, err)
		return
	}
	ctx.ConnectAction = ConnectOk
	host := r.URL.Host
	if ctx.Prx.OnConnect != nil {
		ctx.ConnectAction, host = ctx.Prx.OnConnect(ctx, host)
		if ctx.ConnectAction == ConnectNone {
			ctx.ConnectAction = ConnectOk
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	switch ctx.ConnectAction {
	case ConnectOk:
		targetConn, err := net.Dial("tcp", host)
		if err != nil {
			hijConn.Close()
			doError(ctx, err)
			return
		}
		_, err = hijConn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		if err != nil {
			hijConn.Close()
			targetConn.Close()
			doError(ctx, err)
			return
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, err := io.Copy(targetConn, hijConn)
			if err != nil {
				doError(ctx, err)
			}
			wg.Done()
		}()
		go func() {
			_, err := io.Copy(hijConn, targetConn)
			if err != nil {
				doError(ctx, err)
			}
			wg.Done()
		}()
		hijConn.Close()
		targetConn.Close()
	}

	return
}

func doRequest(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	r.RequestURI = ""
	if !r.URL.IsAbs() {
		if r.Close {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil {
			doError(ctx, err)
		}
		return true
	}
	if ctx.Prx.OnRequest == nil {
		return false
	}
	resp := ctx.Prx.OnRequest(ctx, r)
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

func doResponse(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if r.Close {
			defer r.Body.Close()
		}
		doError(ctx, err)
		return false
	}
	if ctx.Prx.OnResponse != nil {
		ctx.Prx.OnResponse(ctx, r, resp)
	}
	err = ServeResponse(w, resp)
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
	removeProxyHeaders(r)

	if w2, r2 := doConnect(ctx, w, r); r2 != nil {
		w, r = w2, r2
	} else {
		return
	}

	if doRequest(ctx, w, r) {
		return
	}

	doResponse(ctx, w, r)
}
