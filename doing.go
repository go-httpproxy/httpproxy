package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

func doError(ctx *Context, when string, err *Error, opErr error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, when, err, opErr)
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
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Accept", ErrResponseWrite, err)
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
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Auth", ErrResponseWrite, err)
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
		doError(ctx, "Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Close {
			defer r.Body.Close()
		}
		doError(ctx, "Connect", ErrNotSupportHijacking, err)
		return
	}
	hijConn := conn.(*net.TCPConn)
	ctx.ConnectAction = ConnectProxy
	host := r.URL.Host
	if ctx.Prx.OnConnect != nil {
		ctx.ConnectAction, host = ctx.Prx.OnConnect(ctx, host)
		if ctx.ConnectAction == ConnectNone {
			ctx.ConnectAction = ConnectProxy
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	switch ctx.ConnectAction {
	case ConnectProxy:
		conn, err := net.Dial("tcp", host)
		if err != nil {
			hijConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			hijConn.Close()
			doError(ctx, "Connect", ErrRemoteConnect, err)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrResponseWrite, err)
			}
			return
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, err := io.Copy(remoteConn, hijConn)
			if err != nil && !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrRequestRead, err)
			}
			wg.Done()
		}()
		go func() {
			_, err := io.Copy(hijConn, remoteConn)
			if err != nil && !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrResponseWrite, err)
			}
			wg.Done()
		}()
		wg.Wait()
		hijConn.Close()
		remoteConn.Close()
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		cert, err := signHosts(ctx.Prx.Ca, []string{stripPort(host)})
		if err != nil {
			hijConn.Close()
			doError(ctx, "Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrResponseWrite, err)
			}
			return
		}
		hijTlsConn := tls.Server(hijConn, tlsConfig)
		if err := hijTlsConn.Handshake(); err != nil {
			hijTlsConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrTLSHandshake, err)
			}
			return
		}
		hijTlsReader := bufio.NewReader(hijTlsConn)
		req, err := http.ReadRequest(hijTlsReader)
		if err != nil {
			hijTlsConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrRequestRead, err)
			}
			return
		}
		req.RemoteAddr = r.RemoteAddr
		if req.URL.IsAbs() {
			hijTlsConn.Close()
			doError(ctx, "Connect", ErrAbsURLAfterCONNECT, nil)
			return
		}
		req.URL.Scheme = "https"
		req.URL.Host = host
		w2 = NewConnResponseWriter(hijTlsConn)
		r2 = req
		return
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
		if err != nil && !isConnectionClosed(err) {
			doError(ctx, "Request", ErrResponseWrite, err)
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
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Request", ErrResponseWrite, err)
	}
	return true
}

func doResponse(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if r.Close {
			defer r.Body.Close()
		}
		if err != context.Canceled && !isConnectionClosed(err) {
			doError(ctx, "Response", ErrRoundTrip, err)
		}
		return false
	}
	if ctx.Prx.OnResponse != nil {
		ctx.Prx.OnResponse(ctx, r, resp)
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Response", ErrResponseWrite, err)
	}
	return true
}
