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
	if !ctx.Prx.OnAccept(ctx, w, r) {
		return false
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	return true
}

func doAuth(ctx *Context, w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "CONNECT" && !r.URL.IsAbs() {
		return false
	}
	if ctx.Prx.OnAuth == nil {
		return false
	}
	prxAuthType := ctx.Prx.AuthType
	if prxAuthType == "" {
		prxAuthType = "Basic"
	}
	unauthorized := false
	authParts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authParts) >= 2 {
		authType := authParts[0]
		authData := authParts[1]
		if prxAuthType == authType {
			unauthorized = true
			switch authType {
			case "Basic":
				userpassraw, err := base64.StdEncoding.DecodeString(authData)
				if err == nil {
					userpass := strings.SplitN(string(userpassraw), ":", 2)
					if len(userpass) >= 2 && ctx.Prx.OnAuth(ctx, userpass[0], userpass[1]) {
						return false
					}
				}
			default:
				unauthorized = false
			}
		}
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	respCode := 407
	respBody := "Proxy Authentication Required"
	if unauthorized {
		respBody += " [Unauthorized]"
	}
	err := ServeInMemory(w, respCode, map[string][]string{"Proxy-Authenticate": {prxAuthType}},
		[]byte(respBody))
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Auth", ErrResponseWrite, err)
	}
	return true
}

func doConnect(ctx *Context, w http.ResponseWriter, r *http.Request) (w2 http.ResponseWriter) {
	if r.Method != "CONNECT" {
		w2 = w
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		doError(ctx, "Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		doError(ctx, "Connect", ErrNotSupportHijacking, err)
		return
	}
	//hijConn := conn.(*net.TCPConn)
	hijConn := conn
	ctx.ConnectAction = ConnectProxy
	ctx.ConnectReq = r
	host := r.URL.Host
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.Prx.OnConnect(ctx, host)
		if newHost != "" {
			host = newHost
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	switch ctx.ConnectAction {
	case ConnectProxy:
		conn, err := net.Dial("tcp", host)
		if err != nil {
			hijConn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
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
		cert := ctx.Prx.signer.SignHost(stripPort(host))
		if cert == nil {
			hijConn.Close()
			doError(ctx, "Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrResponseWrite, err)
			}
			return
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) {
				doError(ctx, "Connect", ErrTLSHandshake, err)
			}
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		w2 = NewConnResponseWriter(ctx.hijTLSConn)
	default:
		hijConn.Close()
	}
	return
}

func doMitm(ctx *Context, w http.ResponseWriter) (r *http.Request) {
	req, err := http.ReadRequest(ctx.hijTLSReader)
	if err != nil {
		if !isConnectionClosed(err) {
			doError(ctx, "Request", ErrRequestRead, err)
		}
		return
	}
	req.RemoteAddr = ctx.ConnectReq.RemoteAddr
	if req.URL.IsAbs() {
		doError(ctx, "Request", ErrAbsURLAfterCONNECT, nil)
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = ctx.ConnectHost
	r = req
	return
}

func doRequest(ctx *Context, w http.ResponseWriter, r *http.Request) (bool, error) {
	r.RequestURI = ""
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil && !isConnectionClosed(err) {
			doError(ctx, "Request", ErrResponseWrite, err)
		}
		return true, err
	}
	if ctx.Prx.OnRequest == nil {
		return false, nil
	}
	resp := ctx.Prx.OnRequest(ctx, r)
	if resp == nil {
		return false, nil
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err := ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Request", ErrResponseWrite, err)
	}
	return true, err
}

func doResponse(ctx *Context, w http.ResponseWriter, r *http.Request) error {
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) {
			doError(ctx, "Response", ErrRoundTrip, err)
		}
		err := ServeInMemory(w, 404, nil, nil)
		if err != nil && !isConnectionClosed(err) {
			doError(ctx, "Response", ErrResponseWrite, err)
		}
		return err
	}
	if ctx.Prx.OnResponse != nil {
		ctx.Prx.OnResponse(ctx, r, resp)
	}
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	err = ServeResponse(w, resp)
	if err != nil && !isConnectionClosed(err) {
		doError(ctx, "Response", ErrResponseWrite, err)
	}
	return err
}
