package httpproxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

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
			hijConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			hijConn.Close()
			doError(ctx, err)
			return
		}
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
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
		wg.Wait()
		hijConn.Close()
		targetConn.Close()
	case ConnectMitm:
		//tlsConfig := &tls.Config{InsecureSkipVerify: true}
		tlsConfig := &tls.Config{}
		cert, err := signHosts(ctx.Prx.Ca, []string{stripPort(host)})
		if err != nil {
			hijConn.Close()
			doError(ctx, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)

		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			doError(ctx, err)
			return
		}

		hijTlsConn := tls.Server(hijConn, tlsConfig)
		if err := hijTlsConn.Handshake(); err != nil {
			hijTlsConn.Close()
			doError(ctx, err)
			return
		}

		hijTlsReader := bufio.NewReader(hijTlsConn)
		req, err := http.ReadRequest(hijTlsReader)
		if err != nil {
			hijTlsConn.Close()
			if err != io.EOF {
				doError(ctx, err)
			}
			return
		}

		req.RemoteAddr = r.RemoteAddr
		req.URL, _ = url.Parse("https://" + host + req.URL.String()) //!
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
