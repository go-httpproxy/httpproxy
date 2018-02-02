package httpproxy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

func InMemoryResponse(code int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	if body == nil {
		body = make([]byte, 0)
	}
	st := http.StatusText(code)
	if st != "" {
		st = " " + st
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d%s", code, st),
		StatusCode:    code,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewBuffer(body)),
		ContentLength: int64(len(body)),
	}
}

func ServeResponse(w http.ResponseWriter, resp *http.Response) error {
	if resp.Close {
		defer resp.Body.Close()
	}
	h := w.Header()
	for k, v := range resp.Header {
		for _, v1 := range v {
			h.Add(k, v1)
		}
	}
	if resp.ContentLength >= 0 {
		h.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	} else {
		h.Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)
	_, err := io.Copy(w, resp.Body)
	return err
}

func ServeInMemory(w http.ResponseWriter, code int, header http.Header, body []byte) error {
	return ServeResponse(w, InMemoryResponse(code, header, body))
}

var hasPort = regexp.MustCompile(`:\d+$`)

func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}

func removeProxyHeaders(r *http.Request) {
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.
	r.Header.Del("Connection")
}
