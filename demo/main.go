package main

import (
	"log"
	"net/http"

	"github.com/go-httpproxy/httpproxy"
)

func OnError(ctx *httpproxy.Context, when string, error error) {
	log.Printf("%s %s", when, error)
}

func OnAccept(ctx *httpproxy.Context, req *http.Request) *http.Response {
	return nil
}

func OnAuth(ctx *httpproxy.Context, user string, pass string) bool {
	return true
}

func OnConnect(ctx *httpproxy.Context, host string) (httpproxy.ConnectAction, string) {
	//return httpproxy.ConnectOk, host
	return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) *http.Response {
	return nil
}

func OnResponse(ctx *httpproxy.Context, req *http.Request, resp *http.Response) {
	resp.Header.Add("Via", "test")
}

func main() {
	prx, _ := httpproxy.NewProxy()
	prx.OnError = OnError
	prx.OnResponse = OnResponse
	prx.OnConnect = OnConnect
	http.ListenAndServe(":8080", prx)
}
