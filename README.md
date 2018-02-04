# A Go HTTP proxy library which has KISS principle

## Introduction

`github.com/go-httpproxy/httpproxy` repository provides an HTTP proxy library
for Go (golang).

The library is regular HTTP proxy; supports HTTP, HTTPS through CONNECT. And
also provides HTTPS connection using "Man in the Middle" style attack.

It's easy to use. `httpproxy.Proxy` implements `Handler` interface of `net/http`
package to offer `http.ListenAndServe` function.

### Keep it simple, stupid!

> KISS is an acronym for "Keep it simple, stupid" as a design principle. The
KISS principle states that most systems work best if they are kept simple rather
than made complicated; therefore simplicity should be a key goal in design and
unnecessary complexity should be avoided.  [Wikipedia]

## Usage

Library has two significant structs: Proxy and Context.

### Proxy struct

```go
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
}
```

### Context struct

```go
// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	// User data to use free.
	UserData interface{}
}
```

## GoDoc

[https://godoc.org/github.com/go-httpproxy/httpproxy](https://godoc.org/github.com/go-httpproxy/httpproxy)

## To-Do

* GoDoc
