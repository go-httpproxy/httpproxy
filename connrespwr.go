package httpproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

type ConnResponseWriter struct {
	Conn        net.Conn
	mu          sync.Mutex
	code        int
	header      http.Header
	headersSent bool
}

func NewConnResponseWriter(conn net.Conn) *ConnResponseWriter {
	return &ConnResponseWriter{Conn: conn, header: make(http.Header)}
}

func (c *ConnResponseWriter) Header() http.Header {
	return c.header
}

func (c *ConnResponseWriter) Write(body []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.headersSent {
		c.headersSent = true
		st := http.StatusText(c.code)
		if st != "" {
			st = " " + st
		}
		if _, err := io.WriteString(c.Conn, fmt.Sprintf("HTTP/1.1 %d%s\r\n", c.code, st)); err != nil {
			return 0, err
		}
		if err := c.header.Write(c.Conn); err != nil {
			return 0, err
		}
		if _, err := io.WriteString(c.Conn, "\r\n"); err != nil {
			return 0, err
		}
	}
	return c.Conn.Write(body)
}

func (c *ConnResponseWriter) WriteHeader(code int) {
	c.code = code
}

func (c *ConnResponseWriter) Close() error {
	return c.Conn.Close()
}
