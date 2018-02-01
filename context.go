package httpproxy

type Context struct {
	Prx       *Proxy
	SessionNo int64
	UserData  interface{}
}
