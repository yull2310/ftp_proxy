package pftp

// modify by yull
type Context struct {
	RemoteAddr      string
	RealLoginUser   string
	RealLoginPasswd string
	LoginSessionID  string
}

func newContext(c *config) *Context {
	return &Context{
		RemoteAddr: c.RemoteAddr,
	}
}
