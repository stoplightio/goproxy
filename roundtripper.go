package goproxy

import (
	"fmt"
	"net"
	"net/http"
)

type RoundTripper interface {
	RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error)
}

type RoundTripperFunc func(req *http.Request, ctx *ProxyCtx) (*http.Response, error)

func (f RoundTripperFunc) RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
	return f(req, ctx)
}

func (ctx *ProxyCtx) RoundTrip(req *http.Request) (*http.Response, error) {
	if ctx.RoundTripper != nil {
		return ctx.RoundTripper.RoundTrip(req, ctx)
	}

	var tr http.RoundTripper
	var addendum = ""
	if ctx.fakeDestinationDNS != "" {
		tr = &RedirectedTransport{ctx.proxy.Transport, ctx.fakeDestinationDNS, ctx}
		addendum = fmt.Sprintf(", fakedns=%q", ctx.fakeDestinationDNS)
	} else {
		tr = ctx.proxy.Transport
	}

	ctx.Logf("RoundTrip for req.URL=%q, req.Host=%q%s", req.URL, req.Host, addendum)
	resp, err := tr.RoundTrip(req)
	ctx.Logf("  RoundTrip returned: err=%v", err)

	return resp, err
}

func wrapRoundTrip(req *http.Request, ctx *ProxyCtx) RoundTripper {
	if ctx.RoundTripper != nil {
		return ctx.RoundTripper
	}
	return RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
		return ctx.proxy.Transport.RoundTrip(req)
	})
}

type RedirectedTransport struct {
	*http.Transport
	redirectHost string
	ctx          *ProxyCtx
}

func (rt *RedirectedTransport) Dial(network, addr string) (c net.Conn, err error) {
	if addr != rt.redirectHost {
		rt.ctx.Logf("Transport.Dial: lying to whom we're connecting to: saying %q while connecting to %q", addr, rt.redirectHost)
	}
	return net.Dial(network, rt.redirectHost)
}
