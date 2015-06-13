package goproxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
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
		req.URL.Host = ctx.fakeDestinationDNS
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         strings.Split(ctx.host, ":")[0],
				InsecureSkipVerify: true,
			},
			Proxy: ctx.proxy.Transport.Proxy,
		}
		addendum = fmt.Sprintf(", sni=%q, fakedns=%q", transport.TLSClientConfig.ServerName, ctx.fakeDestinationDNS)
		tr = transport
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
