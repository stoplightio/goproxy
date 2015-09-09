/*
Package goproxy provides a customizable HTTP proxy,
supporting hijacking HTTPS connection.

The intent of the proxy, is to be usable with reasonable amount of traffic
yet, customizable and programable.

The proxy itself is simply an `net/http` handler.

Typical usage is

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		if ctx.Host() == "example.com:80" {
			ctx.SetDestinationHost("127.0.0.1:8080")
			return goproxy.FORWARD
		}
		return goproxy.NEXT
	})
	proxy.ListenAndServe(":8080")

Adding a header to each request:

	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Req.Header.Set("X-GoProxy","1")
		return goproxy.NEXT
	})

For printing the content type of all incoming responses

	proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		fmt.Println(ctx.Req.Host, "->", ctx.Req.Header.Get("Content-Type"))
		return goproxy.NEXT
	})

Note the use of `ctx.Req` here.  The `ctx` holds `Req` and `Resp`.
`Resp` can be nil if not available.

To print the content type of all responses from a certain url, we'll add a
"middleware" before:

	golangOrgOnly := goproxy.UrlHasPrefix("golang.org/pkg")
	logInYourFace := func(ctx *goproxy.ProxyCtx) goproxy.Next {
		fmt.Println(ctx.Req.Host, "->", ctx.Req.Header.Get("Content-Type"))
		return goproxy.NEXT
	}
	proxy.HandleResponseFunc(golangOrgOnly(logInYourFace))

To invalide responses based on headers for example, you can:

	proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		if ctx.Resp.Header.Get("X-GoProxy") == "" {
			ctx.Resp.Close()
			http.Error(ctx.ResponseWriter, "Denied.. didn't find an X-GoProxy header!", 403)
			return goproxy.DONE
		}
		return goproxy.NEXT
	})

We close the body of the original repsonse, and return a new 403 response with a short message.

You can catch traffic going through the proxy selectively, and write it to a HAR formatted file
with this code:

	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		if ctx.Host() == "example.com:80" {
			ctx.LogToHARFile(true)
		}
		return goproxy.NEXT
	})
	proxy.NonProxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/har" {
			proxy.FlushHARToDisk("/tmp/file.har")
			w.WriteHeader(201)
			w.Write([]byte("hello world!\n"))
		}
	})

You then "curl http://localhost:8888/har" to provoke a file flush to "/tmp/file.har".


Example use cases:

1. https://github.com/stoplightio/goproxy/tree/master/examples/goproxy-avgsize

To measure the average size of an Html served in your site. One can ask
all the QA team to access the website by a proxy, and the proxy will
measure the average size of all text/html responses from your host.

2. [not yet implemented]

All requests to your web servers should be directed through the proxy,
when the proxy will detect html pieces sent as a response to AJAX
request, it'll send a warning email.

3. https://github.com/stoplightio/goproxy/blob/master/examples/goproxy-httpdump/

Generate a real traffic to your website by real users using through
proxy. Record the traffic, and try it again for more real load testing.

4. https://github.com/stoplightio/goproxy/tree/master/examples/goproxy-no-reddit-at-worktime

Will allow browsing to reddit.com between 8:00am and 17:00pm

5. https://github.com/stoplightio/goproxy/tree/master/examples/goproxy-jquery-version

Will warn if multiple versions of jquery are used in the same domain.

6. https://github.com/stoplightio/goproxy/blob/master/examples/goproxy-upside-down-ternet/

Modifies image files in an HTTP response via goproxy's image extension found in ext/.

*/
package goproxy
