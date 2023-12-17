package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"regexp"

	http_dialer "github.com/chribro88/go-http-dialer"
	"github.com/elazarl/goproxy"
	"github.com/fedosgad/mirror_proxy/cert_generator"
	"github.com/fedosgad/mirror_proxy/hijackers"
	"golang.org/x/net/proxy"
)

const UPSTREAM_PROXY_HDR = "X-Mirrorproxy-Upstream" // canonical format

func main() {
	opts := getOptions()

	klw, err := getSSLLogWriter(opts)
	if err != nil {
		log.Fatalf("Error opening key log file: %v", err)
	}
	defer klw.Close()

	cg, err := cert_generator.NewCertGeneratorFromFiles(opts.CertFile, opts.KeyFile)
	if err != nil {
		log.Fatal(err)
	}

	proxyHeader := make(http.Header)

	dialer, err := getDialer(opts, proxyHeader)
	if err != nil {
		log.Fatalf("Error getting proxy dialer: %v", err)
	}

	hj := getHijacker(opts, klw, cg, dialer)

	transport := getTransport(dialer)

	p := goproxy.NewProxyHttpServer()
	// Handle all CONNECT requests
	p.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				// handle the X-Forwarded-For header
				remoteIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr)
				if err != nil {
					ctx.Logf("Error getting remote IP: %v", err)
				}
				ff := getAddHdr("X-Forwarded-For", remoteIP, ctx)
				// handle the Mirror Proxy header
				up := getDelHdr(UPSTREAM_PROXY_HDR, ctx)
				if len(up) != 0 {
					// change upstream proxy
					opts.ProxyAddr = up[0]
				}

				if len(ff) != 0 || len(up) != 0 {
					d, err := getDialer(opts, ctx.Req.Header)
					if err != nil {
						ctx.Logf("Error getting proxy dialer: %v", err)
						// TODO: return 500
						return &goproxy.ConnectAction{
							Action: goproxy.ConnectReject,
						}, host
					}

					hj = getHijacker(opts, klw, cg, d)
				}
				return &goproxy.ConnectAction{
					Action: goproxy.ConnectHijack,
					Hijack: getTLSHijackFunc(hj),
				}, host
			}))
	// Handle all HTTP requests
	p.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*$"))).
		DoFunc(
			func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				// handle the X-Forwarded-For header
				remoteIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr)
				if err != nil {
					ctx.Logf("Error getting remote IP: %v", err)
				}
				_ = getAddHdr("X-Forwarded-For", remoteIP, ctx)
				// handle the Mirror Proxy header
				up := getDelHdr(UPSTREAM_PROXY_HDR, ctx)
				if len(up) != 0 {
					// change upstream proxy
					opts.ProxyAddr = up[0]
				}

				// get new transport if upstream proxy provided ONLY
				if len(up) != 0 {
					d, err := getDialer(opts, req.Header)
					if err != nil {
						ctx.Logf("Error getting proxy dialer: %v", err)
						return nil, goproxy.NewResponse(
							req,
							"text/plain",
							500,
							fmt.Sprintf("Error getting proxy dialer: %v", err))
					}

					ctx.Proxy.Tr = getTransport(d)

				} else {
					// default upstream proxy
					ctx.Proxy.Tr = transport
				}
				return req, nil
			})

	p.Verbose = opts.Verbose

	if opts.PprofAddress != "" {
		go func() {
			log.Println(http.ListenAndServe(opts.PprofAddress, nil))
		}()
	}
	log.Fatal(http.ListenAndServe(opts.ListenAddress, p))
}

type writeNopCloser struct {
	io.Writer
}

func getAddHdr(hdr string, val string, ctx *goproxy.ProxyCtx) []string {
	// add val to header and return original value
	ffv, ok := ctx.Req.Header[hdr]
	// If the header exists
	if ok {
		ctx.Logf("Appending %s to Header %s: %s", val, hdr, ffv)
		ctx.Req.Header.Add(hdr, val)
		return ffv
	}
	return []string{}
}

func getDelHdr(hdr string, ctx *goproxy.ProxyCtx) []string {
	// delete the header and return original value
	upv, ok := ctx.Req.Header[hdr]
	// If the key exists
	if ok {
		ctx.Logf("Deleting Header: %s: %s", hdr, upv[0])
		ctx.Req.Header.Del(hdr)
		return upv
	}
	return []string{}
}

func (c writeNopCloser) Close() error {
	return nil
}

func getSSLLogWriter(opts *Options) (klw io.WriteCloser, err error) {
	klw = writeNopCloser{Writer: io.Discard}

	if opts.SSLLogFile != "" {
		klw, err = os.OpenFile(opts.SSLLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	return klw, err
}

func getDialer(opts *Options, proxyHeader http.Header) (proxy.Dialer, error) {
	// Timeout SHOULD be set. Otherwise, dialing will never succeed if the first address
	// returned by resolver is not responding (connection will just hang forever).
	d := &net.Dialer{
		Timeout: opts.DialTimeout,
	}
	if opts.ProxyAddr == "" {
		return d, nil
	}
	proxyURL, err := url.Parse(opts.ProxyAddr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Scheme == "socks5" {
		return proxy.FromURL(proxyURL, d)
	}
	h := make(http.Header)
	forwardfor, ok := proxyHeader["X-Forwarded-For"]
	// If the header exists
	if ok {
		h.Set("X-Forwarded-For", forwardfor[0])

	}
	if proxyURL.Scheme == "http" || proxyURL.Scheme == "https" {
		if proxyURL.User != nil {
			pass, _ := proxyURL.User.Password()
			username := proxyURL.User.Username()
			return http_dialer.New(
				proxyURL,
				http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, pass)),
				http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
				http_dialer.WithContextDialer(d),
				http_dialer.WithProxyHeader(h),
			), nil
		}
		return http_dialer.New(
			proxyURL,
			http_dialer.WithConnectionTimeout(opts.ProxyTimeout),
			http_dialer.WithContextDialer(d),
			http_dialer.WithProxyHeader(h),
		), nil
	}

	return nil, fmt.Errorf("cannot use proxy scheme %q", proxyURL.Scheme)
}

func getHijacker(opts *Options, klw io.WriteCloser, cg *cert_generator.CertificateGenerator, dialer proxy.Dialer) hijackers.Hijacker {
	hjf := hijackers.NewHijackerFactory(
		dialer,
		opts.AllowInsecure,
		klw,
		cg.GenChildCert,
		opts.KeepPSK,
	)
	return hjf.Get(opts.Mode)
}

func getTransport(dialer proxy.Dialer) *http.Transport {
	return &http.Transport{
		Dial:            dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}
