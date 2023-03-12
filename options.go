package main

import (
	"log"
	"time"

	"github.com/cosiner/flag"
)

type Options struct {
	Verbose       bool   `names:"--verbose, -v" usage:"Turn on verbose logging" default:"false"`
	ListenAddress string `names:"--listen, -l" usage:"Address for proxy to listen on" default:":8080"`
	PprofAddress  string `names:"--pprof" usage:"Enable profiling server on http://{pprof}/debug/pprof/" default:""`

	Mode string `names:"--mode, -m" usage:"Operation mode (available: mitm, passthrough)" default:"mitm"`

	DialTimeout     time.Duration `names:"-"`
	DialTimeoutArg  string        `names:"--dial-timeout, -dt" usage:"Remote host dialing timeout" default:"5s"`
	ProxyAddr       string        `names:"--proxy, -p" usage:"Upstream proxy address (direct connection if empty)" default:""`
	ProxyTimeout    time.Duration `names:"-"`
	ProxyTimeoutArg string        `names:"--proxy-timeout, -pt" usage:"Upstream proxy timeout" default:"5s"`

	CertFile      string `names:"--certificate, -c" usage:"Path to root CA certificate" default:""`
	KeyFile       string `names:"--key, -k" usage:"Path to root CA key" default:""`
	SSLLogFile    string `names:"--sslkeylog, -s" usage:"Path to SSL/TLS secrets log file" default:"ssl.log"`
	AllowInsecure bool   `names:"--insecure, -i" usage:"Allow connecting to insecure remote hosts" default:"false"`
	KeepPSK       bool   `names:"--keeppsk, -e" usage:"KeepPSK will ensure that the PreSharedKey extension is passed along into the resulting ClientHelloSpec as-is. Depreciated in utls 1.3.0" default:"false"`
}

func getOptions() *Options {
	opts := &Options{}
	err := flag.Commandline.ParseStruct(opts)
	if err != nil {
		log.Fatal(err)
	}
	parseDuration(opts.DialTimeoutArg, &opts.DialTimeout)
	parseDuration(opts.ProxyTimeoutArg, &opts.ProxyTimeout)
	opts.check()
	return opts
}

func (o Options) check() {
	failIfEmpty := func(val, err string) {
		if val == "" {
			log.Fatal(err)
		}
	}

	failIfEmpty(o.ListenAddress, "Please provide listen address")
	if o.Mode != "mitm" && o.Mode != "passthrough" {
		log.Fatal()
	}
	if o.Mode != "mitm" {
		return
	}
	// TLS-related options
	failIfEmpty(o.CertFile, "Please provide certificate file")
	failIfEmpty(o.KeyFile, "Please provide key file")
	failIfEmpty(o.SSLLogFile, "Please provide key log file")

	if o.DialTimeout == 0 {
		log.Println("Warning: timeout=0, connections may hang!")
	}
	return
}

func parseDuration(inp string, res *time.Duration) {
	d, err := time.ParseDuration(inp)
	if err != nil {
		log.Fatal(err)
	}
	*res = d
}
