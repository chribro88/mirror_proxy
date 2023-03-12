package hijackers

import (
	"crypto/tls"
	"io"
)

type HijackerFactory struct {
	dialer Dialer

	allowInsecure    bool
	keyLogWriter     io.Writer
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error)
	keepPSK          bool
}

func NewHijackerFactory(
	dialer Dialer,
	allowInsecure bool,
	keyLogWriter io.Writer,
	generateCertFunc func(ips []string, names []string) (*tls.Certificate, error),
	keepPSK bool,
) *HijackerFactory {
	return &HijackerFactory{
		dialer:           dialer,
		allowInsecure:    allowInsecure,
		keyLogWriter:     keyLogWriter,
		generateCertFunc: generateCertFunc,
		keepPSK:          keepPSK,
	}
}

func (hf *HijackerFactory) Get(mode string) Hijacker {
	switch mode {
	case ModePassthrough:
		return NewPassThroughHijacker(hf.dialer)
	case ModeMITM:
		return NewUTLSHijacker(
			hf.dialer,
			hf.allowInsecure,
			hf.keyLogWriter,
			hf.generateCertFunc,
			hf.keepPSK,
		)
	default:
		return nil
	}
}
