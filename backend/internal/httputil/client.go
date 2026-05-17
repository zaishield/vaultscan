// Package httputil ships a production-ready *http.Client with
// sane timeouts and a properly-pooled transport. Several callers
// (integrations.Service, updater fetches, OIDC JWKS fetcher,
// cloudposture adapters) used http.DefaultClient or built their
// own client with no IdleConnTimeout — under load the kernel
// runs out of ephemeral source ports because every call opens a
// fresh socket.
package httputil

import (
	"net"
	"net/http"
	"time"
)

// Options configures a Client. Zero values are filled with sane
// production defaults.
type Options struct {
	// Total per-call timeout. Includes connect + headers + body.
	// 30s is the upper bound on a single outbound call; longer
	// than that and the caller's request ctx has almost certainly
	// expired anyway.
	Timeout time.Duration

	// Dial / TLS sub-timeouts.
	DialTimeout    time.Duration
	TLSTimeout     time.Duration
	IdleTimeout    time.Duration

	// Pool sizing. Set per-deploy if you talk to a small number
	// of upstreams with high RPS (e.g. SIEM forwarder); defaults
	// are reasonable for the mixed-upstream case.
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int

	// Additional transport hooks (e.g. otel instrumentation).
	WrapTransport func(http.RoundTripper) http.RoundTripper
}

func (o Options) withDefaults() Options {
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.TLSTimeout == 0 {
		o.TLSTimeout = 5 * time.Second
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 90 * time.Second
	}
	if o.MaxIdleConns == 0 {
		o.MaxIdleConns = 100
	}
	if o.MaxIdleConnsPerHost == 0 {
		o.MaxIdleConnsPerHost = 16
	}
	if o.MaxConnsPerHost == 0 {
		// 0 in net/http means unlimited; we want an explicit cap
		// so a single misbehaving upstream can't exhaust local
		// ephemeral ports.
		o.MaxConnsPerHost = 64
	}
	return o
}

// NewClient builds an *http.Client with the production transport.
// Callers should keep ONE instance and reuse it for the lifetime
// of the process — the connection pool is what makes this
// configuration worth using.
func NewClient(o Options) *http.Client {
	o = o.withDefaults()
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   o.DialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          o.MaxIdleConns,
		MaxIdleConnsPerHost:   o.MaxIdleConnsPerHost,
		MaxConnsPerHost:       o.MaxConnsPerHost,
		IdleConnTimeout:       o.IdleTimeout,
		TLSHandshakeTimeout:   o.TLSTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// Limit response header size so a hostile or broken upstream
		// can't OOM us with a flood of headers.
		MaxResponseHeaderBytes: 64 * 1024,
	}
	var rt http.RoundTripper = tr
	if o.WrapTransport != nil {
		rt = o.WrapTransport(tr)
	}
	return &http.Client{
		Timeout:   o.Timeout,
		Transport: rt,
	}
}
