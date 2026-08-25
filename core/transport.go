// Package core provides session management, connection pooling, and shared
// transport infrastructure for all Proton service clients. A single core
// session is shared across service modules (drive, mail, calendar, etc.),
// each of which forks its own auth context but reuses the underlying TCP/TLS
// connection pool.
package core

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Default transport configuration values.
const (
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 10
	defaultMaxConnsPerHost     = 0 // unlimited
	defaultIdleConnTimeout     = 90 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
)

// Transport is a configured HTTP connection pool intended to be shared across
// all service sessions within an application. It wraps [http.Transport] and
// provides configurable pool sizes, timeouts, and keep-alive settings.
//
// Transport is safe for concurrent use from multiple goroutines — the
// underlying [http.Transport] guarantees this. Create one Transport per
// application and pass it to all service sessions.
type Transport struct {
	rt *http.Transport
}

// TransportOption configures a [Transport] at construction time.
type TransportOption func(*transportConfig)

type transportConfig struct {
	maxIdleConns        int
	maxIdleConnsPerHost int
	maxConnsPerHost     int
	idleConnTimeout     time.Duration
	tlsHandshakeTimeout time.Duration
	disableKeepAlives   bool
}

func defaultTransportConfig() *transportConfig {
	return &transportConfig{
		maxIdleConns:        defaultMaxIdleConns,
		maxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		maxConnsPerHost:     defaultMaxConnsPerHost,
		idleConnTimeout:     defaultIdleConnTimeout,
		tlsHandshakeTimeout: defaultTLSHandshakeTimeout,
		disableKeepAlives:   false,
	}
}

// WithMaxIdleConns sets the maximum number of idle (keep-alive) connections
// across all hosts. Zero means unlimited. Default: 100.
func WithMaxIdleConns(n int) TransportOption {
	return func(c *transportConfig) {
		c.maxIdleConns = n
	}
}

// WithMaxIdleConnsPerHost sets the maximum number of idle connections to keep
// per-host. Default: 10.
func WithMaxIdleConnsPerHost(n int) TransportOption {
	return func(c *transportConfig) {
		c.maxIdleConnsPerHost = n
	}
}

// WithMaxConnsPerHost limits the total number of connections per host,
// including connections in the dialing, active, and idle states. Zero means
// unlimited. Default: 0 (unlimited).
func WithMaxConnsPerHost(n int) TransportOption {
	return func(c *transportConfig) {
		c.maxConnsPerHost = n
	}
}

// WithIdleConnTimeout sets how long an idle connection remains in the pool
// before being closed. Default: 90s.
func WithIdleConnTimeout(d time.Duration) TransportOption {
	return func(c *transportConfig) {
		c.idleConnTimeout = d
	}
}

// WithTLSHandshakeTimeout sets the maximum time waiting for a TLS handshake
// to complete. Default: 10s.
func WithTLSHandshakeTimeout(d time.Duration) TransportOption {
	return func(c *transportConfig) {
		c.tlsHandshakeTimeout = d
	}
}

// WithDisableKeepAlives disables HTTP keep-alives when set to true. When
// disabled, each request uses a fresh connection. Default: false (keep-alive
// enabled).
func WithDisableKeepAlives(disable bool) TransportOption {
	return func(c *transportConfig) {
		c.disableKeepAlives = disable
	}
}

// NewTransport creates a shared [Transport] with the given options applied
// over sensible defaults. The returned Transport is safe for concurrent use
// and should be shared across all service sessions in the application.
func NewTransport(opts ...TransportOption) *Transport {
	cfg := defaultTransportConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	return &Transport{
		rt: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:        cfg.maxIdleConns,
			MaxIdleConnsPerHost: cfg.maxIdleConnsPerHost,
			MaxConnsPerHost:     cfg.maxConnsPerHost,
			IdleConnTimeout:     cfg.idleConnTimeout,
			TLSHandshakeTimeout: cfg.tlsHandshakeTimeout,
			DisableKeepAlives:   cfg.disableKeepAlives,
			ForceAttemptHTTP2:   true,
		},
	}
}

// RoundTripper returns the underlying [http.RoundTripper] for use by service
// sessions. The returned value is safe for concurrent use.
func (t *Transport) RoundTripper() http.RoundTripper {
	return t.rt
}
