package httpclient

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Config holds settings for the HTTP client.
type Config struct {
	Timeout  time.Duration
	Proxy    func(*http.Request) (*url.URL, error)
	Headers  http.Header
	Cookie   string
	Insecure bool
	Retries  int
}

// New returns a configured HTTP client with manual redirect handling.
func New(cfg Config) *http.Client {
	transport := &http.Transport{
		Proxy:           cfg.Proxy,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// prevent automatic redirects
			return http.ErrUseLastResponse
		},
	}
	return client
}
