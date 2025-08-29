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

// headerRoundTripper wraps a base RoundTripper to inject headers/cookies and
// perform simple retry logic.
type headerRoundTripper struct {
	base    http.RoundTripper
	headers http.Header
	cookie  string
	retries int
}

func (h *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if h.base == nil {
		h.base = http.DefaultTransport
	}

	var resp *http.Response
	var err error

	for attempt := 0; ; attempt++ {
		// Clone the request to avoid mutations across retries
		r := req.Clone(req.Context())
		if req.Body != nil {
			if req.GetBody != nil {
				if body, berr := req.GetBody(); berr == nil {
					r.Body = body
				}
			} else {
				r.Body = req.Body
			}
		}

		// Inject headers and cookies
		for k, vs := range h.headers {
			r.Header.Del(k)
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		if h.cookie != "" {
			r.Header.Set("Cookie", h.cookie)
		}

		resp, err = h.base.RoundTrip(r)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}

		if attempt >= h.retries {
			if err != nil {
				return nil, err
			}
			return resp, nil
		}

		if resp != nil {
			_ = resp.Body.Close()
		}
		time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
	}
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
		Transport: &headerRoundTripper{
			base:    transport,
			headers: cfg.Headers,
			cookie:  cfg.Cookie,
			retries: cfg.Retries,
		},
		Timeout: cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// prevent automatic redirects
			return http.ErrUseLastResponse
		},
	}
	return client
}
