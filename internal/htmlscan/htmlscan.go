package htmlscan

import (
	"io"
	"net/url"
	"regexp"
	"strings"
)

var (
	metaRefreshRe = regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*"refresh"[^>]*content\s*=\s*"\d+;\s*url=([^"'>]+)`)
	jsRedirectRe  = regexp.MustCompile(`(?i)(?:window\.|document\.)?location(?:\.href)?\s*=\s*['"]([^'"#]+)['"]`)
)

// ShouldFetchBody checks if content-type indicates HTML.
func ShouldFetchBody(ct string) bool {
	return strings.Contains(ct, "text/html")
}

// DetectRedirect inspects the body for meta refresh or JS redirects.
// It returns the next URL and the mechanism used.
func DetectRedirect(body []byte, base *url.URL) (next *url.URL, via string, ok bool) {
	if m := metaRefreshRe.FindSubmatch(body); m != nil {
		u, err := url.Parse(string(m[1]))
		if err == nil {
			return base.ResolveReference(u), "meta-refresh", true
		}
	}
	if m := jsRedirectRe.FindSubmatch(body); m != nil {
		u, err := url.Parse(string(m[1]))
		if err == nil {
			return base.ResolveReference(u), "js", true
		}
	}
	return nil, "", false
}

// ReadAndDetect reads from r up to limit and performs DetectRedirect.
func ReadAndDetect(r io.Reader, limit int64, base *url.URL) (next *url.URL, via string, body []byte, ok bool) {
	buf := make([]byte, limit)
	n, _ := io.ReadFull(io.LimitReader(r, limit), buf)
	buf = buf[:n]
	next, via, ok = DetectRedirect(buf, base)
	return next, via, buf, ok
}
