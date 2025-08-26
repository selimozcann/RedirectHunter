package util

import (
	"net/url"
	"strings"
)

// ETLDPlusOne returns the eTLD+1 for the URL host.
func ETLDPlusOne(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
