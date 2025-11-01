package util

import (
	"net"
	"net/url"
	"strings"
)

// ETLDPlusOne returns the eTLD+1 for the URL host. It trims known multi-label
// public suffixes using a lightweight heuristic so that subdomains (including
// www-prefixed variants) collapse to the same base domain.
func ETLDPlusOne(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	// Handle common multi-label public suffixes (e.g. example.co.uk).
	suffix := strings.Join(parts[len(parts)-2:], ".")
	secondLevel := parts[len(parts)-2]
	if len(parts) >= 3 {
		last := parts[len(parts)-1]
		candidate := secondLevel + "." + last
		switch candidate {
		case "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "com.au", "net.au", "org.au", "co.jp", "com.br", "com.mx":
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return suffix
}

// BaseDomainFromString parses the provided URL string and returns the base
// domain (eTLD+1). When the URL cannot be parsed or does not contain a host it
// returns an empty string.
func BaseDomainFromString(raw string) string {
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return ETLDPlusOne(parsed)
}

// SameBaseDomain reports whether the two URLs share the same base domain. If
// either cannot be parsed or lacks a host, it returns false.
func SameBaseDomain(a, b string) bool {
	da := BaseDomainFromString(a)
	db := BaseDomainFromString(b)
	if da == "" || db == "" {
		return false
	}
	return da == db
}
