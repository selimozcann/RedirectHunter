package detect

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/util"
)

var tokenKeys = map[string]bool{
	"token":        true,
	"access_token": true,
	"id_token":     true,
	"code":         true,
	"session":      true,
	"bearer":       true,
}

// SSRF checks whether the URL points to an internal host.
func SSRF(u *url.URL, hop int) *model.Finding {
	if util.IsInternalHost(u.Hostname()) {
		return &model.Finding{Type: "SSRF", Severity: "high", AtHop: hop, Detail: u.Host, Source: "core"}
	}
	return nil
}

// HTTPSDowngrade reports if the scheme changed from https to http.
func HTTPSDowngrade(prev, next *url.URL, hop int) *model.Finding {
	if prev.Scheme == "https" && next.Scheme == "http" {
		return &model.Finding{Type: "HTTPS_DOWNGRADE", Severity: "medium", AtHop: hop, Detail: prev.String() + " -> " + next.String(), Source: "core"}
	}
	return nil
}

// TokenLeakage detects sensitive tokens in query or fragment.
func TokenLeakage(u *url.URL, hop int) *model.Finding {
	q := u.Query()
	for k := range q {
		if tokenKeys[strings.ToLower(k)] {
			return &model.Finding{Type: "TOKEN_LEAK", Severity: "medium", AtHop: hop, Detail: k + " in query", Source: "core"}
		}
	}
	if frag := u.Fragment; frag != "" {
		for _, part := range strings.Split(frag, "&") {
			kv := strings.SplitN(part, "=", 2)
			if tokenKeys[strings.ToLower(kv[0])] {
				return &model.Finding{Type: "TOKEN_LEAK", Severity: "high", AtHop: hop, Detail: kv[0] + " in fragment", Source: "core"}
			}
		}
	}
	return nil
}

// PhishingIndicators performs a very small heuristic scan of the HTML body for
// common phishing artefacts such as forms and password fields.
func PhishingIndicators(body []byte, hop int) *model.Finding {
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte("<form")) && bytes.Contains(lower, []byte("password")) {
		return &model.Finding{Type: "PHISHING_INDICATOR", Severity: "high", AtHop: hop, Detail: "form with password field", Source: "core"}

	}
	isLowSeverity := bytes.Contains(lower, []byte("document.forms")) || bytes.Contains(lower, []byte("eval(")) || bytes.Contains(lower, []byte("username"))
	if isLowSeverity {
		return &model.Finding{Type: "PHISHING_INDICATOR", Severity: "low", AtHop: hop, Detail: "suspicious javascript", Source: "core"}
	}
	return nil
}
