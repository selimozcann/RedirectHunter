package detect

import (
	"net/url"
	"strings"

	"redirecthunter/internal/model"
	"redirecthunter/internal/util"
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
		return &model.Finding{Type: "SSRF", Severity: "high", AtHop: hop, Detail: u.Host}
	}
	return nil
}

// HTTPSDowngrade reports if the scheme changed from https to http.
func HTTPSDowngrade(prev, next *url.URL, hop int) *model.Finding {
	if prev.Scheme == "https" && next.Scheme == "http" {
		return &model.Finding{Type: "HTTPS_DOWNGRADE", Severity: "medium", AtHop: hop, Detail: prev.String() + " -> " + next.String()}
	}
	return nil
}

// TokenLeakage detects sensitive tokens in query or fragment.
func TokenLeakage(u *url.URL, hop int) *model.Finding {
	q := u.Query()
	for k := range q {
		if tokenKeys[strings.ToLower(k)] {
			return &model.Finding{Type: "TOKEN_LEAK", Severity: "medium", AtHop: hop, Detail: k + " in query"}
		}
	}
	if frag := u.Fragment; frag != "" {
		for _, part := range strings.Split(frag, "&") {
			kv := strings.SplitN(part, "=", 2)
			if tokenKeys[strings.ToLower(kv[0])] {
				return &model.Finding{Type: "TOKEN_LEAK", Severity: "high", AtHop: hop, Detail: kv[0] + " in fragment"}
			}
		}
	}
	return nil
}
