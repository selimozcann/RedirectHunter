package trace

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/detect"
	"github.com/selimozcann/RedirectHunter/internal/htmlscan"
	"github.com/selimozcann/RedirectHunter/internal/model"
)

// Tracer performs manual redirect tracing.
type Tracer struct {
	Client *http.Client
}

// New creates a new Tracer.
func New(c *http.Client) *Tracer { return &Tracer{Client: c} }

// Trace follows redirects starting from target.
func (t *Tracer) Trace(ctx context.Context, target string, maxChain int, jsScan bool) model.Result {
	res := model.Result{Target: target, StartedAt: time.Now()}
	current := target
	seen := make(map[string]struct{})
	var prevURL *url.URL

	for i := 0; i < maxChain; i++ {
		if _, ok := seen[current]; ok {
			res.Findings = append(res.Findings, model.Finding{Type: "CHAIN_LOOP", Severity: "info", AtHop: i, Detail: current})
			break
		}
		seen[current] = struct{}{}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if err != nil {
			res.Error = err.Error()
			break
		}
		start := time.Now()
		resp, err := t.Client.Do(req)
		duration := time.Since(start).Milliseconds()
		if err != nil {
			res.Error = err.Error()
			break
		}

		size := resp.ContentLength
		if size < 0 {
			size = 0
		}
		hop := model.Hop{Index: i, URL: current, Method: req.Method, Status: resp.StatusCode, Via: "http-location", TimeMs: duration, Size: size}
		u := resp.Request.URL

		if f := detect.SSRF(u, i); f != nil {
			res.Findings = append(res.Findings, *f)
		}
		if f := detect.TokenLeakage(u, i); f != nil {
			res.Findings = append(res.Findings, *f)
		}
		if prevURL != nil {
			if f := detect.HTTPSDowngrade(prevURL, u, i); f != nil {
				res.Findings = append(res.Findings, *f)
			}
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			_ = resp.Body.Close()
			if loc == "" {
				hop.Final = true
				res.Chain = append(res.Chain, hop)
				break
			}
			nextURL, err := url.Parse(loc)
			if err != nil {
				hop.Final = true
				res.Chain = append(res.Chain, hop)
				break
			}
			hop.Final = false
			res.Chain = append(res.Chain, hop)
			prevURL = u
			current = u.ResolveReference(nextURL).String()
			continue
		}

		// Non-redirect
		ct := resp.Header.Get("Content-Type")
		if htmlscan.ShouldFetchBody(ct) {
			next, via, body, ok := htmlscan.ReadAndDetect(resp.Body, 512*1024, u)
			hop.Size = int64(len(body))
			_ = resp.Body.Close()
			if f := detect.PhishingIndicators(body, i); f != nil {
				res.Findings = append(res.Findings, *f)
			}
			if jsScan && ok {
				hop.Final = false
				res.Chain = append(res.Chain, hop)
				// synthetic hop for client-side redirect
				i++
				if i >= maxChain {
					res.Findings = append(res.Findings, model.Finding{Type: "CHAIN_TOO_LONG", Severity: "info", AtHop: i})
					break
				}
				current = next.String()
				res.Chain = append(res.Chain, model.Hop{Index: i, URL: current, Method: http.MethodGet, Status: 0, Via: via, Size: int64(len(body))})
				prevURL = u
				if f := detect.TokenLeakage(next, i); f != nil {
					res.Findings = append(res.Findings, *f)
				}
				if f := detect.SSRF(next, i); f != nil {
					res.Findings = append(res.Findings, *f)
				}
				continue
			}
			hop.Final = true
			res.Chain = append(res.Chain, hop)
		} else {
			_ = resp.Body.Close()
			if resp.ContentLength >= 0 {
				hop.Size = resp.ContentLength
			}
			hop.Final = true
			res.Chain = append(res.Chain, hop)
		}
		break
	}

	if len(res.Chain) >= maxChain {
		res.Findings = append(res.Findings, model.Finding{Type: "CHAIN_TOO_LONG", Severity: "info", AtHop: maxChain})
	}
	res.DurationMs = time.Since(res.StartedAt).Milliseconds()
	return res
}
