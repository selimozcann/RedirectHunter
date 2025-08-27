package plugin

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// PhishingPlugin looks for simple phishing indicators on the landing page.
type PhishingPlugin struct{}

func (p *PhishingPlugin) Name() string { return "phishing" }

func (p *PhishingPlugin) Evaluate(ctx context.Context, res *model.Result) []model.Risk {
	if len(res.Chain) == 0 {
		return nil
	}
	url := res.Chain[len(res.Chain)-1].URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	body := strings.ToLower(string(buf[:n]))
	var risks []model.Risk
	if strings.Contains(body, "<form") {
		risks = append(risks, model.Risk{Type: "PHISHING_FORM", Severity: "medium", Detail: url, AtHop: len(res.Chain) - 1})
	}
	if strings.Contains(body, "eval(") {
		risks = append(risks, model.Risk{Type: "PHISHING_EVAL", Severity: "low", Detail: url, AtHop: len(res.Chain) - 1})
	}
	return risks
}
