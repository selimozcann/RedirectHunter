package plugin

import (
	"context"
	"net/url"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/util"
)

// SSRFPlugin checks the final URL for internal hosts.
type SSRFPlugin struct{}

func (p *SSRFPlugin) Name() string { return "ssrf-final" }

func (p *SSRFPlugin) Evaluate(ctx context.Context, res *model.Result) []model.Risk {
	if len(res.Chain) == 0 {
		return nil
	}
	u, err := url.Parse(res.Chain[len(res.Chain)-1].URL)
	if err != nil {
		return nil
	}
	if util.IsInternalHost(u.Hostname()) {
		return []model.Risk{{Type: "SSRF_FINAL", Severity: "high", Detail: u.String(), AtHop: len(res.Chain) - 1}}
	}
	return nil
}
