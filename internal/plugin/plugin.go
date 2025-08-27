package plugin

import (
	"context"
	"net/url"
	"strings"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/util"
)

// Plugin evaluates a scan result and may return additional findings.
type Plugin interface {
	Name() string
	Evaluate(ctx context.Context, res *model.Result) []model.Finding
}

// Load returns plugin implementations for the provided comma separated list.
func Load(list string) []Plugin {
	var plugins []Plugin
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		switch name {
		case "", "none":
			// ignore
		case "final-ssrf", "ssrf":
			plugins = append(plugins, &finalSSRF{})
		}
	}
	return plugins
}

// finalSSRF checks if the final URL resolves to an internal host.
type finalSSRF struct{}

func (p *finalSSRF) Name() string { return "final-ssrf" }

func (p *finalSSRF) Evaluate(ctx context.Context, res *model.Result) []model.Finding {
	if len(res.Chain) == 0 {
		return nil
	}
	last := res.Chain[len(res.Chain)-1]
	u, err := url.Parse(last.URL)
	if err != nil {
		return nil
	}
	if util.IsInternalHost(u.Hostname()) {
		return []model.Finding{{Type: "FINAL_SSRF", Severity: "high", AtHop: last.Index, Detail: last.URL}}
	}
	return nil
}
