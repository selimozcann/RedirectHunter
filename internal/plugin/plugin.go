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

var registry = map[string]func() Plugin{
	"final-ssrf": func() Plugin { return &finalSSRF{} },
}

// Load returns plugin implementations for the provided comma separated list.
func Load(list string) []Plugin {
	plugins, _ := LoadWithWarnings(list)
	return plugins
}

// LoadWithWarnings returns plugins along with unknown names that were ignored.
func LoadWithWarnings(list string) ([]Plugin, []string) {
	var (
		plugins []Plugin
		unknown []string
	)
	seen := make(map[string]bool)
	for _, name := range strings.Split(list, ",") {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" || strings.EqualFold(trimmed, "none") {
			continue
		}
		key := strings.ToLower(trimmed)
		if key == "ssrf" {
			key = "final-ssrf"
		}
		factory, ok := registry[key]
		if !ok {
			unknown = append(unknown, trimmed)
			continue
		}
		if seen[key] {
			continue
		}
		plugins = append(plugins, factory())
		seen[key] = true
	}
	return plugins, unknown
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
		return []model.Finding{{Type: "FINAL_SSRF", Severity: "high", AtHop: last.Index, Detail: last.URL, Source: p.Name()}}
	}
	return nil
}
