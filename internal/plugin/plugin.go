package plugin

import (
	"context"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// Plugin analyses a scan result and returns additional risks.
type Plugin interface {
	Name() string
	Evaluate(ctx context.Context, res *model.Result) []model.Risk
}

// Default returns the built-in plugins.
func Default() []Plugin {
	return []Plugin{&SSRFPlugin{}, &PhishingPlugin{}}
}
