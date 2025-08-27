package report

import (
	"html/template"
	"os"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// WriteHTML generates a basic HTML report for the given results.
func WriteHTML(path string, results []model.Result) error {
	const tpl = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>RedirectHunter Report</title></head><body>{{range .}}<h2>{{.Target}}</h2><ul>{{range .Chain}}<li>{{.Status}} {{.URL}}</li>{{end}}</ul>{{if .Risks}}<h3>Risks</h3><ul>{{range .Risks}}<li>{{.Severity}} {{.Type}} - {{.Detail}}</li>{{end}}</ul>{{end}}{{end}}</body></html>`
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	t := template.Must(template.New("rep").Parse(tpl))
	return t.Execute(f, results)
}
