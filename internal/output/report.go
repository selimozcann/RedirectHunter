package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/util"
)

// ResultType enumerates the classification of a redirect chain.
type ResultType string

const (
	ResultTypeUnknown    ResultType = "unknown"
	ResultTypeRedirect   ResultType = "open_redirect"
	ResultTypeUnredirect ResultType = "unredirect"
	ResultTypeOK         ResultType = "ok"
	ResultTypeError      ResultType = "error"
)

// Record represents one line in the JSONL report.
type Record struct {
	Timestamp      string          `json:"timestamp"`
	InputURL       string          `json:"input_url"`
	Payload        string          `json:"payload,omitempty"`
	FinalURL       string          `json:"final_url"`
	Type           ResultType      `json:"type"`
	RedirectChain  []string        `json:"redirect_chain"`
	StatusCode     int             `json:"status_code"`
	RespLen        int64           `json:"resp_len"`
	DurationMs     int64           `json:"duration_ms"`
	Findings       []model.Finding `json:"findings,omitempty"`
	PluginFindings []model.Finding `json:"plugin_findings,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// Summary contains counters for the HTML summary section.
type Summary struct {
	TotalTargets   int
	WithFindings   int
	PluginFindings int
	Errors         int
}

// ResultView is used by the HTML template with pre-computed fields.
type ResultView struct {
	Index          int
	Timestamp      time.Time
	InputURL       string
	Payload        string
	FinalURL       string
	Type           ResultType
	StatusCode     int
	RespLen        int64
	DurationMs     int64
	Findings       []model.Finding
	PluginFindings []model.Finding
	Chain          []model.Hop
	Error          string
}

// PageData provides the full context for the HTML report.
type PageData struct {
	Title         string
	GeneratedAt   time.Time
	Params        map[string]string
	OrderedParams []Param
	Summary       Summary
	Results       []ResultView
}

// Param represents a rendered CLI argument/value pair.
type Param struct {
	Key   string
	Value string
}

// BuildRecord converts a model.Result into a Record for JSONL output.
func BuildRecord(res model.Result) Record {
	finalURL := res.Target
	status := 0
	respLen := int64(0)
	chainStrings := make([]string, len(res.Chain))
	if len(res.Chain) > 0 {
		last := res.Chain[len(res.Chain)-1]
		finalURL = last.URL
		status = last.Status
		respLen = last.Size
	}
	for i, hop := range res.Chain {
		chainStrings[i] = hop.URL
	}
	return Record{
		Timestamp:      res.StartedAt.UTC().Format(time.RFC3339),
		InputURL:       res.Target,
		Payload:        res.Payload,
		FinalURL:       finalURL,
		Type:           DetermineType(res),
		RedirectChain:  chainStrings,
		StatusCode:     status,
		RespLen:        respLen,
		DurationMs:     res.DurationMs,
		Findings:       append([]model.Finding(nil), res.Findings...),
		PluginFindings: append([]model.Finding(nil), res.PluginFindings...),
		Error:          res.Error,
	}
}

// BuildResultView converts a model.Result into a ResultView for HTML rendering.
func BuildResultView(idx int, res model.Result) ResultView {
	finalURL := res.Target
	status := 0
	respLen := int64(0)
	if len(res.Chain) > 0 {
		last := res.Chain[len(res.Chain)-1]
		finalURL = last.URL
		status = last.Status
		respLen = last.Size
	}
	return ResultView{
		Index:          idx,
		Timestamp:      res.StartedAt,
		InputURL:       res.Target,
		Payload:        res.Payload,
		FinalURL:       finalURL,
		Type:           DetermineType(res),
		StatusCode:     status,
		RespLen:        respLen,
		DurationMs:     res.DurationMs,
		Findings:       append([]model.Finding(nil), res.Findings...),
		PluginFindings: append([]model.Finding(nil), res.PluginFindings...),
		Chain:          append([]model.Hop(nil), res.Chain...),
		Error:          res.Error,
	}
}

// BuildSummary derives high level counters from the results.
func BuildSummary(results []model.Result) Summary {
	sum := Summary{TotalTargets: len(results)}
	for _, res := range results {
		if len(res.Findings) > 0 || len(res.PluginFindings) > 0 {
			sum.WithFindings++
		}
		sum.PluginFindings += len(res.PluginFindings)
		if res.Error != "" {
			sum.Errors++
		}
	}
	return sum
}

// DetermineType classifies the given result into one of the ResultType values.
func DetermineType(res model.Result) ResultType {
	finalURL := res.Target
	finalStatus := 0
	if len(res.Chain) > 0 {
		last := res.Chain[len(res.Chain)-1]
		finalURL = last.URL
		finalStatus = last.Status
	}
	if res.Error != "" {
		return ResultTypeError
	}
	if hasRedirectHop(res.Chain) {
		if has302To200(res.Chain) || !util.SameBaseDomain(res.Target, finalURL) {
			return ResultTypeRedirect
		}
		if util.SameBaseDomain(res.Target, finalURL) {
			return ResultTypeUnredirect
		}
		return ResultTypeRedirect
	}
	switch {
	case finalStatus == http.StatusOK:
		return ResultTypeOK
	case finalStatus == 0:
		return ResultTypeUnknown
	case finalStatus >= 400:
		return ResultTypeError
	default:
		return ResultTypeOK
	}
}

func hasRedirectHop(chain []model.Hop) bool {
	for _, hop := range chain {
		if hop.Status >= 300 && hop.Status < 400 {
			return true
		}
	}
	return false
}

func has302To200(chain []model.Hop) bool {
	for i := 0; i < len(chain)-1; i++ {
		if chain[i].Status == http.StatusFound && chain[i+1].Status == http.StatusOK {
			return true
		}
	}
	return false
}

// WriteJSONL writes each record as a JSON line to w.
func WriteJSONL(w io.Writer, records []Record) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return bw.Flush()
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"join":       strings.Join,
	"formatHop": func(h model.Hop) string {
		return fmt.Sprintf("%s (%d) via %s", h.URL, h.Status, h.Via)
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root { color-scheme: light dark; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; background:#fafafa; color:#111; }
header { margin-bottom: 24px; }
h1 { font-size: 26px; margin: 0 0 8px; }
.section { border:1px solid #e5e7eb; border-radius:16px; padding:16px 20px; margin-bottom:18px; background:#fff; box-shadow:0 1px 2px rgba(15,23,42,0.08); }
h2 { font-size:20px; margin:0 0 12px; }
h3 { font-size:16px; margin:12px 0 6px; }
dt { font-weight:600; }
dd { margin:0 0 8px 0; }
.summary-grid { display:grid; gap:12px; grid-template-columns: repeat(auto-fit,minmax(180px,1fr)); }
.summary-card { display:block; padding:12px; border-radius:12px; border:1px solid #cbd5f5; text-decoration:none; color:inherit; position:relative; transition:box-shadow .2s ease; background:linear-gradient(180deg,#eef2ff,#fff); }
.summary-card:hover { box-shadow:0 8px 16px rgba(79,70,229,0.2); }
.summary-card[data-active="true"] { border-color:#4f46e5; box-shadow:0 0 0 2px rgba(79,70,229,0.4); }
.summary-card .badge { position:absolute; top:12px; right:12px; padding:2px 10px; border-radius:999px; background:#4f46e5; color:#fff; font-size:12px; }
.meta { color:#6b7280; font-size:12px; }
.finding-row { border-top:1px solid #e5e7eb; padding-top:12px; margin-top:12px; }
.finding-row:first-of-type { border-top:none; padding-top:0; margin-top:0; }
.finding-list { list-style:disc; margin:8px 0 8px 20px; }
.badge-inline { display:inline-block; padding:2px 8px; border-radius:999px; background:#e5e7eb; font-size:12px; margin-left:6px; }
.table { width:100%; border-collapse:collapse; font-size:14px; }
.table th, .table td { border-bottom:1px solid #e5e7eb; padding:6px 8px; text-align:left; }
.table th { background:#f9fafb; }
.chain-url { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:13px; }
.chain-meta { color:#6b7280; font-size:12px; }
.footer { text-align:center; font-size:12px; color:#6b7280; margin-top:24px; }
@media (prefers-color-scheme: dark) {
        body { background:#0f172a; color:#e2e8f0; }
        .section { background:#1e293b; border-color:#334155; box-shadow:none; }
        .summary-card { background:linear-gradient(180deg,#312e81,#1e293b); border-color:#4338ca; color:#e0e7ff; }
        .summary-card .badge { background:#a855f7; }
        .meta { color:#94a3b8; }
        .table th { background:#1e293b; }
        .chain-meta { color:#94a3b8; }
        .badge-inline { background:#475569; }
}
</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
  const cards = document.querySelectorAll('[data-filter]');
  const rows = document.querySelectorAll('.finding-row');
  const notice = document.getElementById('filterNotice');
  function apply(filter) {
    cards.forEach(c => c.dataset.active = (c.dataset.filter === filter ? 'true' : 'false'));
    rows.forEach(row => {
      const hasCore = Number(row.dataset.core);
      const hasPlugin = Number(row.dataset.plugin);
      const hasError = Number(row.dataset.error);
      let show = true;
      let text = 'Showing all targets.';
      switch(filter) {
        case 'core':
          show = hasCore > 0;
          text = 'Filtered to targets with core findings.';
          break;
        case 'plugin':
          show = hasPlugin > 0;
          text = 'Filtered to targets with plugin findings.';
          break;
        case 'errors':
          show = hasError > 0;
          text = 'Filtered to targets with errors only.';
          break;
        default:
          show = true;
      }
      if (show) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
      if (notice) {
        notice.textContent = text;
      }
    });
  }
  cards.forEach(card => {
    card.addEventListener('click', function (ev) {
      ev.preventDefault();
      apply(card.dataset.filter || 'all');
      const target = card.getAttribute('href');
      if (target) {
        const el = document.querySelector(target);
        if (el) {
          el.scrollIntoView({behavior: 'smooth'});
        }
      }
    });
  });
  apply('all');
});
</script>
</head>
<body>
<header>
  <h1>{{.Title}}</h1>
  <p class="meta">Generated at {{formatTime .GeneratedAt}}</p>
</header>
<section id="summary" class="section">
  <h2>Summary</h2>
  <div class="summary-grid">
    <a class="summary-card" href="#chains" data-filter="all"><strong>Total Targets</strong><span class="badge">{{.Summary.TotalTargets}}</span></a>
    <a class="summary-card" href="#findings" data-filter="core"><strong>Targets with Findings</strong><span class="badge">{{.Summary.WithFindings}}</span></a>
    <a class="summary-card" href="#plugin-findings" data-filter="plugin"><strong>Plugin Findings</strong><span class="badge">{{.Summary.PluginFindings}}</span></a>
    <a class="summary-card" href="#findings" data-filter="errors"><strong>Errors</strong><span class="badge">{{.Summary.Errors}}</span></a>
  </div>
</section>
<section id="parameters" class="section">
  <h2>Parameters</h2>
  <dl>
  {{- range .OrderedParams }}
    <dt>{{.Key}}</dt>
    <dd><span class="chain-url">{{.Value}}</span></dd>
  {{- end }}
  </dl>
</section>
<section id="findings" class="section">
  <h2>Findings</h2>
  <p class="meta" id="filterNotice">Showing all targets.</p>
  {{range .Results}}
  <div class="finding-row" data-core="{{len .Findings}}" data-plugin="{{len .PluginFindings}}" data-error="{{if .Error}}1{{else}}0{{end}}">
    <h3>{{.InputURL}}<span class="badge-inline">Status {{.StatusCode}}</span></h3>
    {{if .Payload}}<p class="meta">Payload: <span class="chain-url">{{.Payload}}</span></p>{{end}}
    {{if .Error}}
      <p class="meta">Error: {{.Error}}</p>
    {{end}}
    {{if .Findings}}
      <p><strong>Core Findings</strong></p>
      <ul class="finding-list">
        {{range .Findings}}
          <li><strong>{{.Severity}}</strong>: {{.Type}} — {{.Detail}}</li>
        {{end}}
      </ul>
    {{end}}
    {{if .PluginFindings}}
      <p><strong>Plugin Findings</strong></p>
      <ul class="finding-list">
        {{range .PluginFindings}}
          <li><strong>{{.Severity}}</strong>: {{.Type}} — {{.Detail}} <span class="meta">{{.Source}}</span></li>
        {{end}}
      </ul>
    {{end}}
    <p class="meta">Duration {{.DurationMs}}ms • Response {{.RespLen}} bytes • Started {{formatTime .Timestamp}}</p>
  </div>
  {{end}}
</section>
<section id="chains" class="section">
  <h2>Redirect Chains</h2>
  {{range .Results}}
    <details open>
      <summary>{{.InputURL}} → {{.FinalURL}} <span class="meta">{{len .Chain}} hops</span></summary>
      <table class="table">
        <thead>
          <tr><th>#</th><th>URL</th><th>Method</th><th>Status</th><th>Via</th><th>Time (ms)</th><th>Size</th></tr>
        </thead>
        <tbody>
        {{range .Chain}}
          <tr>
            <td>{{.Index}}</td>
            <td class="chain-url">{{.URL}}</td>
            <td>{{.Method}}</td>
            <td>{{.Status}}</td>
            <td>{{.Via}}</td>
            <td>{{.TimeMs}}</td>
            <td>{{.Size}}</td>
          </tr>
        {{end}}
        </tbody>
      </table>
    </details>
  {{end}}
</section>
<section id="plugin-findings" class="section">
  <h2>Plugin Findings</h2>
  {{if eq .Summary.PluginFindings 0}}
    <p class="meta">No plugin findings recorded.</p>
  {{else}}
    <ul class="finding-list">
    {{range .Results}}
      {{- $res := . -}}
      {{range .PluginFindings}}
        <li><span class="chain-url">{{$res.InputURL}}</span> — <strong>{{.Severity}}</strong> {{.Type}} ({{.Source}}) — {{.Detail}}</li>
      {{end}}
    {{end}}
    </ul>
  {{end}}
</section>
<footer class="footer">
  RedirectHunter report generated at {{formatTime .GeneratedAt}}
</footer>
</body>
</html>
`))

// RenderHTML renders the HTML report using the provided data.
func RenderHTML(w io.Writer, data PageData) error {
	if data.Params != nil {
		keys := make([]string, 0, len(data.Params))
		for k := range data.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make([]Param, 0, len(keys))
		for _, k := range keys {
			ordered = append(ordered, Param{Key: k, Value: data.Params[k]})
		}
		data.OrderedParams = ordered
	}
	return htmlTemplate.Execute(w, data)
}
