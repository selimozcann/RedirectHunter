package output_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/output"
)

func TestWriteJSONL(t *testing.T) {
	baseTime := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	res := model.Result{
		Target:  "https://example.com/start",
		Payload: "PAY",
		Chain: []model.Hop{
			{Index: 0, URL: "https://example.com/start", Method: "GET", Status: 302, Via: "http-location", TimeMs: 10, Size: 128},
			{Index: 1, URL: "https://example.com/end", Method: "GET", Status: 200, Via: "http-location", TimeMs: 25, Size: 456, Final: true},
		},
		Findings: []model.Finding{
			{Type: "CORE", AtHop: 0, Severity: "low", Detail: "core finding", Source: "core"},
			{Type: "PLUGIN", AtHop: 1, Severity: "high", Detail: "plugin finding", Source: "final-ssrf"},
		},
		PluginFindings: []model.Finding{{Type: "PLUGIN", AtHop: 1, Severity: "high", Detail: "plugin finding", Source: "final-ssrf"}},
		StartedAt:      baseTime,
		DurationMs:     123,
	}

	record := output.BuildRecord(res)
	var buf bytes.Buffer
	if err := output.WriteJSONL(&buf, []output.Record{record}); err != nil {
		t.Fatalf("WriteJSONL error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	var got output.Record
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("unexpected JSON decode error: %v", err)
	}
	if got.Type != output.ResultTypeUnredirect {
		t.Fatalf("expected type unredirect, got %q", got.Type)
	}
	if got.FinalURL != "https://example.com/end" {
		t.Fatalf("unexpected final URL: %s", got.FinalURL)
	}
	if len(got.RedirectChain) != 2 {
		t.Fatalf("expected redirect chain length 2, got %d", len(got.RedirectChain))
	}
}

func TestRenderHTML(t *testing.T) {
	baseTime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	res := model.Result{
		Target:  "https://example.com/start",
		Payload: "PAY",
		Chain: []model.Hop{
			{Index: 0, URL: "https://example.com/start", Method: "GET", Status: 302, Via: "http-location", TimeMs: 10, Size: 128},
			{Index: 1, URL: "https://example.com/end", Method: "GET", Status: 200, Via: "http-location", TimeMs: 25, Size: 456, Final: true},
		},
		Findings: []model.Finding{
			{Type: "CORE", AtHop: 0, Severity: "low", Detail: "core finding", Source: "core"},
			{Type: "PLUGIN", AtHop: 1, Severity: "high", Detail: "plugin finding", Source: "final-ssrf"},
		},
		PluginFindings: []model.Finding{{Type: "PLUGIN", AtHop: 1, Severity: "high", Detail: "plugin finding", Source: "final-ssrf"}},
		StartedAt:      baseTime,
		DurationMs:     123,
	}

	view := output.BuildResultView(0, res)
	page := output.PageData{
		Title:       "Test Report",
		GeneratedAt: baseTime,
		Params: map[string]string{
			"threads": "10",
			"target":  "https://example.com/start",
		},
		Summary: output.Summary{TotalTargets: 1, WithFindings: 1, PluginFindings: 1, Errors: 0},
		Results: []output.ResultView{view},
	}

	var buf bytes.Buffer
	if err := output.RenderHTML(&buf, page); err != nil {
		t.Fatalf("RenderHTML error: %v", err)
	}
	html := buf.String()

	mustContain := []string{
		"Test Report",
		"Targets with Findings",
		"data-filter=\"plugin\"",
		"https://example.com/start",
		"Status 200",
		"<strong>Plugin Findings</strong>",
	}
	for _, sub := range mustContain {
		if !strings.Contains(html, sub) {
			t.Fatalf("expected HTML to contain %q", sub)
		}
	}

	idxTarget := strings.Index(html, "<dt>target</dt>")
	idxThreads := strings.Index(html, "<dt>threads</dt>")
	if idxTarget == -1 || idxThreads == -1 {
		t.Fatalf("expected parameters to render")
	}
	if idxTarget > idxThreads {
		t.Fatalf("expected parameters to be sorted alphabetically")
	}
}
