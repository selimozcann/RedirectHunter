package output

import (
	"bufio"
	"fmt"
	"html"
	"io"
	"strings"
	"sync"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// HTMLWriter streams a simple HTML report.
type HTMLWriter struct {
	w       *bufio.Writer
	started bool
	closed  bool
	mu      sync.Mutex
}

// NewHTMLWriter returns a new streaming HTML writer.
func NewHTMLWriter(w io.Writer) *HTMLWriter {
	return &HTMLWriter{w: bufio.NewWriter(w)}
}

// Begin writes the HTML header once.
func (h *HTMLWriter) Begin(title string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.started {
		return nil
	}
	h.started = true
	_, err := fmt.Fprintf(h.w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>%s</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;}
h1{font-size:22px;margin:0 0 16px;}
h2{font-size:18px;margin:24px 0 8px;}
ol{margin:8px 0 8px 24px;}
ul{margin:8px 0 8px 24px;}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#eee;margin-left:8px;font-size:12px;}
.finding-low{color:#1f6feb}.finding-medium{color:#b45309}.finding-high{color:#b91c1c}
.section{border:1px solid #eee;border-radius:12px;padding:12px 16px;margin-bottom:14px;}
.meta{color:#666;font-size:12px;margin-left:8px}
.code{font-family:ui-monospace,Menlo,Consolas,monospace}
</style>
</head>
<body>
<h1>%s</h1>
`, html.EscapeString(title), html.EscapeString(title))
	return err
}

// Write one result section.
func (h *HTMLWriter) Write(r model.Result) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.started {
		if _, err := fmt.Fprintln(h.w, "<!doctype html><html><body>"); err != nil {
			return err
		}
		h.started = true
	}

	// Header per target
	if _, err := fmt.Fprintf(h.w, `<div class="section">
<h2 class="code">%s</h2>
<ol>
`, html.EscapeString(r.Target)); err != nil {
		return err
	}

	// Redirect chain
	for _, hop := range r.Chain {
		_, err := fmt.Fprintf(
			h.w,
			`<li><span class="code">%s</span> <span class="meta">status %d • via %s • %d ms</span></li>
`,
			html.EscapeString(hop.URL),
			hop.Status,
			html.EscapeString(hop.Via),
			hop.TimeMs,
		)
		if err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(h.w, "</ol>"); err != nil {
		return err
	}

	// Findings, if any
	if len(r.Findings) > 0 {
		if _, err := fmt.Fprintln(h.w, "<ul>"); err != nil {
			return err
		}
		for _, f := range r.Findings {
			severityClass := "finding-low"
			switch strings.ToLower(f.Severity) {
			case "medium":
				severityClass = "finding-medium"
			case "high", "critical":
				severityClass = "finding-high"
			}
			_, err := fmt.Fprintf(
				h.w,
				`<li><strong class="%s">%s</strong>: %s <span class="meta">— %s</span></li>
`,
				severityClass,
				html.EscapeString(f.Severity),
				html.EscapeString(f.Type),
				html.EscapeString(f.Detail),
			)
			if err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(h.w, "</ul>"); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintln(h.w, "</div>")
	return err
}

// Flush buffered HTML to the underlying writer.
func (h *HTMLWriter) Flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.w.Flush()
}

// Close writes the closing tags (once) and flushes.
func (h *HTMLWriter) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if !h.started {
		if _, err := fmt.Fprintln(h.w, "<!doctype html><html><body>"); err != nil {
			return err
		}
		h.started = true
	}
	if _, err := fmt.Fprintln(h.w, "</body></html>"); err != nil {
		return err
	}
	return h.w.Flush()
}
