package output

import (
	"bufio"
	"fmt"
	"html"
	"io"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

// HTMLWriter creates a very simple HTML report for the provided results.
type HTMLWriter struct {
	w *bufio.Writer
}

// NewHTMLWriter returns a new writer instance.
func NewHTMLWriter(w io.Writer) *HTMLWriter {
	return &HTMLWriter{w: bufio.NewWriter(w)}
}

// WriteAll writes an entire report with all results.
func (h *HTMLWriter) WriteAll(results []model.Result) error {
	fmt.Fprintln(h.w, "<html><body>")
	for _, r := range results {
		fmt.Fprintf(h.w, "<h2>%s</h2>\n<ol>\n", html.EscapeString(r.Target))
		for _, hop := range r.Chain {
			fmt.Fprintf(h.w, "<li>%s %d via %s (%d ms)</li>\n", html.EscapeString(hop.URL), hop.Status, hop.Via, hop.TimeMs)
		}
		fmt.Fprintln(h.w, "</ol>")
		if len(r.Findings) > 0 {
			fmt.Fprintln(h.w, "<ul>")
			for _, f := range r.Findings {
				fmt.Fprintf(h.w, "<li><strong>%s</strong>: %s - %s</li>\n", html.EscapeString(f.Severity), html.EscapeString(f.Type), html.EscapeString(f.Detail))
			}
			fmt.Fprintln(h.w, "</ul>")
		}
	}
	fmt.Fprintln(h.w, "</body></html>")
	return h.w.Flush()
}
