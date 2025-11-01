package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/banner"
	"github.com/selimozcann/RedirectHunter/internal/httpclient"
	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/output"
	"github.com/selimozcann/RedirectHunter/internal/plugin"
	"github.com/selimozcann/RedirectHunter/internal/runner"
	"github.com/selimozcann/RedirectHunter/internal/statuscolor"
	"github.com/selimozcann/RedirectHunter/internal/trace"
)

type headerList []string

type options struct {
	url         string
	wordlist    string
	cookie      string
	headers     headerList
	proxy       string
	timeout     time.Duration
	retries     int
	threads     int
	rateLimit   int
	maxChain    int
	jsScan      bool
	insecure    bool
	verbose     bool
	silent      bool
	summary     bool
	onlyRisky   bool
	plugins     string
	outputJSONL string
	outputHTML  string
}

type summaryRow struct {
	View           output.ResultView
	CoreFindings   int
	PluginFindings int
	Error          string
}

func main() {
	opts := parseFlags()
	banner.PrintBanner()
	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	var opts options
	flag.StringVar(&opts.url, "u", "", "Target URL (supports FUZZ)")
	flag.StringVar(&opts.wordlist, "w", "", "Wordlist file (used when FUZZ is in URL)")
	flag.StringVar(&opts.cookie, "cookie", "", "Cookie header")
	flag.Var(&opts.headers, "H", "Extra HTTP header (repeatable)")
	flag.StringVar(&opts.proxy, "proxy", "", "HTTP(S) proxy URL")
	flag.DurationVar(&opts.timeout, "timeout", 8*time.Second, "Per-target timeout")
	flag.IntVar(&opts.retries, "retries", 1, "Retry count")
	flag.IntVar(&opts.threads, "t", 10, "Threads")
	flag.IntVar(&opts.rateLimit, "rl", 0, "Global rate limit (requests per second)")
	flag.IntVar(&opts.maxChain, "max-chain", 15, "Max redirect hops including JS/meta")
	flag.BoolVar(&opts.jsScan, "js-scan", true, "Enable JS/meta redirect detection")
	flag.BoolVar(&opts.insecure, "insecure", false, "Skip TLS verification")
	flag.BoolVar(&opts.verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&opts.silent, "silent", false, "Suppress chain output")
	flag.BoolVar(&opts.summary, "summary", false, "Show one-line summary per target")
	flag.BoolVar(&opts.onlyRisky, "only-risky", false, "Only output results with findings")
	flag.StringVar(&opts.plugins, "plugins", "final-ssrf", "Plugins to enable (comma-separated)")
	flag.StringVar(&opts.outputJSONL, "o", "out.jsonl", "JSONL output file")
	flag.StringVar(&opts.outputHTML, "html", "report.html", "HTML report output file")
	flag.Parse()
	return opts
}

func run(opts options) error {
	if opts.url == "" {
		return errors.New("-u (target URL) is required")
	}
	if opts.threads <= 0 {
		return fmt.Errorf("-t must be greater than zero (got %d)", opts.threads)
	}
	if opts.retries < 0 {
		return fmt.Errorf("-retries must be >= 0 (got %d)", opts.retries)
	}
	if opts.rateLimit < 0 {
		return fmt.Errorf("-rl must be >= 0 (got %d)", opts.rateLimit)
	}
	if opts.timeout <= 0 {
		return fmt.Errorf("-timeout must be > 0 (got %s)", opts.timeout)
	}
	if opts.maxChain <= 0 {
		return fmt.Errorf("-max-chain must be > 0 (got %d)", opts.maxChain)
	}

	targets, payloads, err := buildTargets(opts.url, opts.wordlist)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return errors.New("no targets generated")
	}

	headerMap, err := toHeader(opts.headers)
	if err != nil {
		return err
	}

	var proxyFunc func(*http.Request) (*url.URL, error)
	if opts.proxy != "" {
		proxyURL, perr := url.Parse(opts.proxy)
		if perr != nil {
			return fmt.Errorf("invalid proxy URL: %w", perr)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	client := httpclient.New(httpclient.Config{
		Timeout:  opts.timeout,
		Proxy:    proxyFunc,
		Headers:  headerMap,
		Cookie:   opts.cookie,
		Insecure: opts.insecure,
		Retries:  opts.retries,
	})

	tracer := trace.New(client)
	runCfg := runner.Config{Threads: opts.threads, RateLimit: opts.rateLimit, MaxChain: opts.maxChain, JSSCAN: opts.jsScan}
	runr := runner.New(runCfg, tracer)

	if opts.verbose {
		fmt.Fprintf(os.Stderr, "[config] targets=%d threads=%d rate-limit=%d max-chain=%d js-scan=%t\n", len(targets), opts.threads, opts.rateLimit, opts.maxChain, opts.jsScan)
	}

	ctx := context.Background()
	results := runr.Run(ctx, targets)
	if len(results) != len(payloads) {
		return fmt.Errorf("internal error: results(%d) != payloads(%d)", len(results), len(payloads))
	}

	plugins, unknown := plugin.LoadWithWarnings(opts.plugins)
	if len(unknown) > 0 {
		return fmt.Errorf("unknown plugin(s): %s", strings.Join(unknown, ", "))
	}

	for i := range results {
		results[i].Target = targets[i]
		results[i].Payload = payloads[i]
		for _, pl := range plugins {
			findings := pl.Evaluate(ctx, &results[i])
			if len(findings) == 0 {
				continue
			}
			results[i].PluginFindings = append(results[i].PluginFindings, findings...)
			results[i].Findings = append(results[i].Findings, findings...)
		}
	}

	var (
		jsonFile   *os.File
		jsonWriter *bufio.Writer
		jsonEnc    *json.Encoder
	)
	if opts.outputJSONL != "" {
		var err error
		jsonFile, jsonWriter, jsonEnc, err = openJSONLAppender(opts.outputJSONL)
		if err != nil {
			return err
		}
		defer jsonFile.Close()
	}

	views := make([]output.ResultView, len(results))
	rows := make([]summaryRow, len(results))
	for i, res := range results {
		view := output.BuildResultView(i, res)
		views[i] = view
		rows[i] = summaryRow{
			View:           view,
			CoreFindings:   countCoreFindings(res.Findings),
			PluginFindings: len(res.PluginFindings),
			Error:          res.Error,
		}
		if jsonEnc != nil {
			record := output.BuildRecord(res)
			if err := jsonEnc.Encode(record); err != nil {
				return fmt.Errorf("write JSONL: %w", err)
			}
		}
	}
	if jsonWriter != nil {
		if err := jsonWriter.Flush(); err != nil {
			return fmt.Errorf("flush JSONL: %w", err)
		}
		if opts.verbose {
			fmt.Fprintf(os.Stderr, "[append] JSONL report -> %s\n", opts.outputJSONL)
		}
	}

	summary := output.BuildSummary(results)

	if !opts.silent {
		printConsole(results, views, opts)
	}

	params := buildParamsMap(opts, len(targets))
	if opts.outputHTML != "" {
		generatedAt := time.Now().UTC()
		if err := writeHTMLSummaryFile(opts.outputHTML, generatedAt, params, summary, rows, opts.verbose); err != nil {
			return err
		}
	}
	return nil
}

func buildTargets(urlStr, wordlist string) ([]string, []string, error) {
	hasFuzz := strings.Contains(urlStr, "FUZZ")
	switch {
	case hasFuzz && wordlist == "":
		return nil, nil, errors.New("URL contains FUZZ but no -w wordlist provided")
	case !hasFuzz && wordlist != "":
		return nil, nil, errors.New("-w supplied but target URL has no FUZZ placeholder")
	}

	if !hasFuzz {
		return []string{urlStr}, []string{""}, nil
	}

	words, err := loadWordlist(wordlist)
	if err != nil {
		return nil, nil, err
	}
	targets := make([]string, 0, len(words))
	payloads := make([]string, 0, len(words))
	for _, payload := range words {
		target := strings.Replace(urlStr, "FUZZ", payload, 1)
		targets = append(targets, target)
		payloads = append(payloads, payload)
	}
	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("wordlist %q produced no payloads", wordlist)
	}
	return targets, payloads, nil
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open wordlist %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	var entries []string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("wordlist read error: %w", err)
	}
	return entries, nil
}

func toHeader(headers headerList) (http.Header, error) {
	hdr := make(http.Header)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header %q (expected Key: Value)", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("invalid header %q (empty key)", h)
		}
		hdr.Add(key, value)
	}
	return hdr, nil
}

func buildParamsMap(opts options, targetCount int) map[string]string {
	params := map[string]string{
		"target":            opts.url,
		"wordlist":          opts.wordlist,
		"threads":           strconv.Itoa(opts.threads),
		"rate_limit":        strconv.Itoa(opts.rateLimit),
		"timeout":           opts.timeout.String(),
		"retries":           strconv.Itoa(opts.retries),
		"max_chain":         strconv.Itoa(opts.maxChain),
		"js_scan":           strconv.FormatBool(opts.jsScan),
		"insecure":          strconv.FormatBool(opts.insecure),
		"summary":           strconv.FormatBool(opts.summary),
		"silent":            strconv.FormatBool(opts.silent),
		"only_risky":        strconv.FormatBool(opts.onlyRisky),
		"plugins":           opts.plugins,
		"output_jsonl":      opts.outputJSONL,
		"output_html":       opts.outputHTML,
		"targets_generated": strconv.Itoa(targetCount),
	}
	if opts.cookie != "" {
		params["cookie"] = opts.cookie
	}
	if opts.proxy != "" {
		params["proxy"] = opts.proxy
	}
	if len(opts.headers) > 0 {
		params["headers"] = strings.Join(opts.headers, "; ")
	}
	return params
}

func openJSONLAppender(path string) (*os.File, *bufio.Writer, *json.Encoder, error) {
	if err := ensureDir(path); err != nil {
		return nil, nil, nil, fmt.Errorf("create JSONL directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open JSONL file: %w", err)
	}
	writer := bufio.NewWriter(f)
	enc := json.NewEncoder(writer)
	enc.SetEscapeHTML(false)
	return f, writer, enc, nil
}

func writeHTMLSummaryFile(path string, generatedAt time.Time, params map[string]string, summary output.Summary, rows []summaryRow, verbose bool) error {
	if err := ensureDir(path); err != nil {
		return fmt.Errorf("create HTML directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create HTML file: %w", err)
	}
	defer f.Close()
	if err := renderTinySummaryHTML(f, generatedAt, params, summary, rows); err != nil {
		return fmt.Errorf("write HTML summary: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[write] HTML summary -> %s\n", path)
	}
	return nil
}

func renderTinySummaryHTML(w io.Writer, generatedAt time.Time, params map[string]string, summary output.Summary, rows []summaryRow) error {
	buf := bufio.NewWriter(w)
	fmt.Fprintln(buf, "<!doctype html>")
	fmt.Fprintln(buf, "<html lang=\"en\">")
	fmt.Fprintln(buf, "<head>")
	fmt.Fprintln(buf, "<meta charset=\"utf-8\">")
	fmt.Fprintln(buf, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	fmt.Fprintln(buf, "<title>RedirectHunter Summary</title>")
	fmt.Fprintln(buf, "<style>")
	fmt.Fprintln(buf, "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;background:#f9fafb;color:#0f172a;}")
	fmt.Fprintln(buf, "h1{font-size:24px;margin:0 0 12px;}")
	fmt.Fprintln(buf, "h2{font-size:18px;margin:24px 0 12px;}")
	fmt.Fprintln(buf, ".meta{color:#64748b;font-size:12px;margin-top:4px;}")
	fmt.Fprintln(buf, ".overview{display:flex;flex-wrap:wrap;gap:12px;margin:16px 0 8px;padding:0;list-style:none;}")
	fmt.Fprintln(buf, ".overview li{flex:1 1 180px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;padding:12px 16px;box-shadow:0 1px 3px rgba(15,23,42,0.08);}")
	fmt.Fprintln(buf, ".overview strong{display:block;font-size:20px;color:#0f172a;}")
	fmt.Fprintln(buf, ".params{margin-top:24px;}")
	fmt.Fprintln(buf, ".params dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px 16px;margin:0;padding:0;}")
	fmt.Fprintln(buf, ".params dt{font-weight:600;color:#0f172a;}")
	fmt.Fprintln(buf, ".params dd{margin:0;color:#475569;word-break:break-word;}")
	fmt.Fprintln(buf, ".results{width:100%;border-collapse:collapse;margin-top:24px;font-size:14px;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;}")
	fmt.Fprintln(buf, ".results th,.results td{border-bottom:1px solid #e2e8f0;padding:10px 12px;text-align:left;vertical-align:top;}")
	fmt.Fprintln(buf, ".results th{background:#f8fafc;font-size:12px;text-transform:uppercase;letter-spacing:0.05em;color:#475569;}")
	fmt.Fprintln(buf, ".results tr:last-child td{border-bottom:none;}")
	fmt.Fprintln(buf, ".url{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px;word-break:break-all;}")
	fmt.Fprintln(buf, ".badge{display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600;font-size:12px;}")
	fmt.Fprintln(buf, ".badge.good{background:#dcfce7;color:#166534;}")
	fmt.Fprintln(buf, ".badge.info{background:#dbeafe;color:#1d4ed8;}")
	fmt.Fprintln(buf, ".badge.warn{background:#fef3c7;color:#92400e;}")
	fmt.Fprintln(buf, ".badge.bad{background:#fee2e2;color:#b91c1c;}")
	fmt.Fprintln(buf, ".badge.neutral{background:#e2e8f0;color:#1f2937;}")
	fmt.Fprintln(buf, ".row-error{background:rgba(248,113,113,0.08);}")
	fmt.Fprintln(buf, "@media (prefers-color-scheme: dark){body{background:#0f172a;color:#e2e8f0;} .overview li{background:#111c3a;border-color:#1e293b;color:#e2e8f0;} .params dt{color:#e2e8f0;} .params dd{color:#cbd5f5;} .results{background:#0f172a;border-color:#1e293b;} .results th{background:#111c3a;color:#cbd5f5;} .results td{border-color:#1e293b;} .badge.info{background:#1e3a8a;color:#bfdbfe;} .row-error{background:rgba(248,113,113,0.18);} }")
	fmt.Fprintln(buf, "</style>")
	fmt.Fprintln(buf, "</head>")
	fmt.Fprintln(buf, "<body>")
	fmt.Fprintln(buf, "<header>")
	fmt.Fprintln(buf, "<h1>RedirectHunter Summary</h1>")
	fmt.Fprintf(buf, "<div class=\"meta\">Generated %s</div>\n", html.EscapeString(generatedAt.Format(time.RFC3339)))
	fmt.Fprintln(buf, "</header>")
	fmt.Fprintln(buf, "<ul class=\"overview\">")
	fmt.Fprintf(buf, "<li><strong>%d</strong><span class=\"meta\">Total targets</span></li>\n", summary.TotalTargets)
	fmt.Fprintf(buf, "<li><strong>%d</strong><span class=\"meta\">Targets with findings</span></li>\n", summary.WithFindings)
	fmt.Fprintf(buf, "<li><strong>%d</strong><span class=\"meta\">Plugin findings</span></li>\n", summary.PluginFindings)
	fmt.Fprintf(buf, "<li><strong>%d</strong><span class=\"meta\">Errors</span></li>\n", summary.Errors)
	fmt.Fprintln(buf, "</ul>")

	if len(params) > 0 {
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(buf, "<section class=\"params\">")
		fmt.Fprintln(buf, "<h2>Run parameters</h2>")
		fmt.Fprintln(buf, "<dl>")
		for _, key := range keys {
			fmt.Fprintf(buf, "<dt>%s</dt><dd>%s</dd>\n", html.EscapeString(key), html.EscapeString(params[key]))
		}
		fmt.Fprintln(buf, "</dl>")
		fmt.Fprintln(buf, "</section>")
	}

	fmt.Fprintln(buf, "<table class=\"results\">")
	fmt.Fprintln(buf, "<thead><tr><th>#</th><th>Input</th><th>Final</th><th>Status</th><th>Core</th><th>Plugin</th><th>Duration</th><th>Error</th></tr></thead>")
	fmt.Fprintln(buf, "<tbody>")
	for _, row := range rows {
		rowClass := ""
		if row.Error != "" {
			rowClass = " class=\"row-error\""
		}
		payloadMeta := ""
		if row.View.Payload != "" {
			payloadMeta = fmt.Sprintf("<div class=\"meta\">payload: %s</div>", html.EscapeString(row.View.Payload))
		}
		finalURL := "—"
		if row.View.FinalURL != "" {
			finalURL = html.EscapeString(row.View.FinalURL)
		}
		statusClass, statusLabel := statusBadge(row.View, row.Error != "")
		errorText := "—"
		if row.Error != "" {
			errorText = html.EscapeString(row.Error)
		}
		fmt.Fprintf(
			buf,
			"<tr%s><td>%d</td><td><div class=\"url\">%s</div>%s</td><td><div class=\"url\">%s</div></td><td><span class=\"badge %s\">%s</span></td><td>%d</td><td>%d</td><td>%d&nbsp;ms</td><td>%s</td></tr>\n",
			rowClass,
			row.View.Index+1,
			html.EscapeString(row.View.InputURL),
			payloadMeta,
			finalURL,
			statusClass,
			html.EscapeString(statusLabel),
			row.CoreFindings,
			row.PluginFindings,
			row.View.DurationMs,
			errorText,
		)
	}
	fmt.Fprintln(buf, "</tbody>")
	fmt.Fprintln(buf, "</table>")
	fmt.Fprintln(buf, "</body>")
	fmt.Fprintln(buf, "</html>")
	return buf.Flush()
}

func statusBadge(view output.ResultView, hasError bool) (class string, label string) {
	switch view.Type {
	case output.ResultTypeRedirect:
		return "good", "[REDIRECT]"
	case output.ResultTypeUnredirect:
		return "info", "[UNREDIRECT]"
	case output.ResultTypeOK:
		if view.StatusCode == 0 {
			return "neutral", "—"
		}
		return "warn", strconv.Itoa(view.StatusCode)
	case output.ResultTypeError:
		if view.StatusCode == 0 {
			if hasError {
				return "bad", "error"
			}
			return "bad", "—"
		}
		return "bad", strconv.Itoa(view.StatusCode)
	default:
		return "neutral", "—"
	}
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func printConsole(results []model.Result, views []output.ResultView, opts options) {
	total := len(results)
	width := len(strconv.Itoa(total))
	var (
		totalRedirect   int
		totalUnredirect int
		totalOK         int
		totalError      int
	)
	for i, res := range results {
		view := views[i]
		coreCount := countCoreFindings(res.Findings)
		pluginCount := len(res.PluginFindings)
		hasError := res.Error != ""
		if opts.onlyRisky && coreCount == 0 && pluginCount == 0 && !hasError {
			continue
		}

		if opts.summary {
			if hasError {
				line := fmt.Sprintf("[%*d/%d] %s | error: %s", width, i+1, total, view.InputURL, res.Error)
				fmt.Println(statuscolor.Gray(line))
				continue
			}

			chainParts := make([]string, 0, len(res.Chain))
			for _, hop := range res.Chain {
				chainParts = append(chainParts, statuscolor.Sprint(hop.Status))
			}
			chainText := "—"
			if len(chainParts) > 0 {
				chainText = strings.Join(chainParts, "→")
			}

			finalURL := view.FinalURL
			if finalURL == "" {
				finalURL = "—"
			}

			var label string
			switch view.Type {
			case output.ResultTypeRedirect:
				label = statuscolor.WrapByStatus("[REDIRECT]", http.StatusFound)
				totalRedirect++
			case output.ResultTypeUnredirect:
				label = statuscolor.Blue("[UNREDIRECT]")
				totalUnredirect++
			case output.ResultTypeOK:
				label = statuscolor.WrapByStatus("[OK]", http.StatusOK)
				totalOK++
			case output.ResultTypeError:
				label = statuscolor.WrapByStatus("[ERROR]", http.StatusNotFound)
				totalError++
			default:
				label = statuscolor.Gray("[UNKNOWN]")
			}

			line := fmt.Sprintf(
				"%s [%*d/%d] %s -> %s | Final: %s | Chain: %s | core=%2d | plugin=%2d | duration=%dms",
				label,
				width,
				i+1,
				total,
				view.InputURL,
				finalURL,
				statuscolor.Sprint(view.StatusCode),
				chainText,
				coreCount,
				pluginCount,
				view.DurationMs,
			)
			fmt.Println(line)
			continue
		}

		fmt.Printf("=== Target %d/%d ===\n", i+1, total)
		statuscolor.PrintResult(res)
		fmt.Printf("Final: %s (status %s, %d bytes)\n", view.FinalURL, statuscolor.Sprint(view.StatusCode), view.RespLen)

		coreFindings := filterFindings(res.Findings, func(f model.Finding) bool {
			return f.Source == "" || strings.EqualFold(f.Source, "core")
		})
		if len(coreFindings) > 0 {
			fmt.Println("Core findings:")
			for _, f := range coreFindings {
				fmt.Printf("  - [%s] %s — %s\n", strings.ToUpper(f.Severity), f.Type, f.Detail)
			}
		} else {
			fmt.Println("Core findings: none")
		}

		if pluginCount > 0 {
			fmt.Println("Plugin findings:")
			for _, f := range res.PluginFindings {
				fmt.Printf("  - [%s] %s — %s (%s)\n", strings.ToUpper(f.Severity), f.Type, f.Detail, f.Source)
			}
		}

		if hasError {
			fmt.Printf("Error: %s\n", res.Error)
		}
		fmt.Printf("Duration: %dms\n\n", view.DurationMs)
	}

	if opts.summary {
		fmt.Printf("Summary: ✅ %d redirects | 🌀 %d unredirects | ⚠️ %d ok | ❌ %d errors\n", totalRedirect, totalUnredirect, totalOK, totalError)
	}
}

func countCoreFindings(findings []model.Finding) int {
	count := 0
	for _, f := range findings {
		if f.Source == "" || strings.EqualFold(f.Source, "core") {
			count++
		}
	}
	return count
}

type findingFilter func(model.Finding) bool

func filterFindings(findings []model.Finding, keep findingFilter) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

func (h *headerList) String() string {
	return strings.Join(*h, "; ")
}

func (h *headerList) Set(value string) error {
	*h = append(*h, value)
	return nil
}
