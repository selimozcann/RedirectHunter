package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	flag.StringVar(&opts.outputJSONL, "o", "", "JSONL output file")
	flag.StringVar(&opts.outputHTML, "html", "", "HTML report output file")
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

	views := make([]output.ResultView, len(results))
	records := make([]output.Record, len(results))
	for i, res := range results {
		views[i] = output.BuildResultView(i, res)
		records[i] = output.BuildRecord(res)
	}
	summary := output.BuildSummary(results)

	if !opts.silent {
		printConsole(results, views, opts)
	}

	params := buildParamsMap(opts, len(targets))
	if opts.outputJSONL != "" {
		if err := writeJSONLFile(opts.outputJSONL, records, opts.verbose); err != nil {
			return err
		}
	}
	if opts.outputHTML != "" {
		page := output.PageData{
			Title:       "RedirectHunter Report",
			GeneratedAt: time.Now().UTC(),
			Params:      params,
			Summary:     summary,
			Results:     views,
		}
		if err := writeHTMLFile(opts.outputHTML, page, opts.verbose); err != nil {
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

func writeJSONLFile(path string, records []output.Record, verbose bool) error {
	if err := ensureDir(path); err != nil {
		return fmt.Errorf("create JSONL directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JSONL file: %w", err)
	}
	defer f.Close()
	if err := output.WriteJSONL(f, records); err != nil {
		return fmt.Errorf("write JSONL: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[write] JSONL report -> %s\n", path)
	}
	return nil
}

func writeHTMLFile(path string, page output.PageData, verbose bool) error {
	if err := ensureDir(path); err != nil {
		return fmt.Errorf("create HTML directory: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create HTML file: %w", err)
	}
	defer f.Close()
	if err := output.RenderHTML(f, page); err != nil {
		return fmt.Errorf("write HTML: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[write] HTML report -> %s\n", path)
	}
	return nil
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
	for i, res := range results {
		view := views[i]
		coreCount := countCoreFindings(res.Findings)
		pluginCount := len(res.PluginFindings)
		hasError := res.Error != ""
		if opts.onlyRisky && coreCount == 0 && pluginCount == 0 && !hasError {
			continue
		}

		if opts.summary {
			fmt.Printf("[%d/%d] %s -> %s | status=%d | core=%d | plugin=%d | duration=%dms\n", i+1, total, view.InputURL, view.FinalURL, view.StatusCode, coreCount, pluginCount, view.DurationMs)
			if hasError {
				fmt.Printf("    error: %s\n", res.Error)
			}
			continue
		}

		fmt.Printf("=== Target %d/%d ===\n", i+1, total)
		statuscolor.PrintResult(res)
		fmt.Printf("Final: %s (status %d, %d bytes)\n", view.FinalURL, view.StatusCode, view.RespLen)

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
