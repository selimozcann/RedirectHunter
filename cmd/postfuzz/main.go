package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/banner"
	"github.com/selimozcann/RedirectHunter/internal/model"
	"github.com/selimozcann/RedirectHunter/internal/output"
)

func main() {
	var (
		// Common
		urlStr      string
		cookie      string
		headers     headerList
		proxyStr    string
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

		// URL FUZZ
		urlWordlist string // -w

		// BODY FUZZ / POSTFuzz
		method      string // -X
		bodyTmpl    string // -body
		bodyWLPath  string // -payloads
		contentType string // -content-type
	)

	// Common flags
	flag.StringVar(&urlStr, "u", "", "Target URL (supports FUZZ)")
	flag.StringVar(&cookie, "cookie", "", "Cookie header")
	flag.Var(&headers, "H", "Extra HTTP header (repeatable)")
	flag.StringVar(&proxyStr, "proxy", "", "HTTP(S) proxy URL")
	flag.DurationVar(&timeout, "timeout", 8*time.Second, "Per-target timeout")
	flag.IntVar(&retries, "retries", 1, "Retry count")
	flag.IntVar(&threads, "t", 10, "Threads")
	flag.IntVar(&rateLimit, "rl", 0, "Global rate limit (requests per second)")
	flag.IntVar(&maxChain, "max-chain", 15, "Max redirect hops including JS/meta")
	flag.BoolVar(&jsScan, "js-scan", true, "Enable JS/meta redirect detection")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.BoolVar(&silent, "silent", false, "Suppress chain output")
	flag.BoolVar(&summary, "summary", false, "Show one-line summary per target")
	flag.BoolVar(&onlyRisky, "only-risky", false, "Only output results with findings")
	flag.StringVar(&plugins, "plugins", "final-ssrf", "Plugins to enable (comma-separated)")
	flag.StringVar(&outputJSONL, "o", "", "JSONL output file")
	flag.StringVar(&outputHTML, "html", "", "HTML report output file")

	// URL FUZZ flags
	flag.StringVar(&urlWordlist, "w", "", "Wordlist file (used when FUZZ is in URL)")

	// BODY FUZZ flags (use single dash, e.g., -body, -payloads)
	flag.StringVar(&method, "X", "GET", "HTTP method to use (GET, POST, PUT)")
	flag.StringVar(&bodyTmpl, "body", "", "Request body template (use FUZZ as placeholder)")
	flag.StringVar(&bodyWLPath, "payloads", "", "Wordlist file for FUZZ in body")
	flag.StringVar(&contentType, "content-type", "application/json", "Content-Type header for body requests")

	flag.Parse()

	_ = maxChain
	_ = jsScan
	_ = onlyRisky
	_ = plugins

	banner.PrintBanner()
	if urlStr == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: -u (URL) is required")
		os.Exit(1)
	}

	// HTTP client
	transport := &http.Transport{}
	if proxyStr != "" {
		proxyURL, err := url.Parse(proxyStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid proxy: %v\n", err)
			os.Exit(1)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	// Outputs
	var (
		jsonl   *output.JSONLWriter
		htmlw   *output.HTMLWriter
		closeFn []func() error
	)
	if outputJSONL != "" {
		f, err := os.Create(outputJSONL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create JSONL file: %v\n", err)
			os.Exit(1)
		}
		jsonl = output.NewJSONLWriter(f)
		closeFn = append(closeFn, func() error { defer f.Close(); return jsonl.Close() })
	}
	if outputHTML != "" {
		f, err := os.Create(outputHTML)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create HTML file: %v\n", err)
			os.Exit(1)
		}
		htmlw = output.NewHTMLWriter(f)
		if err := htmlw.Begin("RedirectHunter Report"); err != nil {
			fmt.Fprintf(os.Stderr, "[-] HTML begin error: %v\n", err)
			os.Exit(1)
		}
		closeFn = append(closeFn, func() error { defer f.Close(); return htmlw.Close() })
	}
	defer func() {
		for _, fn := range closeFn {
			if err := fn(); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Close error: %v\n", err)
			}
		}
	}()

	// Rate limiter
	var limiter *time.Ticker
	if rateLimit > 0 {
		interval := time.Second / time.Duration(rateLimit)
		if interval <= 0 {
			interval = time.Second
		}
		limiter = time.NewTicker(interval)
		defer limiter.Stop()
	}

	// Build jobs
	type job struct {
		Method     string
		URL        string
		Body       []byte // nil if no body
		PayloadTag string // for verbose printing (URL or BODY payload)
	}

	var jobs []job

	isURLFuzz := strings.Contains(urlStr, "FUZZ") && urlWordlist != ""
	isBodyFuzz := bodyTmpl != "" && strings.Contains(bodyTmpl, "FUZZ") && (bodyWLPath != "" || urlWordlist != "")

	switch {
	case isURLFuzz:
		words := mustLoadWordlist(urlWordlist)
		jobs = make([]job, 0, len(words))
		for _, p := range words {
			j := job{
				Method:     method,
				URL:        strings.Replace(urlStr, "FUZZ", p, 1),
				Body:       nil,
				PayloadTag: p,
			}
			// If also bodyTmpl present but without FUZZ, use same body for all
			if bodyTmpl != "" && !strings.Contains(bodyTmpl, "FUZZ") {
				j.Body = []byte(bodyTmpl)
			}
			jobs = append(jobs, j)
		}

	case isBodyFuzz:
		// pick body wordlist: prefer -payloads else fallback to -w
		bodyWL := bodyWLPath
		if bodyWL == "" {
			bodyWL = urlWordlist
		}
		words := mustLoadWordlist(bodyWL)
		jobs = make([]job, 0, len(words))
		for _, p := range words {
			body := strings.Replace(bodyTmpl, "FUZZ", p, -1)
			jobs = append(jobs, job{
				Method:     method,
				URL:        urlStr, // URL may or may not include FUZZ
				Body:       []byte(body),
				PayloadTag: p,
			})
		}

	default:
		// No fuzzing; single request
		var bodyBytes []byte
		if bodyTmpl != "" {
			bodyBytes = []byte(bodyTmpl)
		}
		jobs = []job{{
			Method: method,
			URL:    urlStr,
			Body:   bodyBytes,
		}}
	}

	// Concurrency + output
	var (
		wg       sync.WaitGroup
		stdoutMu sync.Mutex
	)

	emit := func(res model.Result) {
		if jsonl != nil {
			if err := jsonl.Write(res); err != nil {
				stdoutMu.Lock()
				fmt.Fprintf(os.Stderr, "[-] JSONL write error: %v\n", err)
				stdoutMu.Unlock()
			}
		}
		if htmlw != nil {
			if err := htmlw.Write(res); err != nil {
				stdoutMu.Lock()
				fmt.Fprintf(os.Stderr, "[-] HTML write error: %v\n", err)
				stdoutMu.Unlock()
			}
		}
		if silent {
			return
		}
		stdoutMu.Lock()
		if summary {
			last := ""
			status := 0
			if len(res.Chain) > 0 {
				last = res.Chain[len(res.Chain)-1].URL
				status = res.Chain[len(res.Chain)-1].Status
			}
			fmt.Printf("[+] Target: %s | Final: %s | Status: %d | Findings: %d | Duration: %dms\n",
				res.Target, last, status, len(res.Findings), res.DurationMs)
		} else {
			fmt.Printf("=== %s %s ===\n", res.Target, "")
			for i, h := range res.Chain {
				fmt.Printf("  %d) %s  [status=%d via=%s time=%dms]\n", i+1, h.URL, h.Status, h.Via, h.TimeMs)
			}
			if len(res.Findings) > 0 {
				fmt.Println("  Findings:")
				for _, f := range res.Findings {
					fmt.Printf("    - [%s] %s — %s\n", f.Severity, f.Type, f.Detail)
				}
			}
			fmt.Println()
		}
		stdoutMu.Unlock()
	}

	jobCh := make(chan job, threads)
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jb := range jobCh {
				if limiter != nil {
					<-limiter.C
				}
				if verbose {
					stdoutMu.Lock()
					if jb.PayloadTag != "" {
						fmt.Printf("[>] Payload: %q\n", jb.PayloadTag)
					}
					fmt.Printf("[>] %s %s\n", jb.Method, jb.URL)
					if len(jb.Body) > 0 {
						fmt.Printf("[>] Body: %s\n", truncate(string(jb.Body), 300))
					}
					stdoutMu.Unlock()
				}
				res, err := doRequestWithRetries(client, jb.Method, jb.URL, jb.Body, contentType, cookie, headers, retries)
				if err != nil {
					stdoutMu.Lock()
					fmt.Fprintf(os.Stderr, "[-] Request error (%s): %v\n", jb.URL, err)
					stdoutMu.Unlock()
					continue
				}
				emit(res)
			}
		}()
	}

	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)
	wg.Wait()
}

/* ---------------- Helpers ---------------- */

type headerList []string

func (h *headerList) String() string         { return fmt.Sprint(*h) }
func (h *headerList) Set(value string) error { *h = append(*h, value); return nil }

func mustLoadWordlist(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open wordlist: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Wordlist read error: %v\n", err)
		os.Exit(1)
	}
	return lines
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
}

// doRequestWithRetries performs one HTTP request with optional body and content-type.
// It returns a model.Result with a SINGLE http hop (final URL, status, duration).
func doRequestWithRetries(client *http.Client, method, rawURL string, body []byte, contentType, cookie string, headers headerList, retries int) (model.Result, error) {
	var (
		resp   *http.Response
		final  *http.Request
		size   int64
		err    error
		result model.Result
	)

	start := time.Now()

	for attempt := 0; attempt <= retries; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, rerr := http.NewRequest(method, rawURL, bodyReader)
		if rerr != nil {
			return model.Result{}, rerr
		}

		// Headers
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		for _, h := range headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		if body != nil && contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err = client.Do(req)
		if err != nil {
			if attempt < retries {
				time.Sleep(backoff(attempt))
				continue
			}
			return model.Result{}, err
		}

		final = resp.Request
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		size = n
		break
	}

	// Hop
	hop := model.Hop{
		Index:  0,
		URL:    final.URL.String(),
		Method: final.Method,
		Status: resp.StatusCode,
		Via:    "http",
		TimeMs: time.Since(start).Milliseconds(),
		Final:  true,
		// Add Size to your model.Hop if desired:
		// Size: size,
	}

	// Result
	result = model.Result{
		Target:     rawURL,
		Chain:      []model.Hop{hop},
		Findings:   nil,
		StartedAt:  start,
		DurationMs: time.Since(start).Milliseconds(),
	}

	// If you extended model.Hop with Size, also include it in HTML/JSONL writers.
	_ = size

	return result, nil
}

func backoff(attempt int) time.Duration {
	return time.Duration(300*(attempt+1)) * time.Millisecond
}
