package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"redirecthunter/internal/httpclient"
	"redirecthunter/internal/model"
	"redirecthunter/internal/output"
	"redirecthunter/internal/runner"
	"redirecthunter/internal/trace"
)

func main() {
	var (
		urlFlag    string
		wordlist   string
		threads    int
		rateLimit  int
		timeoutStr string
		retries    int
		maxChain   int
		mc         string
		jsScan     bool
		outFile    string
		outFormat  string
		cookie     string
		proxyStr   string
		insecure   bool
	)

	flag.StringVar(&urlFlag, "u", "", "Single URL (supports FUZZ)")
	flag.StringVar(&wordlist, "w", "", "Wordlist file")
	flag.IntVar(&threads, "t", 10, "Threads")
	flag.IntVar(&rateLimit, "rl", 0, "Global rate limit req/sec")
	flag.StringVar(&timeoutStr, "timeout", "8s", "Per-target timeout")
	flag.IntVar(&retries, "retries", 1, "Retry count")
	flag.IntVar(&maxChain, "max-chain", 15, "Max hops including meta/js")
	flag.StringVar(&mc, "mc", "", "Match status classes/codes")
	flag.BoolVar(&jsScan, "js-scan", false, "Enable HTML/JS redirect detection")
	flag.StringVar(&outFile, "o", "", "Output file")
	flag.StringVar(&outFormat, "of", "jsonl", "Output format")
	flag.StringVar(&cookie, "cookie", "", "Cookie header")
	flag.StringVar(&proxyStr, "proxy", "", "HTTP proxy URL")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	headers := http.Header{}
	flag.Func("H", "Extra header", func(s string) error {
		parts := strings.SplitN(s, ":", 2)
		if len(parts) == 2 {
			headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
		return nil
	})
	flag.Parse()

	timeout, _ := time.ParseDuration(timeoutStr)

	proxyFunc := http.ProxyFromEnvironment
	if proxyStr != "" {
		pURL, err := url.Parse(proxyStr)
		if err == nil {
			proxyFunc = http.ProxyURL(pURL)
		}
	}

	client := httpclient.New(httpclient.Config{Timeout: timeout, Proxy: proxyFunc, Headers: headers, Cookie: cookie, Insecure: insecure, Retries: retries})
	tracer := trace.New(client)
	run := runner.New(runner.Config{Threads: threads, RateLimit: rateLimit, MaxChain: maxChain, JSSCAN: jsScan}, tracer)

	targets := collectTargets(urlFlag, wordlist)
	ctx := context.Background()
	results := run.Run(ctx, targets)

	out := os.Stdout
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		out = f
	}
	writer := output.NewJSONLWriter(out)
	for _, r := range results {
		if shouldOutput(r, mc) {
			_ = writer.WriteResult(r)
		}
	}
}

// collectTargets builds the list of targets from flags.
func collectTargets(u, wordlist string) []string {
	var targets []string
	if u != "" && strings.Contains(u, "FUZZ") {
		var words []string
		if wordlist != "" {
			f, _ := os.Open(wordlist)
			defer func() { _ = f.Close() }()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				words = append(words, sc.Text())
			}
		} else {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				words = append(words, sc.Text())
			}
		}
		for _, w := range words {
			targets = append(targets, strings.ReplaceAll(u, "FUZZ", w))
		}
	} else if wordlist != "" {
		f, _ := os.Open(wordlist)
		defer func() { _ = f.Close() }()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			targets = append(targets, sc.Text())
		}
	} else if u != "" {
		targets = append(targets, u)
	}
	return targets
}

func shouldOutput(res model.Result, mc string) bool {
	if mc == "" {
		return true
	}
	set := map[string]struct{}{}
	for _, part := range strings.Split(mc, ",") {
		set[strings.TrimSpace(part)] = struct{}{}
	}
	for _, h := range res.Chain {
		codeStr := fmt.Sprintf("%d", h.Status)
		class := fmt.Sprintf("%dxx", h.Status/100)
		if _, ok := set[codeStr]; ok {
			return true
		}
		if _, ok := set[class]; ok {
			return true
		}
	}
	return len(res.Findings) > 0
}
