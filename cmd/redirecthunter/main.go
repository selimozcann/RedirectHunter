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

	"github.com/selimozcann/RedirectHunter/internal/banner"
	"github.com/selimozcann/RedirectHunter/internal/httpclient"
	"github.com/selimozcann/RedirectHunter/internal/output"
	"github.com/selimozcann/RedirectHunter/internal/plugin"
	"github.com/selimozcann/RedirectHunter/internal/runner"
	"github.com/selimozcann/RedirectHunter/internal/statuscolor"
	"github.com/selimozcann/RedirectHunter/internal/trace"
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
		jsScan     bool
		outFile    string
		htmlFile   string
		cookie     string
		proxyStr   string
		insecure   bool
		silent     bool
		summary    bool
		onlyRisky  bool
		pluginList string
	)

	banner.PrintBanner()

	flag.StringVar(&urlFlag, "u", "", "Single URL (supports FUZZ)")
	flag.StringVar(&wordlist, "w", "", "Wordlist file")
	flag.IntVar(&threads, "t", 10, "Concurrent threads")
	flag.IntVar(&rateLimit, "rl", 0, "Global rate limit req/sec")
	flag.StringVar(&timeoutStr, "timeout", "8s", "Per-target timeout")
	flag.IntVar(&retries, "retries", 1, "Retry count")
	flag.IntVar(&maxChain, "max-chain", 15, "Max hops including meta/js")
	flag.BoolVar(&jsScan, "js-scan", true, "Enable HTML/JS redirect detection")
	flag.StringVar(&outFile, "o", "", "JSONL output file")
	flag.StringVar(&htmlFile, "html", "", "HTML report output file")
	flag.StringVar(&cookie, "cookie", "", "Cookie header")
	flag.StringVar(&proxyStr, "proxy", "", "HTTP proxy URL")
	flag.BoolVar(&insecure, "insecure", false, "Skip TLS verification")
	flag.BoolVar(&silent, "silent", false, "Suppress chain output")
	flag.BoolVar(&summary, "summary", false, "Print one line summary per target")
	flag.BoolVar(&onlyRisky, "only-risky", false, "Only output results with findings")
	flag.StringVar(&pluginList, "plugins", "final-ssrf", "Comma separated plugins to enable")

	headers := http.Header{}
	flag.Func("H", "Extra header (repeatable)", func(s string) error {
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
		if pURL, err := url.Parse(proxyStr); err == nil {
			proxyFunc = http.ProxyURL(pURL)
		}
	}

	client := httpclient.New(httpclient.Config{Timeout: timeout, Proxy: proxyFunc, Headers: headers, Cookie: cookie, Insecure: insecure, Retries: retries})
	tracer := trace.New(client)
	run := runner.New(runner.Config{Threads: threads, RateLimit: rateLimit, MaxChain: maxChain, JSSCAN: jsScan}, tracer)

	targets := collectTargets(urlFlag, wordlist)
	ctx := context.Background()
	results := run.Run(ctx, targets)

	plugins := plugin.Load(pluginList)
	for i := range results {
		for _, p := range plugins {
			results[i].Findings = append(results[i].Findings, p.Evaluate(ctx, &results[i])...)
		}
	}

	// console output and JSONL
	var writer *output.JSONLWriter
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		writer = output.NewJSONLWriter(f)
	}

	for _, r := range results {
		if onlyRisky && len(r.Findings) == 0 {
			continue
		}
		if !silent {
			statuscolor.PrintResult(r)
		}
		if summary {
			fmt.Printf("%s: %d hops, %d risks\n", r.Target, len(r.Chain), len(r.Findings))
		}
		if writer != nil {
			_ = writer.WriteResult(r)
		}
	}

	if htmlFile != "" {
		f, err := os.Create(htmlFile)
		if err == nil {
			defer f.Close()
			hw := output.NewHTMLWriter(f)
			_ = hw.WriteAll(results)
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
			defer f.Close()
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
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			targets = append(targets, sc.Text())
		}
	} else if u != "" {
		targets = append(targets, u)
	}
	return targets
}
