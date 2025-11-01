package main

import (
	"bufio"
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
)

func main() {
	var (
		urlStr      string
		payloadPath string
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
	)

	flag.StringVar(&urlStr, "u", "", "Target URL (supports FUZZ)")
	flag.StringVar(&payloadPath, "w", "", "Wordlist file (used when FUZZ is in URL)")
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
	flag.StringVar(&plugins, "plugins", "final-ssrf", "Plugins to enable")
	flag.StringVar(&outputJSONL, "o", "", "JSONL output file")
	flag.StringVar(&outputHTML, "html", "", "HTML report output file")

	flag.Parse()

	banner.PrintBanner()
	if urlStr == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: -u (URL) is required")
		os.Exit(1)
	}

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
		transport.TLSClientConfig = insecureTLS()
	}
	client := &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	if payloadPath != "" {
		runParallelFuzzing(client, urlStr, payloadPath, cookie, headers, threads, verbose)
		return
	}

	sendRequest(client, urlStr, cookie, headers, urlStr, verbose)
}

type headerList []string

func (h *headerList) String() string         { return fmt.Sprint(*h) }
func (h *headerList) Set(value string) error { *h = append(*h, value); return nil }

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} // #nosec G402
}

func runParallelFuzzing(client *http.Client, urlStr, wordlistPath, cookie string, headers headerList, threads int, verbose bool) {
	payloads := loadWordlist(wordlistPath)
	var wg sync.WaitGroup
	ch := make(chan string, threads)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range ch {
				urlWithPayload := buildURLWithPayload(urlStr, payload)
				sendRequest(client, urlWithPayload, cookie, headers, payload, verbose)
			}
		}()
	}

	for _, p := range payloads {
		ch <- p
	}
	close(ch)
	wg.Wait()
}

func buildURLWithPayload(baseURL, payload string) string {
	if strings.Contains(baseURL, "FUZZ") {
		return strings.Replace(baseURL, "FUZZ", payload, 1)
	}
	return baseURL + payload
}

func loadWordlist(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open wordlist: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

func sendRequest(client *http.Client, urlStr, cookie string, headers headerList, payload string, verbose bool) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request build error for payload %q: %v\n", payload, err)
		return
	}

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	if verbose {
		fmt.Printf("[>] Payload: %q\n[>] URL: %s\n", payload, urlStr)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request error for payload %q: %v\n", payload, err)
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)

	indicator := "[-]"
	if resp.StatusCode == http.StatusFound {
		indicator = "[+]"
	}

	redirectInfo := ""
	if location := resp.Header.Get("Location"); location != "" {
		redirectInfo = fmt.Sprintf(" | Redirect: %s", location)
	}

	line := fmt.Sprintf("| %s Payload: %-30s | Status: %d | RespLen: %d%s", indicator, payload, resp.StatusCode, n, redirectInfo)

	if resp.StatusCode == http.StatusFound {
		fmt.Printf("\033[32m%s\033[0m\n", line)
	} else {
		fmt.Println(line)
	}
}
