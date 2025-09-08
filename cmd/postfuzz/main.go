package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/selimozcann/RedirectHunter/internal/banner"
)

func main() {
	var (
		urlStr      string
		method      string
		bodyTmpl    string
		payloads    string
		contentType string
		verbose     bool
	)

	// CLI flags
	flag.StringVar(&urlStr, "u", "", "target URL (required)")
	flag.StringVar(&method, "X", "POST", "HTTP method (POST, PUT)")
	flag.StringVar(&bodyTmpl, "body", "", "POST body template. Use 'FUZZ' as placeholder")
	flag.StringVar(&payloads, "payloads", "", "payload wordlist file")
	flag.StringVar(&contentType, "content-type", "application/json", "Content-Type header")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.Parse()
	banner.PrintBanner()
	if urlStr == "" {
		fmt.Fprintln(os.Stderr, "-u is required")
		os.Exit(1)
	}

	method = strings.ToUpper(method)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	if (method == "POST" || method == "PUT") && bodyTmpl != "" {
		if strings.Contains(bodyTmpl, "FUZZ") && payloads != "" {
			f, err := os.Open(payloads)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to open payloads: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				payload := sc.Text()
				body := strings.Replace(bodyTmpl, "FUZZ", payload, 1)
				if verbose {
					fmt.Printf("[>] Payload: %q\n[>] Body:\n%s\n", payload, body)
				}
				sendRequest(client, method, urlStr, body, contentType, payload)
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "reading payloads: %v\n", err)
			}
		} else {
			if verbose {
				fmt.Printf("[>] Sending static body:\n%s\n", bodyTmpl)
			}
			sendRequest(client, method, urlStr, bodyTmpl, contentType, "")
		}
		return
	}

	// GET or other method without body
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request build error: %v\n", err)
		return
	}

	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	fmt.Printf("[*] Status: %d | Response Length: %d\n", resp.StatusCode, n)
}

func sendRequest(client *http.Client, method, urlStr, body, contentType, payload string) {
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request build error for payload %q: %v\n", payload, err)
		return
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error for payload %q: %v\n", payload, err)
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	fmt.Printf("[+] Payload: %-20s | Status: %d | RespLen: %d\n", payload, resp.StatusCode, n)
}
