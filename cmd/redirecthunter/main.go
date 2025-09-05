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
)

func main() {
	var (
		urlStr      string
		method      string
		bodyTmpl    string
		payloadPath string
		contentType string
		verbose     bool
	)

	// CLI flags
	flag.StringVar(&urlStr, "u", "", "Target URL (required)")
	flag.StringVar(&method, "X", "GET", "HTTP method (GET, POST, PUT, etc.)")
	flag.StringVar(&bodyTmpl, "body", "", "Request body template. Use 'FUZZ' as placeholder")
	flag.StringVar(&payloadPath, "payloads", "", "Path to payload wordlist file")
	flag.StringVar(&contentType, "content-type", "application/json", "Content-Type header")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.Parse()

	if urlStr == "" {
		fmt.Fprintln(os.Stderr, "[-] Error: -u (URL) is required")
		os.Exit(1)
	}

	method = strings.ToUpper(method)
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// POST/PUT with template body and optional fuzzing
	if (method == "POST" || method == "PUT") && bodyTmpl != "" {
		if strings.Contains(bodyTmpl, "FUZZ") && payloadPath != "" {
			fuzzWithPayloads(client, urlStr, method, bodyTmpl, payloadPath, contentType, verbose)
		} else {
			sendRequest(client, urlStr, method, bodyTmpl, contentType, "", verbose)
		}
		return
	}

	// GET or other methods without body
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request build error: %v\n", err)
		return
	}

	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request error: %v\n", err)
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	fmt.Printf("[*] Status: %d | Response Length: %d\n", resp.StatusCode, n)
}

// fuzzWithPayloads injects each payload into the body and sends requests
func fuzzWithPayloads(client *http.Client, urlStr, method, bodyTmpl, payloadPath, contentType string, verbose bool) {
	file, err := os.Open(payloadPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open payloads file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		payload := scanner.Text()
		body := strings.Replace(bodyTmpl, "FUZZ", payload, 1)
		sendRequest(client, urlStr, method, body, contentType, payload, verbose)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error reading payloads file: %v\n", err)
	}
}

// sendRequest builds and sends a single request
func sendRequest(client *http.Client, urlStr, method, body, contentType, payload string, verbose bool) {
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request build error for payload %q: %v\n", payload, err)
		return
	}

	if method == "POST" || method == "PUT" {
		req.Header.Set("Content-Type", contentType)
	}

	if verbose {
		fmt.Printf("[>] Payload: %q\n[>] Body:\n%s\n", payload, body)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Request error for payload %q: %v\n", payload, err)
		return
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	fmt.Printf("[+] Payload: %-20s | Status: %d | RespLen: %d\n", payload, resp.StatusCode, n)
}
