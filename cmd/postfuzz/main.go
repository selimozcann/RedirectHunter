package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	var (
		urlStr      string
		method      string
		bodyTmpl    string
		payloads    string
		contentType string
	)

	flag.StringVar(&urlStr, "u", "", "target URL (required)")
	flag.StringVar(&method, "X", "GET", "HTTP method")
	flag.StringVar(&bodyTmpl, "body", "", "POST body template")
	flag.StringVar(&payloads, "payloads", "", "payload wordlist file")
	flag.StringVar(&contentType, "content-type", "application/json", "Content-Type header")
	flag.Parse()

	if urlStr == "" {
		fmt.Fprintln(os.Stderr, "-u is required")
		os.Exit(1)
	}

	method = strings.ToUpper(method)
	client := &http.Client{}

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
				body := strings.ReplaceAll(bodyTmpl, "FUZZ", payload)
				sendRequest(client, method, urlStr, body, contentType, payload)
			}
			if err := sc.Err(); err != nil {
				fmt.Fprintf(os.Stderr, "reading payloads: %v\n", err)
			}
		} else {
			sendRequest(client, method, urlStr, bodyTmpl, contentType, "")
		}
		return
	}

	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request build error: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	fmt.Printf("%s\t%d\t%d\n", "", resp.StatusCode, n)
}

func sendRequest(client *http.Client, method, urlStr, body, contentType, payload string) {
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "request build error: %v\n", err)
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
	fmt.Printf("%s\t%d\t%d\n", payload, resp.StatusCode, n)
}
