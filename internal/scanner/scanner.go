package scanner

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"redirecthunter/internal/analyzer"
	"redirecthunter/internal/output"
	"strings"
	"time"
)

func RunScan(filePath string) (err error) {
	urls, err := loadURLs(filePath)
	if err != nil {
		return err
	}
	for _, url := range urls {
		traceRedirectChain(url)
		fmt.Println()
	}
	return nil
}

func loadURLs(filePath string) ([]string, error) {
	var urls []string
	file, err := os.Open(filePath)
	if err != nil {
		return urls, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls = append(urls, url)
		}
	}
	return urls, scanner.Err()
}

func traceRedirectChain(startURL string) {
	output.PrintScanHeader(startURL)
	currentURL := startURL

	client := &http.Client{
		Timeout: time.Second * 10,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow manual handling of redirects
			return http.ErrUseLastResponse
		},
	}
	visited := make(map[string]bool)
	redirectAmount := 10
	for i := 0; i < redirectAmount; i++ {
		if visited[currentURL] {
			fmt.Println(" [!] Loop Detected")
			break
		}
		visited[currentURL] = true
		resp, err := client.Get(currentURL)
		if err != nil {
			output.PrintError(currentURL, err.Error())
			break
		}
		defer resp.Body.Close()

		fmt.Printf("  ↪ %s → %d\n", currentURL, resp.StatusCode)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				output.PrintNoLocation()
				break
			}
			currentURL = loc
		} else {
			// log.Println("Http status is not => resp.StatusCode >= 300 && resp.StatusCode < 400")
			finalDomain := extractDomain(currentURL)
			startDomain := extractDomain(startURL)

			if finalDomain != startDomain {
				output.PrintRedirectToDifferentDomain(currentURL)
			} else {
				output.PrintFinalURL(currentURL)
			}
			analyzer.AnalyzeHTML(currentURL)
			break
		}
	}
}
