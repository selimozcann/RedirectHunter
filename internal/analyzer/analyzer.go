package analyzer

import (
	"io"
	"net/http"
	"redirecthunter/internal/output"
	"regexp"
	"strings"
	"time"
)

func AnalyzeHTML(url string) {

	client := http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Get(url)
	if err != nil {
		output.PrintError(url, err.Error())
		return
	}
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")
	contenTypeDef := !strings.Contains(contentType, "text/html")
	if contenTypeDef {
		return
	}
	builder := &strings.Builder{}
	_, err = io.Copy(builder, resp.Body)
	if err != nil {
		output.PrintError(url, err.Error())
		return
	}
	html := builder.String()
	var checks = map[string]*regexp.Regexp{
		"<form> tag":   regexp.MustCompile(`(?i)<\s*form\b`),
		"Meta Refresh": regexp.MustCompile(`(?i)<\s*meta[^>]+http-equiv\s*=\s*["']?refresh["']?`),
		"JS Redirect":  regexp.MustCompile(`(?i)window\.location\s*(\.href|\.replace|\.assign)?\s*=`),
	}
	for label, pattern := range checks {
		if pattern.MatchString(html) {
			output.PrintSuspiciousPattern(url, label)
		}
	}
}
