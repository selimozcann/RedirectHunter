package statuscolor

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

const (
	colorGreen = "\033[32m"
	colorRed   = "\033[31m"
	colorReset = "\033[0m"
)

func colorFor(status int) string {
	if status == http.StatusFound {
		return colorGreen
	}
	if status == 0 {
		return colorReset
	}
	return colorRed
}

// Sprint returns a colorized status code string (302 -> green, others red).
func Sprint(status int) string {
	if status == 0 {
		return "0"
	}
	return fmt.Sprintf("%s%d%s", colorFor(status), status, colorReset)
}

// PrintChain fetches the target URL and follows up to 10 redirects,
// printing each hop with a color-coded HTTP status code.
func PrintChain(target string) error {
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	for i := 0; i < 10; i++ {
		resp, err := client.Get(target)
		if err != nil {
			return err
		}
		fmt.Printf("%s %s\n", target, Sprint(resp.StatusCode))
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				break
			}
			u, err := url.Parse(loc)
			if err != nil {
				return fmt.Errorf("invalid location: %w", err)
			}
			target = resp.Request.URL.ResolveReference(u).String()
			continue
		}
		break
	}
	return nil
}

// PrintResult prints a pre-fetched redirect chain with color-coded statuses.
func PrintResult(r model.Result) {
	for _, h := range r.Chain {
		fmt.Printf("[%d] %s %s (%s) via %s\n", h.Index, h.URL, Sprint(h.Status), h.Method, h.Via)
	}
}
