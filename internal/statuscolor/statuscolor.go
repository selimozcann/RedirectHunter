package statuscolor

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/selimozcann/RedirectHunter/internal/model"
)

const (
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorGray   = "\033[90m"
	colorReset  = "\033[0m"
)

func colorFor(status int) string {
	switch status {
	case http.StatusFound:
		return colorGreen
	case http.StatusOK:
		return colorYellow
	case http.StatusNotFound:
		return colorRed
	case 0:
		return colorReset
	default:
		if status >= 400 {
			return colorRed
		}
		return colorYellow
	}
}

// Sprint returns a colorized status code string (302 -> green, others red).
func Sprint(status int) string {
	if status == 0 {
		return fmt.Sprintf("%s—%s", colorGray, colorReset)
	}
	return fmt.Sprintf("%s%d%s", colorFor(status), status, colorReset)
}

// WrapByStatus wraps the provided text with the color that corresponds to the
// supplied status code.
func WrapByStatus(text string, status int) string {
	return fmt.Sprintf("%s%s%s", colorFor(status), text, colorReset)
}

// Gray wraps the provided text with a gray ANSI color.
func Gray(text string) string {
	return fmt.Sprintf("%s%s%s", colorGray, text, colorReset)
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
