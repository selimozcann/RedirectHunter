package output

import (
	"fmt"
)

func PrintRedirectStep(url string, code int) {
	fmt.Printf("  ↪ %s → %d\n", url, code)
}

func PrintFinalURL(url string) {
	fmt.Printf("\033[32m  ✔ Final URL reached: %s\033[0m\n", url)
}

func PrintError(url, err string) {
	fmt.Printf("\033[31m  [!] Error at %s: %s\033[0m\n", url, err)
}

func PrintLoopDetected() {
	fmt.Printf("\033[33m  [!] Redirect loop detected\033[0m\n")
}

func PrintNoLocation() {
	fmt.Printf("\033[33m  [!] Redirect without Location header\033[0m\n")
}

func PrintScanHeader(url string) {
	fmt.Printf("\n[+] Scanning: %s\n", url)
}
func PrintRedirectToDifferentDomain(url string) {
	fmt.Printf("\033[33m  ↪ [DEBUG] Redirected to different domain: %s\033[0m\n", url)
}
