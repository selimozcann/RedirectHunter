package main

import (
	"fmt"
	"os"

	"github.com/selimozcann/RedirectHunter/internal/statuscolor"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	if err := statuscolor.PrintChain(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
