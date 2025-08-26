package banner

import (
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
)

func PrintBanner() {
	myFigure := figure.NewColorFigure("RHUNTER", "doom", "red", true)
	myFigure.Print()

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)

	_, _ = cyan.Println("════════════════════════════════════════════════")
	_, _ = green.Println("    Security Research Tool | Author: https://github.com/selimozcann")
	_, _ = cyan.Println("════════════════════════════════════════════════")
}
