package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"redirecthunter/internal/scanner"
)

var inputFile string

var rootCmd = &cobra.Command{
	Use:   "redirectHunter",
	Short: "Scan URLs for redirect chains",
	Run: func(cmd *cobra.Command, args []string) {
		if inputFile == "" {
			fmt.Println("Please provide a input file")
			os.Exit(1)
		}
		err := scanner.RunScan(inputFile)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func Execute() {
	rootCmd.Flags().StringVarP(&inputFile, "file", "f", "", "Input file")
	_ = rootCmd.MarkFlagRequired("file")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
