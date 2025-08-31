/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "xdp-inspector",
	Short: "Small packet inspector based on XDP/eBPF",
	Long:  ``,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd.AddCommand(RecordCommand())
	rootCmd.AddCommand(NewStatsCommand())

	err := rootCmd.Execute()

	if err != nil {
		os.Exit(1)
	}
}
