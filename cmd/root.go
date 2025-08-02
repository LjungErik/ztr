package cmd

import (
	"fmt"

	"github.com/LjungErik/ztr/cmd/scan"
	"github.com/spf13/cobra"
)

var (
	buildVersion = "dev"
	commitHash   = "--"

	rootCmd = &cobra.Command{
		Use:     "ztr",
		Short:   "ZTR tool for performing network reconnaissance",
		Version: fmt.Sprintf("%s (%s)", buildVersion, commitHash),
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
)

func init() {
	rootCmd.AddCommand(scan.Command())
	// Add other commands here as needed
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
