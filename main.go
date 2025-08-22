package main

import (
	"fmt"

	"github.com/LjungErik/ztr/cmd/scan"
	"github.com/spf13/cobra"
)

var (
	buildVersion = "dev"
	commitHash   = "--"

	cmd = &cobra.Command{
		Use:     "ztr",
		Short:   "ZTR tool for performing network reconnaissance",
		Version: fmt.Sprintf("%s (%s)", buildVersion, commitHash),
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}
)

func init() {
	cmd.AddCommand(scan.Command())
	// Add other commands here as needed
}

func main() {
	cobra.CheckErr(cmd.Execute())
}
