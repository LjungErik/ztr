package scan

import (
	"github.com/LjungErik/ztr/cmd/scan/ip"
	"github.com/LjungErik/ztr/cmd/scan/port"
	"github.com/spf13/cobra"
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan command for scanning network resources",
	}

	cmd.AddCommand(port.Command())
	cmd.AddCommand(ip.Command())

	return cmd
}
