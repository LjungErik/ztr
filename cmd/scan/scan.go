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

	cmd.Flags().StringP("target", "t", "", "-t <target(s)> Specify target(s) to scan (192.168.1.1, 10.0.0.0/24, 192.168.1.1;172.16.1.1, test.example.com)")
	cmd.MarkFlagRequired("target")

	return cmd
}
