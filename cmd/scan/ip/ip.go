package ip

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/LjungErik/ztr/internal/target"
	"github.com/spf13/cobra"
)

var (
	ErrNoTargetProvided  = errors.New("no valid targets provided")
	ErrNoInterfacesFound = errors.New("no interfaces found")
)

const (
	defaultTimeout = 300 * time.Second
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip <target(s)>",
		Short: "IP command for scanning potential hosts on a network (192.168.1.1, 10.0.0.0/24, 192.168.1.1;172.16.1.1, test.example.com)",
		Args:  cobra.MinimumNArgs(1),
		RunE:  exec,
	}

	return cmd
}

func exec(cmd *cobra.Command, args []string) error {
	targets := target.ParseIPv4(args[0])
	if len(targets) == 0 {
		return ErrNoTargetProvided
	}

	_, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoInterfacesFound, err)
	}

	return nil
}
