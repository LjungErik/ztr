package ip

import (
	"fmt"
	"time"

	"github.com/LjungErik/ztr/internal/target"
	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	defaultTimeout   = 5 * time.Second
	defaultPingCount = 3
)

func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "IP command for scanning potential hosts on a network",
		RunE:  exec,
	}

	return cmd
}

func exec(cmd *cobra.Command, args []string) error {
	t, err := cmd.Flags().GetString("target")
	if err != nil {
		return fmt.Errorf("failed to get target flag: %w", err)
	}

	targetRange := target.Parse(t)
	if len(targetRange) == 0 {
		return fmt.Errorf("no valid targets provided")
	}

	for _, target := range targetRange {
		if err := sendPing(target, defaultTimeout, defaultPingCount); err != nil {
			return fmt.Errorf("failed to send ping to %s: %w", target, err)
		}
	}

	return nil
}

func sendPing(target string, timeout time.Duration, pingCount int) error {
	conn, err := icmp.ListenPacket("ip4:icmp", target)
	if err != nil {
		return fmt.Errorf("failed to listen on target %s: %w", target, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	successCount := 0

	for i := 0; i < pingCount; i++ {
		if err := sendIPv4ICMPRequest(conn, target); err != nil {
			fmt.Printf("Ping to %s failed: %v\n", target, err)
			continue
		}

		successCount++
	}

	if successCount == 0 {
		return fmt.Errorf("all pings to %s failed", target)
	}

	return nil
}

func sendIPv4ICMPRequest(conn *icmp.PacketConn, target string) error {
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("ping"),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	if _, err := conn.WriteTo(wb, nil); err != nil {
		return fmt.Errorf("failed to send ICMP message to %s: %w", target, err)
	}

	rb := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(rb)
	if err != nil {
		return fmt.Errorf("failed to read ICMP response: %w", err)
	}

	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP response: %w", err)
	}

	if rm.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Errorf("received non-echo reply from %s: %v", peer, rm.Type)
	}

	return nil
}
