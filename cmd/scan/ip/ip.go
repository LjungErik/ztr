package ip

import (
	"fmt"
	"net"
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
		Use:   "ip <target(s)>",
		Short: "IP command for scanning potential hosts on a network (192.168.1.1, 10.0.0.0/24, 192.168.1.1;172.16.1.1, test.example.com)",
		Args:  cobra.MinimumNArgs(1),
		RunE:  exec,
	}

	return cmd
}

func exec(cmd *cobra.Command, args []string) error {
	targetRange := target.Parse(args[0])
	if len(targetRange) == 0 {
		return fmt.Errorf("no valid targets provided")
	}

	timeout := defaultTimeout

	for _, target := range targetRange {
		sendPing(target, timeout, defaultPingCount)
	}

	return nil
}

func sendPing(target *net.IPAddr, timeout time.Duration, pingCount int) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("failed to listen for ipv4 ICMP packets: %v\n", err)
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
		fmt.Printf("all pings to %s failed\n", target)
		return
	}

	fmt.Printf("Successfully pinged %s %d times\n", target, successCount)
}

func sendIPv4ICMPRequest(conn *icmp.PacketConn, target *net.IPAddr) error {
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

	if _, err := conn.WriteTo(wb, target); err != nil {
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
