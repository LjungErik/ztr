package ip

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	"github.com/google/gopacket"
)

var (
	ErrContextCancelled = errors.New("context cancelled before IP scan finshed")
)

type IPScanner interface {
	Run(ctx context.Context) error
}

type scanner struct {
	targets []net.IP
	nw      network.Network
	bpf     string
}

func NewIPScanner(targets []net.IP, nw network.Network) IPScanner {
	return &scanner{
		targets: targets,
		nw:      nw,
		bpf:     "",
	}
}

func (s *scanner) Run(ctx context.Context) error {
	if err := s.nw.StartCapture(s.bpf); err != nil {
		return fmt.Errorf("failed to start package capture: %w", err)
	}

	defer s.nw.Close()

	for !s.hasFinished() {
		select {
		case <-ctx.Done():
			return ErrContextCancelled
		default:
			if err := s.run(ctx); err != nil {
				log.Errorf("IP Scan returned with error: %v", err)
			}
		}
	}

	return nil
}

func (s *scanner) run(_ context.Context) error {
	packet, err := s.nw.ReadNextPacket()
	if err != nil {
		return fmt.Errorf("failed to read next package: %w", err)
	}

	if err = s.handlePacket(packet); err != nil {
		return fmt.Errorf("failed to handle packet: %w", err)
	}

	if err = s.sendNextBatch(); err != nil {
		return fmt.Errorf("failed to send next batch: %w", err)
	}

	return nil
}

func (s *scanner) handlePacket(packet gopacket.Packet) error {
	// Check package type

	return nil
}

func (s *scanner) sendNextBatch() error {
	return nil
}

func (s *scanner) hasFinished() bool {
	return false
}
