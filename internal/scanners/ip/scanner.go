package ip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	"github.com/google/gopacket"
)

var (
	ErrContextCancelled = errors.New("context cancelled before IP scan finshed")
)

const (
	probeRefreshCheckInterval = 100 * time.Millisecond
)

type IPScanner interface {
	Run(ctx context.Context) error
}

type scanner struct {
	targets      []net.IP
	nw           network.Network
	bpf          string
	sendProbes   chan net.IP
	activeProbes sync.Map
}

func NewIPScanner(targets []net.IP, nw network.Network) IPScanner {
	return &scanner{
		targets: targets,
		nw:      nw,
		bpf:     "",
	}
}

func (s *scanner) Run(ctx context.Context) error {
	pktSrc, err := s.nw.StartCapture(s.bpf)
	if err != nil {
		return fmt.Errorf("failed to start package capture: %w", err)
	}

	defer s.nw.Close()

	for _, target := range s.targets {
		s.activeProbes.Store(target.String(), &TargetState{
			Confirmed: false,
			LastSent:  time.Time{},
			IP:        target,
			Retries:   -1,
		})
	}

	packets := pktSrc.Packets()
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		s.trackActiveProbes(ctx)
		wg.Done()
	}()

	if err = s.run(ctx, packets); err != nil {
		return fmt.Errorf("failed to listen for packet: %w", err)
	}

	wg.Wait()

	return nil
}

func (s *scanner) run(ctx context.Context, packets chan gopacket.Packet) error {
	for !s.hasFinished() {
		select {
		case <-ctx.Done():
			return ErrContextCancelled
		case packet := <-packets:
			if err := s.handlePacket(packet); err != nil {
				log.Debugf("Failed to handle package: %w", err)
			}
		case probTarget := <-s.sendProbes:
			if err := s.sendProbe(probTarget); err != nil {
				log.Debugf("Failed to send probe: %w", err)
			}
		}
	}

	return nil
}

func (s *scanner) trackActiveProbes(ctx context.Context) {
	s.resendCheck()

	ticker := time.NewTicker(probeRefreshCheckInterval)

	for {
		select {
		case <-ctx.Done():
			log.Debugf("context has cancelled, stopping active probe tracking")
		case <-ticker.C:
			s.resendCheck()
		}
	}
}

func (s *scanner) resendCheck() {
	s.activeProbes.Range(func(key, value interface{}) bool {
		state := value.(*TargetState)
		if !state.Confirmed && time.Since(state.LastSent) > retryInterval {
			if state.Retries < maxRetries {
				state.Retries++
				state.LastSent = time.Now()
				s.sendProbes <- state.IP
			} else {
				s.activeProbes.Delete(key)
			}
		}

		return true
	})
}

func (s *scanner) handlePacket(packet gopacket.Packet) error {
	// Check package type

	return nil
}

func (s *scanner) sendProbe(target net.IP) error {
	return nil
}

func (s *scanner) hasFinished() bool {
	return false
}
