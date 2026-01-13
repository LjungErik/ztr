package ip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	ErrContextCancelled = errors.New("context cancelled before IP scan finshed")
)

const (
	probeRefreshCheckInterval = 100 * time.Millisecond
)

type IPScanner interface {
	Run(ctx context.Context) error
	Results() []TargetResult
}

type scanner struct {
	targets      []net.IP
	nw           network.Network
	bpf          string
	sendProbes   chan net.IP
	activeProbes sync.Map
	results      map[string]TargetResult
	sourceIP     net.IP
	sourceHwAddr net.HardwareAddr
}

func NewIPScanner(targets []net.IP, nw network.Network) IPScanner {
	iface := nw.NetworkInterface()

	return &scanner{
		targets:      targets,
		nw:           nw,
		bpf:          "arp",
		sourceIP:     iface.GetIPv4(),
		sourceHwAddr: iface.GetHwAddress(),
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

func (s *scanner) Results() []TargetResult {
	var out = make([]TargetResult, 0, len(s.results))

	for _, v := range s.results {
		out = append(out, v)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].IP.String() < out[j].IP.String()
	})

	return out
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
	// For now we only support ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp := arpLayer.(*layers.ARP)
		key := string(arp.SourceProtAddress)
		val, ok := s.results[key]
		if !ok {
			val = TargetResult{
				IP:             arp.SourceProtAddress,
				CompletedScans: 0,
			}
		}

		val.HwAddr = arp.SourceHwAddress
		val.CompletedScans = val.CompletedScans | ARPScan

		s.results[key] = val
	}

	return nil
}

func (s *scanner) sendProbe(target net.IP) error {
	// Only send ARP requests for now
	arp := NewARPRequest(s.sourceIP, target, s.sourceHwAddr)

	payload, err := arp.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ARP request: %w", err)
	}

	if err := s.nw.SendPacket(payload); err != nil {
		return fmt.Errorf("failed to send package: %w", err)
	}

	return nil
}

func (s *scanner) hasFinished() bool {
	return len(s.results) == len(s.targets)
}
