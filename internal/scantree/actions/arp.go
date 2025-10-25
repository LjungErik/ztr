package actions

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/LjungErik/ztr/internal/log"
	"github.com/LjungErik/ztr/internal/network"
	"github.com/LjungErik/ztr/internal/scantree"

	arp_filter "github.com/LjungErik/ztr/internal/network/filter/arp"
	arp_request "github.com/LjungErik/ztr/internal/network/request/arp"
)

var (
	ErrNoRetriesLeft  = errors.New("no retries left for ARP scan")
	ErrNoFilterFound  = errors.New("no ARP filter found")
	ErrFilterMismatch = errors.New("ARP filter type mismatch")
)

const (
	defaultRetryInterval = time.Millisecond * 50
)

type ARPScanAction struct {
	RetriesLeft int
	lastAttempt time.Time
	result      *scantree.ScanResult
	target      net.IP
}

func (a *ARPScanAction) Evaluate(ctx context.Context, nw network.Network) error {
	if err := a.tryHandleNextResult(nw); err != nil {
		return err
	}

	if a.result != nil {
		return nil
	}

	if a.lastAttempt.Add(defaultRetryInterval).After(time.Now()) {
		return nil
	}

	if a.RetriesLeft <= 0 {
		a.result = &scantree.ScanResult{
			Success: false,
		}

		return ErrNoRetriesLeft
	}

	if err := a.sendRequest(ctx, nw); err != nil {
		log.Errorf("failed to send ARP request: %v", err)

		return nil
	}

	a.lastAttempt = time.Now()
	a.RetriesLeft--

	return nil
}

func (a *ARPScanAction) IsFinished() bool {
	return a.result != nil
}

func (a *ARPScanAction) Result() scantree.ScanResult {
	if a.result != nil {
		return *a.result
	}

	return scantree.ScanResult{
		Success: false,
	}
}

func (a *ARPScanAction) tryHandleNextResult(nw network.Network) error {
	if a.result != nil {
		return nil
	}

	filter, ok := nw.GetFilter("arp")
	if !ok {
		log.Errorf("ARP filter not found in network")
		return ErrNoFilterFound
	}

	arpFilter, ok := filter.(*arp_filter.ARPNetworkFilter)
	if !ok {
		log.Errorf("failed to cast to ARPNetworkFilter")
		return ErrFilterMismatch
	}

	result := arpFilter.NextResultForMatch(a.target)

	a.result = &scantree.ScanResult{
		Success: true,
		Data: map[string]interface{}{
			"target_ip":      result.TargetIP,
			"target_hw_addr": result.TargetHwAddr,
		},
	}

	return nil
}

func (a *ARPScanAction) sendRequest(_ context.Context, nw network.Network) error {
	sourceIPv4 := nw.NetworkInterface().GetIPv4()
	sourceHwAddr := nw.NetworkInterface().GetHwAddress()

	arp := arp_request.NewARPRequest(sourceIPv4, a.target, sourceHwAddr)

	payload, err := arp.Marshal()
	if err != nil {
		return err
	}

	if err = nw.Send(payload); err != nil {
		return err
	}

	return nil
}
