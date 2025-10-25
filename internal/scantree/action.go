package scantree

import (
	"context"
	"net"

	"github.com/LjungErik/ztr/internal/network"
)

type IPScanNode interface {
	Evaluate(ctx context.Context, target net.IP, n network.Network) error
	IsFinished() bool
	Result() ScanResult
}

type ScanResult struct {
	Success bool
	Data    map[string]interface{}
}

func JoinResults(left, right ScanResult) ScanResult {
	result := ScanResult{
		Success: left.Success && right.Success,
		Data:    make(map[string]interface{}),
	}

	for k, v := range left.Data {
		result.Data[k] = v
	}

	for k, v := range right.Data {
		result.Data[k] = v
	}

	return result
}
