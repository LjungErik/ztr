package scantree

import (
	"context"
	"net"

	"github.com/LjungErik/ztr/internal/network"
	"github.com/LjungErik/ztr/internal/scantree"
)

type BinaryOperation struct {
	Left  scantree.IPScanNode
	Right scantree.IPScanNode
}

type JoinOperation struct {
	BinaryOperation
}

func (op *JoinOperation) Evaluate(ctx context.Context, target net.IP, nw network.Network) error {
	leftResult := op.Left.Evaluate(ctx, target, nw)
	rightResult := op.Right.Evaluate(ctx, target, nw)

	if leftResult != nil {
		return leftResult
	}

	if rightResult != nil {
		return rightResult
	}

	return nil
}

func (op *JoinOperation) IsFinished() bool {
	return op.Left.IsFinished() && op.Right.IsFinished()
}

func (op *JoinOperation) Result() scantree.ScanResult {
	leftResult := op.Left.Result()
	rightResult := op.Right.Result()

	return scantree.JoinResults(leftResult, rightResult)
}

type LeftJoinOperation struct {
	BinaryOperation
}

func (op *LeftJoinOperation) Evaluate(ctx context.Context, target net.IP, nw network.Network) error {
	leftResult := op.Left.Evaluate(ctx, target, nw)
	if leftResult != nil {
		return leftResult
	}

	return op.Right.Evaluate(ctx, target, nw)
}

func (op *LeftJoinOperation) IsFinished() bool {
	return op.Left.IsFinished() && op.Right.IsFinished()
}

func (op *LeftJoinOperation) Result() scantree.ScanResult {
	leftResult := op.Left.Result()
	rightResult := op.Right.Result()

	if !rightResult.Success {
		return leftResult
	}

	return scantree.JoinResults(leftResult, rightResult)
}

type ExclusiveOperation struct {
	BinaryOperation
}

func (op *ExclusiveOperation) Evaluate(ctx context.Context, target net.IP, nw network.Network) error {
	leftResult := op.Left.Evaluate(ctx, target, nw)
	if leftResult == nil {
		return nil
	}

	return op.Right.Evaluate(ctx, target, nw)
}

func (op *ExclusiveOperation) IsFinished() bool {
	return op.Left.IsFinished() || op.Right.IsFinished()
}

func (op *ExclusiveOperation) Result() scantree.ScanResult {
	leftResult := op.Left.Result()
	if leftResult.Success {
		return leftResult
	}

	return op.Right.Result()
}
