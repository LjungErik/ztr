package ip

import "net"

const (
	ARPScan = 1
	TCPScan = 2
)

type TargetBatches struct {
	targets    map[string]net.IP
	batches    [][]net.IP
	currentIdx int
	batchSize  int
}

func NewTargetBatches(targets []net.IP, batchSize int) *TargetBatches {
	m := make(map[string]net.IP, len(targets))

	for _, t := range targets {
		m[t.String()] = t
	}

	return &TargetBatches{
		targets:    m,
		batches:    nil,
		currentIdx: 0,
		batchSize:  batchSize,
	}
}

func (t *TargetBatches) NextBatch() []net.IP {
	if t.currentIdx > (len(t.batches) - 1) {
		t.generateNewBatches()
	}

	idx := t.currentIdx
	t.currentIdx += 1

	return t.batches[idx]
}

func (t *TargetBatches) generateNewBatches() {
	newBatches := make([][]net.IP, 0, (len(t.targets)/t.batchSize + 1))
	currentBatch := make([]net.IP, 0, t.batchSize)
	idx := 0
	batchIdx := 0

	for _, v := range t.targets {
		currentBatch = append(currentBatch, v)
		batchIdx = (batchIdx + 1) % t.batchSize

		if batchIdx == 0 {
			newBatches[idx] = currentBatch
			currentBatch = make([]net.IP, 0, t.batchSize)
			idx += 1
		}
	}

	t.batches = newBatches
	t.currentIdx = 0
}
