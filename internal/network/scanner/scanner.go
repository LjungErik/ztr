package scanner

import "context"

type NetworkScanner interface {
	Start(ctx context.Context)
}
