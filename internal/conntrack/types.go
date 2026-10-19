package conntrack

import "errors"

var ErrQueueFull = errors.New("conntrack event queue full")

type DumpStats struct {
	Interrupted  int
	DecodeErrors int
}
