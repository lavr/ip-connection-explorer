//go:build linux

package conntrack

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/lavr/ip-connection-explorer/internal/flows"
)

var ErrQueueFull = errors.New("conntrack event queue full")

// RawListener is the subset of *conntrack.Conn used for events.
type RawListener interface {
	Listen(evChan chan<- ct.Event, numWorkers uint8, groups []netfilter.NetlinkGroup) (chan error, error)
	SetReadBuffer(bytes int) error
	Close() error
}

type Subscriber struct {
	Dial       func() (RawListener, error)
	ReadBuffer int
	QueueSize  int
	Now        func() time.Time
}

type Subscription struct {
	lib     RawListener
	libEv   chan ct.Event
	libErr  chan error
	out     chan flows.CTEvent
	errc    chan error
	closing chan struct{}
	done    chan struct{}
	once    sync.Once
	epoch   uint64
	now     func() time.Time
	dropped atomic.Uint64

	BufferErr error
	closeErr  error
}

func (s *Subscriber) Subscribe(epoch uint64) (*Subscription, error) {
	lib, err := s.Dial()
	if err != nil {
		return nil, err
	}
	queue := s.QueueSize
	if queue <= 0 {
		queue = 4096
	}
	now := s.Now
	if now == nil {
		now = time.Now
	}
	sub := &Subscription{
		lib:     lib,
		libEv:   make(chan ct.Event, 1024),
		out:     make(chan flows.CTEvent, queue),
		errc:    make(chan error, 1),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
		epoch:   epoch,
		now:     now,
	}
	if s.ReadBuffer > 0 {
		sub.BufferErr = lib.SetReadBuffer(s.ReadBuffer)
	}
	sub.libErr, err = lib.Listen(sub.libEv, 1, netfilter.GroupsCT)
	if err != nil {
		lib.Close()
		return nil, err
	}
	go sub.pump()
	return sub, nil
}

func (s *Subscription) Events() <-chan flows.CTEvent { return s.out }
func (s *Subscription) Err() <-chan error            { return s.errc }
func (s *Subscription) Dropped() uint64              { return s.dropped.Load() }

// pump is the only reader of the library channels. The library sends on both channels
// with blocking sends and Close waits for its worker, so both channels must be drained
// until Close returns, or shutdown deadlocks.
func (s *Subscription) pump() {
loop:
	for {
		select {
		case ev := <-s.libEv:
			s.forward(ev)
		case err := <-s.libErr:
			s.report(err)
		case <-s.closing:
			break loop
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- s.lib.Close() }()
	for {
		select {
		case ev := <-s.libEv:
			s.forward(ev)
		case <-s.libErr:
		case err := <-closed:
			s.closeErr = err
			close(s.out)
			close(s.done)
			return
		}
	}
}

func (s *Subscription) forward(ev ct.Event) {
	if ev.Flow == nil {
		return
	}
	var kind flows.EventKind
	switch ev.Type {
	case ct.EventNew:
		kind = flows.EventNew
	case ct.EventUpdate:
		kind = flows.EventUpdate
	case ct.EventDestroy:
		kind = flows.EventDestroy
	default:
		return
	}
	select {
	case s.out <- flows.CTEvent{Kind: kind, At: s.now(), Epoch: s.epoch, Flow: Convert(*ev.Flow)}:
	default:
		s.dropped.Add(1)
		s.report(ErrQueueFull)
	}
}

func (s *Subscription) report(err error) {
	select {
	case s.errc <- err:
	default:
	}
}

// Close stops the subscription. Events() is closed once the library has shut down.
func (s *Subscription) Close(ctx context.Context) error {
	s.once.Do(func() { close(s.closing) })
	select {
	case <-s.done:
		return s.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}
