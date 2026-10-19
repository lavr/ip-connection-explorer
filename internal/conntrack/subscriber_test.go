//go:build linux

package conntrack

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	ct "github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"go.uber.org/goleak"

	"github.com/lavr/ip-connection-explorer/internal/flows"
)

var errFakeClosed = errors.New("fake: socket closed")

// fakeLib mimics ti-mo/conntrack: unbuffered error channel, blocking sends, Close waits for the worker.
type fakeLib struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	gen    func(i int) (ct.Event, error)
}

func (f *fakeLib) Listen(evChan chan<- ct.Event, n uint8, _ []netfilter.NetlinkGroup) (chan error, error) {
	errChan := make(chan error)
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for i := 0; ; i++ {
			if f.isClosed() {
				errChan <- errFakeClosed
				return
			}
			ev, err := f.gen(i)
			if err != nil {
				errChan <- err
				continue
			}
			evChan <- ev
		}
	}()
	return errChan, nil
}

func (f *fakeLib) isClosed() bool          { f.mu.Lock(); defer f.mu.Unlock(); return f.closed }
func (f *fakeLib) SetReadBuffer(int) error { return nil }
func (f *fakeLib) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.wg.Wait()
	return nil
}

func tcpEvent() ct.Event {
	fl := ct.NewFlow(6, ct.StatusSeenReply, netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.5"), 40000, 443, 60, 0)
	return ct.Event{Type: ct.EventNew, Flow: &fl}
}

func subscribe(t *testing.T, lib *fakeLib, queue int) *Subscription {
	t.Helper()
	s := &Subscriber{Dial: func() (RawListener, error) { return lib, nil }, QueueSize: queue, Now: time.Now}
	sub, err := s.Subscribe(3)
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func TestCloseWhileWorkerBlockedOnEventSend(t *testing.T) {
	defer goleak.VerifyNone(t)
	lib := &fakeLib{gen: func(int) (ct.Event, error) { return tcpEvent(), nil }}
	sub := subscribe(t, lib, 4)
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sub.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	for range sub.Events() {
	}
}

func TestCloseWhileWorkerBlockedOnErrorSend(t *testing.T) {
	defer goleak.VerifyNone(t)
	lib := &fakeLib{gen: func(int) (ct.Event, error) { return ct.Event{}, syscall.ENOBUFS }}
	sub := subscribe(t, lib, 4)
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sub.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestFirstErrorReported(t *testing.T) {
	defer goleak.VerifyNone(t)
	lib := &fakeLib{gen: func(i int) (ct.Event, error) {
		if i == 0 {
			return ct.Event{}, syscall.ENOBUFS
		}
		return tcpEvent(), nil
	}}
	sub := subscribe(t, lib, 4096)
	select {
	case err := <-sub.Err():
		if !errors.Is(err, syscall.ENOBUFS) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no error")
	}
	_ = sub.Close(context.Background())
}

func TestEventsConvertedWithEpoch(t *testing.T) {
	defer goleak.VerifyNone(t)
	lib := &fakeLib{gen: func(int) (ct.Event, error) { return tcpEvent(), nil }}
	sub := subscribe(t, lib, 16)
	ev := <-sub.Events()
	if ev.Kind != flows.EventNew || ev.Epoch != 3 || ev.Flow.Orig.Dst.Port != 443 || !ev.Flow.SeenReply || ev.At.IsZero() {
		t.Fatalf("%+v", ev)
	}
	_ = sub.Close(context.Background())
}

func TestQueueFullCounted(t *testing.T) {
	defer goleak.VerifyNone(t)
	lib := &fakeLib{gen: func(int) (ct.Event, error) { return tcpEvent(), nil }}
	sub := subscribe(t, lib, 1)
	select {
	case err := <-sub.Err():
		if !errors.Is(err, ErrQueueFull) {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no queue-full error")
	}
	if sub.Dropped() == 0 {
		t.Fatal("dropped not counted")
	}
	_ = sub.Close(context.Background())
}
