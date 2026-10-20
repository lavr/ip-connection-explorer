package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// metricsServer serves only the metrics path: no default mux, so nothing else (pprof) leaks.
type metricsServer struct {
	srv    *http.Server
	addr   net.Addr
	failed chan error
	done   chan struct{}
}

func startMetricsServer(addr, path string, h http.Handler) (*metricsServer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(path, h)
	ms := &metricsServer{
		srv: &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute},
		addr:   ln.Addr(),
		failed: make(chan error, 1),
		done:   make(chan struct{}),
	}
	go func() {
		defer close(ms.done)
		if err := ms.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
			ms.failed <- err
		}
	}()
	return ms, nil
}

func (ms *metricsServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ms.srv.Shutdown(ctx) != nil {
		ms.srv.Close()
	}
	<-ms.done
}
