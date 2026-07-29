package main

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// startPprofServer binds a tiny HTTP server on addr that serves the standard
// net/http/pprof handlers. It returns once the listener is bound so callers
// know the endpoint is reachable; the server then runs in a background
// goroutine for the rest of the process lifetime.
//
// Only intended for benchmarking / debugging — the caller (CLI flag) gates
// this off by default and the docs warn that it must not be exposed on a
// public network.
func startPprofServer(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			slog.Warn("pprof server stopped", "error", err)
		}
	}()

	return nil
}
