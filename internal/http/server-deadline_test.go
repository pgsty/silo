// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package http

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startDeadlineTestServer starts a full xhttp server (listener + wrapped
// handler, mirroring the server-main timeout layout) on an ephemeral port.
func startDeadlineTestServer(t *testing.T, handler http.Handler, idle, readHeaderTimeout time.Duration) string {
	t.Helper()

	srv := NewServer([]string{"127.0.0.1:0"}).
		UseHandler(handler).
		UseIdleTimeout(idle).
		UseWriteTimeout(idle).
		UseReadHeaderTimeout(readHeaderTimeout).
		// Mirror server-main, which routes the idle timeout to the listener
		// (and from there to deadlineconn) through TCPOptions.
		UseTCPOptions(TCPOptions{IdleTimeout: idle})

	serveFn, err := srv.Init(context.Background(), func(listenAddr string, err error) {
		t.Fatalf("listen %s: %v", listenAddr, err)
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	go serveFn()
	t.Cleanup(func() { srv.Shutdown() })

	srv.listenerMutex.Lock()
	defer srv.listenerMutex.Unlock()
	return srv.listener.Addr().String()
}

// A client that keeps trickling header bytes must have its connection cut
// once ReadHeaderTimeout elapses in total, not per byte.
func TestServerSlowHeaderConnectionKilled(t *testing.T) {
	addr := startDeadlineTestServer(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		5*time.Second, 1*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a partial header line, then dribble one byte at a time well
	// within the idle timeout, so only the absolute deadline can kill it.
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ")); err != nil {
		t.Fatalf("write header: %v", err)
	}
	go func() {
		for i := 0; ; i++ {
			if _, err := conn.Write([]byte{byte('a' + i%26)}); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("slow-header connection survived %v, want it closed within ReadHeaderTimeout+slack", elapsed)
	}
}

// A request whose body stalls mid-transfer must be cut off by the per-read
// idle deadline, while the handler observes the read error.
func TestServerStalledRequestBodyKilled(t *testing.T) {
	bodyResult := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		bodyResult <- err
	})
	addr := startDeadlineTestServer(t, handler, 1*time.Second, 1*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	head := "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n"
	if _, err := conn.Write([]byte(head + strings.Repeat("x", 10))); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Stall: no further body bytes are ever sent.

	select {
	case err := <-bodyResult:
		if err == nil {
			t.Fatal("handler completed a request whose body stalled forever")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stalled body kept the handler blocked past the idle deadline")
	}
}

// A body that keeps making progress, even slower than the idle timeout in
// total, must complete: the deadline is per-read activity, never absolute.
func TestServerSlowProgressingBodyAccepted(t *testing.T) {
	bodyResult := make(chan int, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		bodyResult <- int(n)
	})
	addr := startDeadlineTestServer(t, handler, 500*time.Millisecond, 1*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	const total = 100
	head := "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n\r\n"
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// 20ms per byte: the whole body takes 2s, four times the idle timeout,
	// but every inter-byte gap stays far below it.
	go func() {
		for i := 0; i < total; i++ {
			if _, err := conn.Write([]byte{'y'}); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	select {
	case n := <-bodyResult:
		if n != total {
			t.Fatalf("handler read %d bytes, want %d", n, total)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("progressing slow body was terminated")
	}
}
