// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package ioutil

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestWithDeadlineReturnsBeforeWorker(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			done := make(chan error, 1)
			go func() {
				value, err := WithDeadline(ctx, time.Second, func(context.Context) (int, error) {
					close(entered)
					<-release
					return 42, nil
				})
				if value != 0 {
					t.Errorf("timeout returned a late worker value: %d", value)
				}
				done <- err
			}()
			<-entered
			want := context.DeadlineExceeded
			if cancelEarly {
				cancel()
				want = context.Canceled
			} else {
				time.Sleep(2 * time.Second)
			}
			synctest.Wait()
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("expected %v, got %v", want, err)
				}
			default:
				t.Fatal("caller still waits for the blocked worker")
			}
		})
	}
}

func TestWithDeadlineContainsPanic(t *testing.T) {
	value, err := WithDeadline(t.Context(), time.Second, func(context.Context) (int, error) {
		panic("deadline-test")
	})
	if value != 0 || err == nil || !strings.Contains(err.Error(), "deadline-test") {
		t.Fatalf("panic was not converted to an error: %d, %v", value, err)
	}
}
