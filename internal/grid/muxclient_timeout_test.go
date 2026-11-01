// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package grid

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestSingleRequestDefaultTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &Connection{outQueue: make(chan []byte, 1)}
		client := newMuxClient(t.Context(), 1, conn)
		defer client.cancelFn(context.Canceled)
		done := make(chan error, 1)
		go func() { _, err := client.roundtrip(handlerTest, nil); done <- err }()
		wire := <-conn.outQueue
		var request message
		if _, err := request.UnmarshalMsg(wire); err != nil {
			t.Fatal(err)
		}
		PutByteBuffer(wire)
		if request.DeadlineMS != uint32(defaultSingleRequestTimeout/time.Millisecond) {
			t.Fatalf("wire deadline: %d", request.DeadlineMS)
		}
		time.Sleep(defaultSingleRequestTimeout + time.Second)
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		default:
			t.Fatal("request outlived the default timeout")
		}
	})
}

func TestSingleRequestCancellationAndDisconnect(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit-cancel", true: "disconnect"}[disconnect], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				conn := &Connection{outQueue: make(chan []byte, 1)}
				client := newMuxClient(ctx, 1, conn)
				defer client.cancelFn(context.Canceled)
				done := make(chan error, 1)
				go func() {
					_, err := client.roundtrip(handlerTest, nil)
					done <- err
				}()
				PutByteBuffer(<-conn.outQueue)
				want := context.Canceled
				if disconnect {
					client.close()
					want = ErrDisconnected
				} else {
					cancel()
				}
				if got := <-done; !errors.Is(got, want) {
					t.Fatalf("request did not terminate correctly: want %v, got %v", want, got)
				}
			})
		})
	}
}
