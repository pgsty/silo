// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio/internal/bucket/versioning"
	"github.com/minio/minio/internal/grid"
	xhttp "github.com/minio/minio/internal/http"
)

// A server answers the capability question over the grid. One that does not
// know it, as an older server, or answers something else, blocks native
// restore, and so does one that is not connected.
func TestNativeRestoreCapabilityGrid(t *testing.T) {
	tg, err := grid.SetupTestGrid(4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tg.Cleanup)
	if err := restoreCapabilityRPC.Register(tg.Managers[1], restoreCapabilityHandler); err != nil {
		t.Fatal(err)
	}
	// Managers[2] never registers the handler.
	if err := restoreCapabilityRPC.Register(tg.Managers[3], func(*grid.MSS) (*grid.MSS, *grid.RemoteErr) {
		return grid.NewMSSWith(map[string]string{peerRESTRestoreCapability: "0"}), nil
	}); err != nil {
		t.Fatal(err)
	}
	peer := func(i int) restoreCapabilityPeer {
		return restorePeerClient{&peerRESTClient{gridConn: func() *grid.Connection { return tg.Managers[0].Connection(tg.Hosts[i]) }}}
	}
	offline := restorePeerClient{&peerRESTClient{gridConn: func() *grid.Connection { return nil }}}
	for _, tc := range []struct {
		name  string
		peers []restoreCapabilityPeer
		ok    bool
	}{
		{"single-server", nil, true},
		{"all-capable", []restoreCapabilityPeer{peer(1)}, true},
		{"older-server", []restoreCapabilityPeer{peer(1), peer(2)}, false},
		{"other-answer", []restoreCapabilityPeer{peer(1), peer(3)}, false},
		{"offline", []restoreCapabilityPeer{peer(1), offline}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return tc.peers }}
			if err := g.check(t.Context()); (err == nil) != tc.ok {
				t.Errorf("capability: %v, want available=%v", err, tc.ok)
			}
		})
	}
}

// restoreCapabilityFake is a server whose connection and answer a test sets.
type restoreCapabilityFake struct {
	capable   atomic.Bool
	connected atomic.Bool
	conn      atomic.Int64
	asked     atomic.Int64
}

func newRestoreCapabilityFake() *restoreCapabilityFake {
	p := &restoreCapabilityFake{}
	p.capable.Store(true)
	p.connected.Store(true)
	return p
}

func (p *restoreCapabilityFake) restoreConnection() (string, bool) {
	return strings.Repeat("c", int(p.conn.Load())), p.connected.Load()
}

func (p *restoreCapabilityFake) restoreCapability(context.Context) (string, error) {
	p.asked.Add(1)
	if !p.capable.Load() {
		return "", errors.New("Invalid Handler for type: RestoreCapability")
	}
	return nativeRestoreCapability, nil
}

// A positive answer is reused while the connections stay the same; a
// reconnect asks again, a disconnected server blocks without being asked,
// and a negative answer is not reused.
func TestNativeRestoreCapabilityCache(t *testing.T) {
	p := newRestoreCapabilityFake()
	g := &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return []restoreCapabilityPeer{p} }}
	for range 3 {
		if err := g.check(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.asked.Load(); n != 1 {
		t.Errorf("asked %d times while connected and capable, want 1", n)
	}
	// The server restarts with an older binary and reconnects.
	p.capable.Store(false)
	p.conn.Add(1)
	if err := g.check(t.Context()); !errors.Is(err, errNativeRestoreUnavailable) {
		t.Errorf("after a reconnect to an older server: %v", err)
	}
	p.capable.Store(true)
	if err := g.check(t.Context()); err != nil {
		t.Errorf("a negative answer was reused: %v", err)
	}
	asked := p.asked.Load()
	p.connected.Store(false)
	if err := g.check(t.Context()); !errors.Is(err, errNativeRestoreUnavailable) || p.asked.Load() != asked {
		t.Errorf("disconnected server: %v, asked %d -> %d", err, asked, p.asked.Load())
	}
}

// During a rolling upgrade POST restore answers 503 and writes nothing, and
// a restore queued before it creates no upload and leaves the version
// retryable.
func TestNativeRestoreRollingUpgradeGate(t *testing.T) {
	r := newRestoreSafetyTest(t, 1, versioning.Enabled)
	initConfigSubsystem(t.Context(), r.z)
	oi, _ := restoreIsolationSeed(t, r, 0, false, true)
	p := newRestoreCapabilityFake()
	previous := globalRestoreCapability
	globalRestoreCapability = &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return []restoreCapabilityPeer{p} }}
	t.Cleanup(func() { globalRestoreCapability = previous })

	p.capable.Store(false)
	before := r.fileInfo(oi.VersionID)
	layer := newRestoreIsolationLayer(r)
	rec := restoreIsolationPOST(t, r, layer, oi.VersionID)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "rolling upgrade") {
		t.Errorf("POST during a rolling upgrade: %d %s", rec.Code, rec.Body.String())
	}
	if after := r.fileInfo(oi.VersionID); !reflect.DeepEqual(before.Metadata, after.Metadata) {
		t.Error("refused POST changed the version")
	}
	select {
	case err := <-layer.done:
		t.Fatalf("refused POST started a restore: %v", err)
	default:
	}

	p.capable.Store(true)
	release := make(chan struct{})
	layer.restore = func(ctx context.Context, bucket, object string, opts ObjectOptions) error {
		<-release
		return r.z.RestoreTransitionedObject(ctx, bucket, object, opts)
	}
	if rec := restoreIsolationPOST(t, r, layer, oi.VersionID); rec.Code != http.StatusOK {
		close(release)
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	// A server is replaced by an older binary while the restore is queued.
	p.capable.Store(false)
	p.conn.Add(1)
	close(release)
	if err := layer.wait(t); !errors.Is(err, errNativeRestoreUnavailable) {
		t.Fatalf("queued restore during a rolling upgrade: %v", err)
	}
	if uploads := restoreIsolationUploads(t, r, 0); len(uploads) != 0 {
		t.Errorf("queued restore created an upload during a rolling upgrade: %v", uploads)
	}
	info, err := r.z.GetObjectInfo(t.Context(), r.bucket, r.object, r.opts(oi.VersionID))
	if err != nil || info.RestoreOngoing || !info.IsRemote() || info.UserDefined[xhttp.AmzRestore] != "" {
		t.Errorf("version after a refused queued restore: %q, %v", info.UserDefined[xhttp.AmzRestore], err)
	}
}

// restoreCapabilityHeld is a fake server whose answer a test holds.
type restoreCapabilityHeld struct {
	restoreCapabilityFake
	asking  chan struct{}
	release chan struct{}
}

func (p *restoreCapabilityHeld) restoreCapability(ctx context.Context) (string, error) {
	v, err := p.restoreCapabilityFake.restoreCapability(ctx)
	p.asking <- struct{}{}
	select {
	case <-p.release:
		return v, err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// A check that waits for another reads the connections once its turn
// comes, an answer counts only if its server did not reconnect meanwhile,
// and a waiting check ends with its context.
func TestNativeRestoreCapabilityRevalidates(t *testing.T) {
	t.Run("reconnect-during-check", func(t *testing.T) {
		held := func() *restoreCapabilityHeld {
			p := &restoreCapabilityHeld{asking: make(chan struct{}, 4), release: make(chan struct{})}
			p.capable.Store(true)
			p.connected.Store(true)
			return p
		}
		fast, slow := held(), held()
		g := &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return []restoreCapabilityPeer{fast, slow} }}
		first := make(chan error, 1)
		go func() { first <- g.check(t.Context()) }()
		<-fast.asking
		<-slow.asking
		waiting := make(chan error, 1)
		go func() { waiting <- g.check(t.Context()) }()
		// Both answered "capable"; then fast reconnects as an older server.
		fast.capable.Store(false)
		fast.conn.Add(1)
		close(fast.release)
		close(slow.release)
		if err := <-first; !errors.Is(err, errNativeRestoreUnavailable) {
			t.Errorf("check whose server reconnected while it asked: %v", err)
		}
		if err := <-waiting; !errors.Is(err, errNativeRestoreUnavailable) {
			t.Errorf("waiting check accepted a reconnected older server: %v", err)
		}
	})
	t.Run("canceled-cached", func(t *testing.T) {
		p := newRestoreCapabilityFake()
		g := &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return []restoreCapabilityPeer{p} }}
		if err := g.check(t.Context()); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := g.check(ctx); err == nil {
			t.Error("a cached answer accepted an ended context")
		}
	})
	t.Run("canceled-wait", func(t *testing.T) {
		slow := &restoreCapabilityHeld{restoreCapabilityFake: restoreCapabilityFake{}, asking: make(chan struct{}, 4), release: make(chan struct{})}
		slow.capable.Store(true)
		slow.connected.Store(true)
		defer close(slow.release)
		g := &restoreCapabilityGate{peers: func() []restoreCapabilityPeer { return []restoreCapabilityPeer{slow} }}
		go g.check(t.Context())
		<-slow.asking
		ctx, cancel := context.WithCancel(t.Context())
		waiting := make(chan error, 1)
		go func() { waiting <- g.check(ctx) }()
		cancel()
		select {
		case err := <-waiting:
			if err == nil {
				t.Error("canceled check succeeded")
			}
		case <-time.After(time.Second):
			t.Error("canceled check kept waiting for another check")
		}
	})
}
