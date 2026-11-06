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
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/minio/minio/internal/grid"
)

// Native restore is a protocol among the servers of a cluster
// (restore-stage.go): the restore lock of a version and the attempt that its
// ongoing marker names (restore-attempt.go) say which worker owns the
// restore, the copy is staged in the tmp volume and published under the
// object lock by a commit that checks the attempt again, and a superseded
// attempt writes nothing. A server that predates this protocol does not
// follow it: it would run its own restore of the same version, under other
// locks or none, and write it in its own way.
//
// Native restore therefore runs only while every server of the cluster
// positively reports that it speaks this protocol. A server that does not
// answer, or does not know the question, as an older server does not,
// blocks it: a server that is not reachable now is not proven stopped, and
// it may still be running an older restore.

// nativeRestoreCapability is the native restore protocol this server speaks.
const nativeRestoreCapability = "2"

const (
	peerRESTRestoreCapability = "restore"
	// restoreCapabilityTTL bounds how long a positive answer is reused while
	// no server reconnected.
	restoreCapabilityTTL = 10 * time.Second
	// restoreCapabilityTimeout bounds the question to each server.
	restoreCapabilityTimeout = 5 * time.Second
)

var errNativeRestoreUnavailable = errors.New("native restore is unavailable during a rolling upgrade: not every server of the cluster supports it yet")

// restoreCapabilityHandler answers the question on this server.
func restoreCapabilityHandler(*grid.MSS) (*grid.MSS, *grid.RemoteErr) {
	return grid.NewMSSWith(map[string]string{peerRESTRestoreCapability: nativeRestoreCapability}), nil
}

// restoreCapabilityPeer is another server of the cluster.
type restoreCapabilityPeer interface {
	// restoreConnection identifies the current connection to the server; it
	// changes when the server reconnects, as a restarted one does. ok is
	// false when the server is not connected.
	restoreConnection() (key string, ok bool)
	restoreCapability(ctx context.Context) (string, error)
}

type restorePeerClient struct{ *peerRESTClient }

func (c restorePeerClient) restoreConnection() (string, bool) {
	if c.peerRESTClient == nil || c.gridConn == nil {
		return "", false
	}
	conn := c.gridConn()
	if conn == nil {
		return "", false
	}
	st := conn.Stats()
	if st.Connected == 0 {
		return "", false
	}
	// Keys are compared by the position of their server.
	return fmt.Sprintf("%d/%d", st.LastConnectTime.UnixNano(), st.ReconnectCount), true
}

func (c restorePeerClient) restoreCapability(ctx context.Context) (string, error) {
	conn := c.gridConn()
	if conn == nil {
		return "", errPeerOffline
	}
	resp, err := restoreCapabilityRPC.Call(ctx, conn, grid.NewMSS())
	if err != nil {
		return "", err
	}
	return resp.Get(peerRESTRestoreCapability), nil
}

// restoreCapabilityGate decides whether native restore may run, caching a
// positive answer for restoreCapabilityTTL while the connections to all
// servers stay the same. A negative answer is not cached.
type restoreCapabilityGate struct {
	peers func() []restoreCapabilityPeer

	once    sync.Once
	turn    chan struct{} // one check at a time
	checked time.Time
	keys    []string
}

var globalRestoreCapability = &restoreCapabilityGate{peers: notificationRestorePeers}

func notificationRestorePeers() []restoreCapabilityPeer {
	if globalNotificationSys == nil {
		return nil
	}
	peers := make([]restoreCapabilityPeer, 0, len(globalNotificationSys.peerClients))
	for _, client := range globalNotificationSys.peerClients {
		peers = append(peers, restorePeerClient{client})
	}
	return peers
}

// nativeRestoreAvailable returns errNativeRestoreUnavailable unless every
// other server of the cluster supports native restore.
func nativeRestoreAvailable(ctx context.Context) error {
	return globalRestoreCapability.check(ctx)
}

func (g *restoreCapabilityGate) check(ctx context.Context) error {
	g.once.Do(func() { g.turn = make(chan struct{}, 1) })
	// One deadline covers the wait for another check and the questions.
	ctx, cancel := context.WithTimeout(ctx, restoreCapabilityTimeout)
	defer cancel()
	select {
	case g.turn <- struct{}{}:
	case <-ctx.Done():
		return errNativeRestoreUnavailable
	}
	defer func() { <-g.turn }()

	// Read the connections only now: one may have changed while this check
	// waited for another.
	peers := g.peers()
	connections := func() ([]string, bool) {
		keys := make([]string, len(peers))
		for i, p := range peers {
			key, ok := p.restoreConnection()
			if !ok {
				return nil, false
			}
			keys[i] = key
		}
		return keys, true
	}
	keys, ok := connections()
	if !ok {
		g.checked, g.keys = time.Time{}, nil
		return errNativeRestoreUnavailable
	}
	if ctx.Err() != nil {
		return errNativeRestoreUnavailable
	}
	if !g.checked.IsZero() && time.Since(g.checked) < restoreCapabilityTTL && slices.Equal(keys, g.keys) {
		return nil
	}
	g.checked, g.keys = time.Time{}, nil
	answers := make([]bool, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			version, err := p.restoreCapability(ctx)
			answers[i] = err == nil && version == nativeRestoreCapability
		}()
	}
	wg.Wait()
	// An answer counts only for the connection it was asked on: a server
	// that reconnected meanwhile may be another binary.
	after, ok := connections()
	if !ok || !slices.Equal(keys, after) || slices.Contains(answers, false) || ctx.Err() != nil {
		return errNativeRestoreUnavailable
	}
	g.checked, g.keys = time.Now(), keys
	return nil
}
