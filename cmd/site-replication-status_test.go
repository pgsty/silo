// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
)

// Pause before the real IAM loader, which can itself read replication state.
// TryLock below proves that a configuration writer can proceed at this point
// without leaving deadlocked goroutines behind when this test regresses.
type siteStatusPausedStore struct {
	IAMStorageAPI
	once             sync.Once
	loading, proceed chan struct{}
}

func (s *siteStatusPausedStore) loadUsers(ctx context.Context, typ IAMUserType, users map[string]UserIdentity) error {
	s.once.Do(func() { close(s.loading); <-s.proceed })
	return s.IAMStorageAPI.loadUsers(ctx, typ, users)
}

func TestSiteReplicationStatusReadsStorageUnlocked(t *testing.T) {
	for _, entry := range []string{"metadata", "status", "heal"} {
		for _, change := range []string{"disable", "topology", "cancel"} {
			t.Run(entry+"/"+change, func(t *testing.T) {
				site := newSvcAccSite(t)
				c := &globalSiteReplicationSys
				paused := &siteStatusPausedStore{IAMStorageAPI: site.sys.store.IAMStorageAPI, loading: make(chan struct{}), proceed: make(chan struct{})}
				site.sys.store.IAMStorageAPI = paused
				release := sync.OnceFunc(func() { close(paused.proceed) })
				defer release()
				c.iamMetaCache.Lock()
				c.iamMetaCache.lastUpdate = time.Time{}
				c.iamMetaCache.Unlock()
				c.RLock()
				peers := maps.Clone(c.state.Peers)
				c.RUnlock()
				ctx, cancel := context.WithCancel(site.ctx)
				defer cancel()
				var meta madmin.SRInfo
				var status srStatusInfo
				done := make(chan error, 1)
				go func() {
					var err error
					opts := madmin.SRStatusOptions{Users: true, Groups: true, Policies: true, PeerState: true}
					switch entry {
					case "metadata":
						meta, err = c.SiteReplicationMetaInfo(ctx, site.obj, opts)
					case "status":
						status, err = c.siteReplicationStatus(ctx, site.obj, opts)
					case "heal":
						err = c.healIAMSystem(ctx, site.obj)
					}
					done <- err
				}()
				select {
				case <-paused.loading:
				case err := <-done:
					t.Fatalf("did not read IAM storage: %v", err)
				case <-time.After(10 * time.Second):
					t.Fatal("did not reach IAM loader")
				}
				if c.TryLock() {
					switch change {
					case "disable":
						c.enabled = false
						c.state = srState{}
					case "topology":
						delete(c.state.Peers, "remote")
						c.state.UpdatedAt = UTCNow()
					}
					c.Unlock()
				} else {
					t.Error("replication configuration is locked during IAM storage read")
				}
				if change == "cancel" {
					cancel()
				}
				release()
				select {
				case err := <-done:
					if change != "cancel" {
						mustIAM(t, err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("operation did not finish")
				}
				if change != "cancel" {
					if entry == "metadata" && !reflect.DeepEqual(meta.State.Peers, peers) || entry == "status" && !reflect.DeepEqual(status.Sites, peers) {
						t.Fatal("result topology changed after its snapshot")
					}
				}
			})
		}
	}
}

func TestSiteReplicationStatusRemoteUnlocked(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "peer-error"}[fail], func(t *testing.T) {
			site := newSvcAccSite(t)
			entered, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() { close(entered) })
				<-proceed
				w.Header().Set("Content-Type", "application/json")
				if fail {
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(madmin.ErrorResponse{Code: "AccessDenied", Message: "denied"})
					return
				}
				_ = json.NewEncoder(w).Encode(madmin.SRInfo{DeploymentID: "remote"})
			}))
			defer peer.Close()
			release := sync.OnceFunc(func() { close(proceed) })
			defer release()
			c := &globalSiteReplicationSys
			c.Lock()
			c.state.Peers = site.peers(peer.URL)
			c.state.UpdatedAt = UTCNow()
			updated := c.state.UpdatedAt
			c.Unlock()
			var status srStatusInfo
			done := make(chan error, 1)
			go func() {
				var err error
				status, err = c.siteReplicationStatus(site.ctx, site.obj, madmin.SRStatusOptions{})
				done <- err
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("did not request remote status: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("did not reach peer")
			}
			if c.TryLock() {
				delete(c.state.Peers, "remote")
				c.state.UpdatedAt = updated.Add(time.Second)
				c.Unlock()
			} else {
				t.Error("replication configuration is locked during remote request")
			}
			release()
			select {
			case err := <-done:
				if fail {
					if err == nil || !strings.Contains(err.Error(), "site remote (remote)") {
						t.Fatalf("lost original peer name in error: %v", err)
					}
				} else {
					mustIAM(t, err)
					if len(status.Sites) != 2 || status.Sites["remote"].Endpoint != peer.URL || status.UpdatedAt != updated {
						t.Fatal("status mixed different topology revisions")
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("status did not finish")
			}
		})
	}
}

func TestSiteReplicationMetaInfoCachedPeerState(t *testing.T) {
	site := newSvcAccSite(t)
	c := &globalSiteReplicationSys
	c.srCacheIAMInfo(madmin.SRInfo{DeploymentID: globalDeploymentID(), State: madmin.SRStateInfo{Name: "obsolete"}})
	opts := madmin.SRStatusOptions{Users: true, Groups: true, Policies: true, PeerState: true}
	got, err := c.SiteReplicationMetaInfo(site.ctx, site.obj, opts)
	mustIAM(t, err)
	if !reflect.DeepEqual(got.State.Peers, c.state.Peers) || got.State.Name != c.state.Name {
		t.Fatal("cached IAM response returned stale peer state")
	}
	delete(got.State.Peers, "remote")
	if len(c.state.Peers) != 2 {
		t.Fatal("returned peer map aliases the replication configuration")
	}
	opts.PeerState = false
	got, err = c.SiteReplicationMetaInfo(site.ctx, site.obj, opts)
	mustIAM(t, err)
	if got.State.Name != "" || got.State.Peers != nil {
		t.Fatal("returned cached peer state that was not requested")
	}
}
