// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/base64"
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

type siteBucketDeletePausedLayer struct {
	ObjectLayer
	once             sync.Once
	deleting, resume chan struct{}
}

func (l *siteBucketDeletePausedLayer) DeleteBucket(ctx context.Context, bucket string, opts DeleteBucketOptions) error {
	l.once.Do(func() { close(l.deleting); <-l.resume })
	return l.ObjectLayer.DeleteBucket(ctx, bucket, opts)
}

func TestSiteReplicationHealAndHooksReleaseLock(t *testing.T) {
	cases := []string{
		"make-bucket-hook",
		"delete-bucket-hook",
		"bucket-meta-hook",
		"iam-change-hook",
		"configure-repl",
		"peer-bucket-delete",
		"heal-bucket-make",
		"heal-bucket-delete",
		"heal-bucket-repl-config",
		"heal-bucket-config",
		"heal-cors",
		"heal-ilm-expiry-config",
		"heal-bucket-ilm-expiry",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			site := newSvcAccSite(t)
			c := &globalSiteReplicationSys
			const bucket = "sr-lock-test-bucket"
			mustIAM(t, site.obj.MakeBucket(site.ctx, bucket, MakeBucketOptions{VersioningEnabled: true}))
			_, err := globalBucketMetadataSys.Update(site.ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, err)

			entered, proceed := make(chan struct{}), make(chan struct{})
			var once sync.Once
			pause := func() {
				once.Do(func() { close(entered) })
				<-proceed
			}
			release := sync.OnceFunc(func() { close(proceed) })
			defer release()

			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pause()
				if strings.HasSuffix(r.URL.Path, iamRevisionPeerPath) {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(iamRevisionResponse{
						iamRevisionStatus: iamRevisionStatus{Version: iamRevisionProtocol, Node: "node", Instance: "boot", Digest: "fixture"},
					})
					return
				}
				if r.Method == http.MethodGet {
					if _, ok := r.URL.Query()["versioning"]; ok {
						w.Header().Set("Content-Type", "application/xml")
						_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`))
						return
					}
					if _, ok := r.URL.Query()["location"]; ok {
						w.Header().Set("Content-Type", "application/xml")
						_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
						return
					}
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer peer.Close()

			pausedObj := &siteBucketDeletePausedLayer{
				ObjectLayer: site.obj,
				deleting:    entered,
				resume:      proceed,
			}
			if tc == "peer-bucket-delete" || tc == "heal-bucket-delete" {
				setObjectLayer(pausedObj)
				defer setObjectLayer(site.obj)
			}

			local := globalDeploymentID()
			now := UTCNow().Truncate(time.Second)
			peers := site.peers(peer.URL)
			for id, p := range peers {
				p.ReplicateILMExpiry = true
				peers[id] = p
			}
			c.Lock()
			c.enabled = true
			c.state = srState{
				Name:                    "local",
				ServiceAccountAccessKey: site.parent.AccessKey,
				Peers:                   peers,
				UpdatedAt:               now,
			}
			c.Unlock()

			done := make(chan error, 1)
			go func() {
				switch tc {
				case "make-bucket-hook":
					done <- c.MakeBucketHook(site.ctx, bucket, MakeBucketOptions{CreatedAt: now})
				case "delete-bucket-hook":
					done <- c.DeleteBucketHook(site.ctx, bucket, true)
				case "bucket-meta-hook":
					done <- c.BucketMetaHook(site.ctx, madmin.SRBucketMeta{
						Type:      madmin.SRBucketMetaTypeTags,
						Bucket:    bucket,
						UpdatedAt: now,
					})
				case "iam-change-hook":
					site.create(t, "sr-lock-hook-sa")
					done <- c.IAMChangeHook(site.ctx, madmin.SRIAMItem{
						Type:         madmin.SRIAMItemSvcAcc,
						SvcAccChange: &madmin.SRSvcAccChange{Create: &madmin.SRSvcAccCreate{AccessKey: "sr-lock-hook-sa"}},
						UpdatedAt:    now,
					})
				case "configure-repl":
					done <- c.PeerBucketConfigureReplHandler(site.ctx, bucket)
				case "peer-bucket-delete":
					done <- c.PeerBucketDeleteHandler(site.ctx, bucket, DeleteBucketOptions{Force: true})
				case "heal-bucket-make":
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local:    {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now}}},
								"remote": {HasBucket: false},
							},
						},
					}
					done <- c.healBucket(site.ctx, site.obj, bucket, info)
				case "heal-bucket-delete":
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local:    {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute), DeletedAt: now}}},
								"remote": {HasBucket: false, BucketMarkedDeleted: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{DeletedAt: now.Add(-2 * time.Minute)}}},
							},
						},
					}
					done <- c.healBucket(site.ctx, pausedObj, bucket, info)
				case "heal-bucket-repl-config":
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local: {HasBucket: true, ReplicationCfgMismatch: true},
							},
						},
					}
					done <- c.healBucketReplicationConfig(site.ctx, site.obj, bucket, info, &validateReplicationDestinationOptions{CheckReady: true})
				case "heal-bucket-config":
					tagPayload := base64.StdEncoding.EncodeToString([]byte(`<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`))
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local:    {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute), Tags: &tagPayload, TagConfigUpdatedAt: now}}},
								"remote": {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute)}}},
							},
						},
					}
					done <- c.healBucketConfig(site.ctx, bucket, bucketTaggingConfig, info)
				case "heal-cors":
					corsPayload := base64.StdEncoding.EncodeToString([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local:    {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute), CorsConfig: &corsPayload, CorsConfigUpdatedAt: now}}},
								"remote": {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute)}}},
							},
						},
					}
					done <- c.healCORSMetadata(site.ctx, site.obj, bucket, info)
				case "heal-ilm-expiry-config":
					stalePeers := site.peers(peer.URL)
					for id, p := range stalePeers {
						p.ReplicateILMExpiry = false
						stalePeers[id] = p
					}
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						PeerStates: map[string]madmin.SRStateInfo{
							local:    {Name: "local", Peers: peers, UpdatedAt: now},
							"remote": {Name: "remote", Peers: stalePeers, UpdatedAt: now.Add(-time.Minute)},
						},
					}
					done <- c.healILMExpiryConfig(site.ctx, site.obj, info)
				case "heal-bucket-ilm-expiry":
					lcXML := `<LifecycleConfiguration><Rule><ID>exp</ID><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`
					lcPayload := base64.StdEncoding.EncodeToString([]byte(lcXML))
					info := srStatusInfo{
						Sites: site.peers(peer.URL),
						BucketStats: map[string]map[string]srBucketStatsSummary{
							bucket: {
								local:    {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute), ExpiryLCConfig: &lcPayload, ExpiryLCConfigUpdatedAt: now}}},
								"remote": {HasBucket: true, meta: srBucketMetaInfo{SRBucketInfo: madmin.SRBucketInfo{CreatedAt: now.Add(-time.Minute)}}},
							},
						},
					}
					done <- c.healBucketILMExpiry(site.ctx, site.obj, bucket, info)
				}
			}()

			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("operation returned before reaching storage/peer pause point: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for storage/peer pause point")
			}

			if c.TryLock() {
				c.state.Name = "mutated-while-in-flight"
				delete(c.state.Peers, "remote")
				c.state.UpdatedAt = now.Add(time.Second)
				c.Unlock()
			} else {
				t.Error("SiteReplicationSys lock held across storage I/O or peer RPC")
			}

			release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("operation deadlocked after writer mutation")
			}
		})
	}
}

func TestSiteReplicationConcurrentStateUpdates(t *testing.T) {
	site := newSvcAccSite(t)
	c := &globalSiteReplicationSys
	const bucket = "sr-concurrent-state-bucket"
	mustIAM(t, site.obj.MakeBucket(site.ctx, bucket, MakeBucketOptions{VersioningEnabled: true}))
	_, err := globalBucketMetadataSys.Update(site.ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
	mustIAM(t, err)

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "metainfo") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(madmin.SRInfo{DeploymentID: "remote"})
			return
		}
		if r.Method == http.MethodGet {
			if _, ok := r.URL.Query()["versioning"]; ok {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write([]byte(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`))
				return
			}
			if _, ok := r.URL.Query()["location"]; ok {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = w.Write([]byte(`<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer peer.Close()

	basePeers := site.peers(peer.URL)
	now := UTCNow().Truncate(time.Second)
	c.Lock()
	c.enabled = true
	c.state = srState{
		Name:                    "local",
		ServiceAccountAccessKey: site.parent.AccessKey,
		Peers:                   maps.Clone(basePeers),
		UpdatedAt:               now,
	}
	c.Unlock()

	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := range 10 {
			_ = c.PeerEditReq(site.ctx, madmin.PeerInfo{
				DeploymentID:       "remote",
				Name:               "remote",
				Endpoint:           peer.URL,
				ReplicateILMExpiry: i%2 == 0,
			})
		}
	}()
	go func() {
		defer wg.Done()
		for i := range 10 {
			peers := site.peers(peer.URL)
			p := peers["remote"]
			p.ReplicateILMExpiry = i%2 == 1
			peers["remote"] = p
			_ = c.PeerStateEditReq(site.ctx, madmin.SRStateEditReq{
				Peers:     peers,
				UpdatedAt: now.Add(time.Duration(i+1) * time.Second),
			})
		}
	}()
	go func() {
		defer wg.Done()
		for range 10 {
			_ = c.PeerBucketConfigureReplHandler(site.ctx, bucket)
		}
	}()
	go func() {
		defer wg.Done()
		for range 5 {
			_ = c.healBuckets(site.ctx, site.obj)
		}
	}()
	wg.Wait()
}
