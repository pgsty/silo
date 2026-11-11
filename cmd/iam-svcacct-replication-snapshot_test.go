// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

// Site replication sends a service account as the record its site has
// stored, whole. A peer that applies the last item it was sent then has
// the account of the sending site, whatever it received or lost before,
// and whatever the sending server holds in its cache.

const svcAccSnapshotPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::snapshot/*"]}]}`

// svcAccRecord is what a site has of a service account.
type svcAccRecord struct {
	Parent, Secret, Status, Name, Description, Policy string
	Expiration, UpdatedAt                             time.Time
}

// svcAccPolicyText is a policy document in the one form it is compared in;
// an account without an embedded policy has "".
func svcAccPolicyText(t *testing.T, document []byte) string {
	t.Helper()
	if len(document) == 0 {
		return ""
	}
	p, err := policy.ParseConfig(bytes.NewReader(document))
	mustIAM(t, err)
	text, err := json.Marshal(p)
	mustIAM(t, err)
	return string(text)
}

// svcAccStored is the account as a server that starts now loads it.
func svcAccStored(t *testing.T, f *groupRefreshFixture, key string) svcAccRecord {
	t.Helper()
	u, ok := f.stored(t, key)
	if !ok {
		t.Fatalf("service account %s is not stored", key)
	}
	cr := u.Credentials
	rawClaims, err := auth.ExtractClaims(cr.SessionToken, cr.SecretKey)
	mustIAM(t, err)
	if _, ok := rawClaims.Map()[sessionPolicyNameExtracted]; ok {
		t.Fatal("stored JWT contains the derived policy claim")
	}
	claims, err := getClaimsFromTokenWithSecret(cr.SessionToken, cr.SecretKey)
	mustIAM(t, err)
	rec := svcAccRecord{Parent: cr.ParentUser, Secret: cr.SecretKey, Status: cr.Status, Name: cr.Name, Description: cr.Description, Expiration: cr.Expiration, UpdatedAt: u.UpdatedAt}
	if sp, ok := claims.Lookup(policy.SessionPolicyName); ok && claims.MapClaims[iamPolicyClaimNameSA()] == embeddedPolicyType {
		document, err := base64.StdEncoding.DecodeString(sp)
		mustIAM(t, err)
		rec.Policy = svcAccPolicyText(t, document)
	}
	return rec
}

// svcAccSite is a site that replicates to one peer, which records the IAM
// items it is sent.
type svcAccSite struct {
	*groupRefreshFixture
	mu   sync.Mutex
	sent []iamReplicationItem
}

func newSvcAccSite(t *testing.T) *svcAccSite {
	t.Helper()
	s := &svcAccSite{groupRefreshFixture: newGroupRefreshFixture(t)}
	globalObjLayerMutex.Lock()
	globalObjectAPI = s.obj
	globalObjLayerMutex.Unlock()

	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, iamRevisionPeerPath) {
			var batch iamRevisionBatch
			if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
				t.Error(err)
			}
			s.mu.Lock()
			s.sent = append(s.sent, batch.Items...)
			s.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iamRevisionResponse{iamRevisionStatus: iamRevisionStatus{Version: iamRevisionProtocol, Node: "node", Instance: "boot", Digest: "fixture"}})
	}))
	globalSiteReplicatorCred.Set("snapshot-site-signing-key")
	globalSiteReplicationSys.Lock()
	globalSiteReplicationSys.enabled = true
	globalSiteReplicationSys.state = srState{ServiceAccountAccessKey: s.parent.AccessKey, Peers: s.peers(peer.URL)}
	globalSiteReplicationSys.Unlock()
	t.Cleanup(func() {
		s.leave()
		peer.Close()
	})
	return s
}

func (s *svcAccSite) peers(endpoint string) map[string]madmin.PeerInfo {
	return map[string]madmin.PeerInfo{
		globalDeploymentID(): {Name: "local", DeploymentID: globalDeploymentID()},
		"remote":             {Name: "remote", DeploymentID: "remote", Endpoint: endpoint},
	}
}

// leave ends the replication of this process, for the site that comes next.
func (s *svcAccSite) leave() {
	globalSiteReplicationSys.Lock()
	globalSiteReplicationSys.enabled = false
	globalSiteReplicationSys.state = srState{}
	globalSiteReplicationSys.Unlock()
	globalSiteReplicatorCred.Set("")
}

// items are the creates and edits of account key the peer was sent, in the
// order of sending.
func (s *svcAccSite) items(key string) []iamReplicationItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []iamReplicationItem
	for _, item := range s.sent {
		c := item.SvcAccChange
		if c != nil && ((c.Create != nil && c.Create.AccessKey == key) || (c.Update != nil && c.Update.AccessKey == key)) {
			items = append(items, item)
		}
	}
	return items
}

// create and edit are an administrator's requests to this site.
func (s *svcAccSite) create(t *testing.T, key string) {
	t.Helper()
	rec := iamAdminCall(t, globalActiveCred, http.MethodPut, "/minio/admin/v3/add-service-account",
		madmin.AddServiceAccountReq{TargetUser: s.parent.AccessKey, AccessKey: key, SecretKey: "snapshot-original-secret"}, nil, adminAPIHandlers{}.AddServiceAccount)
	if rec.Code != http.StatusOK {
		t.Fatalf("add-service-account: %d %s", rec.Code, rec.Body.String())
	}
}

func (s *svcAccSite) edit(t *testing.T, key string, req madmin.UpdateServiceAccountReq) {
	t.Helper()
	rec := iamAdminCall(t, globalActiveCred, http.MethodPost, "/minio/admin/v3/update-service-account?accessKey="+key,
		req, map[string]string{"accessKey": key}, adminAPIHandlers{}.UpdateServiceAccount)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("update-service-account: %d %s", rec.Code, rec.Body.String())
	}
}

// svcAccPeer is the site that applies items, in the order given, and what
// it then has of account key. It has the parent user, as a peer does.
func svcAccPeer(t *testing.T, from *svcAccSite, key string, items ...iamReplicationItem) svcAccRecord {
	t.Helper()
	from.leave()
	peer := newGroupRefreshFixture(t)
	for i, item := range items {
		// As the peer reads it off the wire.
		raw, err := json.Marshal(item)
		mustIAM(t, err)
		var received iamReplicationItem
		mustIAM(t, json.Unmarshal(raw, &received))
		if create := received.SvcAccChange.Create; create != nil {
			if _, ok := create.Claims[sessionPolicyNameExtracted]; ok {
				t.Fatal("replication snapshot contains the derived policy claim")
			}
		}
		if err := applyIAMReplicationItem(peer.ctx, received); err != nil {
			t.Fatalf("the peer refused item %d: %v", i, err)
		}
	}
	return svcAccStored(t, peer, key)
}

func wantSvcAccRecord(t *testing.T, where string, got, want svcAccRecord) {
	t.Helper()
	if got != want {
		t.Errorf("%s:\n got %+v\nwant %+v", where, got, want)
	}
}

// An edit of a service account reaches a peer whatever became of the edits
// before it: one that arrives late, or never, is not lost.
func TestSiteReplicationServiceAccountEdits(t *testing.T) {
	const key = "snapshot-edits"
	for _, tc := range []struct {
		name  string
		edits []madmin.UpdateServiceAccountReq
		took  func(svcAccRecord) bool // control: what the site has after them
	}{
		{"policy-secret-description", []madmin.UpdateServiceAccountReq{
			{NewPolicy: json.RawMessage(svcAccSnapshotPolicy)},
			{NewSecretKey: "snapshot-rotated-secret"},
			{NewDescription: "described"},
		}, func(r svcAccRecord) bool {
			return r.Policy != "" && r.Secret == "snapshot-rotated-secret" && r.Description == "described"
		}},
		{"secret-disable", []madmin.UpdateServiceAccountReq{
			{NewPolicy: json.RawMessage(svcAccSnapshotPolicy), NewSecretKey: "snapshot-rotated-secret"},
			{NewStatus: string(madmin.AccountDisabled)},
		}, func(r svcAccRecord) bool {
			return r.Policy != "" && r.Secret == "snapshot-rotated-secret" && r.Status == auth.AccountOff
		}},
		// The last edit removes the embedded policy: the peer gets an
		// account without one, and the description set before.
		{"policy-removed", []madmin.UpdateServiceAccountReq{
			{NewPolicy: json.RawMessage(svcAccSnapshotPolicy)},
			{NewDescription: "described"},
			{NewPolicy: json.RawMessage(`{"Statement":[]}`)},
		}, func(r svcAccRecord) bool { return r.Policy == "" && r.Description == "described" }},
		{"policy-removed-with-version", []madmin.UpdateServiceAccountReq{
			{NewPolicy: json.RawMessage(svcAccSnapshotPolicy)},
			{NewPolicy: json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`), NewName: "named"},
			{NewDescription: "described"},
		}, func(r svcAccRecord) bool {
			return r.Policy == "" && r.Name == "named" && r.Description == "described"
		}},
		{"policy-missing-version", []madmin.UpdateServiceAccountReq{
			{NewPolicy: json.RawMessage(svcAccSnapshotPolicy)},
			{NewPolicy: json.RawMessage(strings.ReplaceAll(strings.ReplaceAll(svcAccSnapshotPolicy, `"Version":"2012-10-17",`, ""), "s3:GetObject", "s3:PutObject"))},
			{NewDescription: "described"},
		}, func(r svcAccRecord) bool {
			return r.Policy == svcAccPolicyText(t, []byte(strings.ReplaceAll(svcAccSnapshotPolicy, "s3:GetObject", "s3:PutObject"))) && r.Description == "described"
		}},
	} {
		for _, delivery := range []string{"late", "lost"} {
			t.Run(tc.name+"/"+delivery, func(t *testing.T) {
				site := newSvcAccSite(t)
				site.create(t, key)
				for _, edit := range tc.edits {
					site.edit(t, key, edit)
				}
				sent := site.items(key)
				if len(sent) != 1+len(tc.edits) {
					t.Fatalf("the site sent %d items for the account, want one for the create and each edit", len(sent))
				}
				want := svcAccStored(t, site.groupRefreshFixture, key)
				if !tc.took(want) {
					t.Fatalf("control: the site did not apply the edits: %+v", want)
				}
				// The peer has the account and gets the last edit. The edits
				// before it were lost, or reach it after the last.
				last := len(sent) - 1
				deliver := []iamReplicationItem{sent[0], sent[last]}
				if delivery == "late" {
					deliver = append(deliver, sent[1:last]...)
				}
				wantSvcAccRecord(t, "peer", svcAccPeer(t, site, key, deliver...), want)
			})
		}
	}

	// Two requests edit the account through this site at once, and the
	// first comes to replicate when the second is stored.
	t.Run("concurrent", func(t *testing.T) {
		site := newSvcAccSite(t)
		site.create(t, key)
		sp, err := policy.ParseConfig(strings.NewReader(svcAccSnapshotPolicy))
		mustIAM(t, err)
		first, err := site.sys.UpdateServiceAccount(site.ctx, key, updateServiceAccountOpts{sessionPolicy: sp})
		mustIAM(t, err)
		second, err := site.sys.UpdateServiceAccount(site.ctx, key, updateServiceAccountOpts{description: "described"})
		mustIAM(t, err)
		for _, at := range []time.Time{first, second} {
			mustIAM(t, globalSiteReplicationSys.IAMChangeHook(site.ctx, madmin.SRIAMItem{
				Type:         madmin.SRIAMItemSvcAcc,
				SvcAccChange: &madmin.SRSvcAccChange{Update: &madmin.SRSvcAccUpdate{AccessKey: key}},
				UpdatedAt:    at,
			}))
		}
		want := svcAccStored(t, site.groupRefreshFixture, key)
		if want.Policy == "" || want.Description != "described" {
			t.Fatalf("control: the site did not apply the edits: %+v", want)
		}
		wantSvcAccRecord(t, "peer", svcAccPeer(t, site, key, site.items(key)...), want)
	})
}

// Another server of the site restricted, rotated and disabled the account,
// and this server's cache has not heard of it. What this server sends, and
// exports, is the account that is stored.
func TestSiteReplicationServiceAccountStaleCache(t *testing.T) {
	const key = "snapshot-stale"
	// prepare returns the site, the stored account and what it sent for the
	// create.
	prepare := func(t *testing.T) (*svcAccSite, svcAccRecord, iamReplicationItem) {
		t.Helper()
		site := newSvcAccSite(t)
		site.create(t, key)
		created := site.items(key)
		if len(created) != 1 {
			t.Fatalf("the site sent %d items for the create", len(created))
		}
		sp, err := policy.ParseConfig(strings.NewReader(svcAccSnapshotPolicy))
		mustIAM(t, err)
		_, err = site.sibling(t).UpdateServiceAccount(site.ctx, key, updateServiceAccountOpts{
			sessionPolicy: sp, secretKey: "snapshot-rotated-secret", status: auth.AccountOff, description: "restricted",
		})
		mustIAM(t, err)
		if cached, _ := site.sys.store.GetUser(key); cached.Credentials.SecretKey != "snapshot-original-secret" || cached.Credentials.Status != auth.AccountOn {
			t.Fatal("control: this server's cache must not have heard of the edit")
		}
		want := svcAccStored(t, site.groupRefreshFixture, key)
		if want.Policy == "" || want.Secret != "snapshot-rotated-secret" || want.Status != auth.AccountOff {
			t.Fatalf("control: the edit is not stored: %+v", want)
		}
		return site, want, created[0]
	}

	t.Run("heal", func(t *testing.T) {
		site, want, created := prepare(t)
		local := madmin.UserInfo{Status: madmin.AccountStatus(want.Status), UpdatedAt: want.UpdatedAt}
		remote := madmin.UserInfo{Status: madmin.AccountStatus(auth.AccountOn), UpdatedAt: created.UpdatedAt}
		info := srStatusInfo{Sites: globalSiteReplicationSys.state.Peers, UserStats: map[string]map[string]srUserStatsSummary{key: {
			globalDeploymentID(): {userInfo: srUserInfo{UserInfo: local}},
			"remote":             {SRUserStatsSummary: madmin.SRUserStatsSummary{UserInfoMismatch: true}, userInfo: srUserInfo{UserInfo: remote}},
		}}}
		mustIAM(t, globalSiteReplicationSys.healUsers(site.ctx, site.obj, key, info))
		sent := site.items(key)
		if len(sent) != 2 {
			t.Fatalf("heal sent %d items for the account, want 1", len(sent)-1)
		}
		wantSvcAccRecord(t, "healed peer", svcAccPeer(t, site, key, sent...), want)
	})

	t.Run("sync", func(t *testing.T) {
		site, want, _ := prepare(t)
		mustIAM(t, globalSiteReplicationSys.syncToAllPeers(site.ctx, madmin.SRAddOptions{}))
		sent := site.items(key)
		if len(sent) != 2 {
			t.Fatalf("sync sent %d items for the account, want 1", len(sent)-1)
		}
		wantSvcAccRecord(t, "new peer", svcAccPeer(t, site, key, sent[1]), want)
	})

	t.Run("export", func(t *testing.T) {
		_, want, _ := prepare(t)
		rec := iamAdminCall(t, globalActiveCred, http.MethodGet, "/minio/admin/v3/export-iam", nil, nil, adminAPIHandlers{}.ExportIAM)
		if rec.Code != http.StatusOK {
			t.Fatalf("export-iam: %d %s", rec.Code, rec.Body.String())
		}
		archive, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
		mustIAM(t, err)
		file, err := archive.Open(path.Join(iamAssetsDir, allSvcAcctsFile))
		mustIAM(t, err)
		raw, err := io.ReadAll(file)
		mustIAM(t, err)
		var accounts map[string]madmin.SRSvcAccCreate
		mustIAM(t, json.Unmarshal(raw, &accounts))
		a, ok := accounts[key]
		if !ok || a.Expiration == nil {
			t.Fatalf("the export has no account %s with an expiration (present=%v)", key, ok)
		}
		got := svcAccRecord{Parent: a.Parent, Secret: a.SecretKey, Status: a.Status, Name: a.Name, Description: a.Description, Policy: svcAccPolicyText(t, a.SessionPolicy), Expiration: *a.Expiration}
		want.UpdatedAt = time.Time{} // an export has no revisions
		wantSvcAccRecord(t, "export", got, want)
		if a.Claims[iamPolicyClaimNameSA()] != embeddedPolicyType {
			t.Errorf("exported claims say %v, want %s", a.Claims[iamPolicyClaimNameSA()], embeddedPolicyType)
		}
		if _, ok := a.Claims[sessionPolicyNameExtracted]; ok {
			t.Error("exported claims contain the derived policy claim")
		}
	})
}

func TestIAMServiceAccountSnapshotClaims(t *testing.T) {
	f := newGroupRefreshFixture(t)
	sp, err := policy.ParseConfig(strings.NewReader(svcAccSnapshotPolicy))
	mustIAM(t, err)
	_, _, err = f.sys.NewServiceAccount(f.ctx, f.parent.AccessKey, nil, newServiceAccountOpts{
		accessKey: "snapshot-claims", secretKey: "snapshot-valid-secret", sessionPolicy: sp,
		claims: map[string]any{"identity-attribute": "preserved"},
	})
	mustIAM(t, err)
	u, ok := f.stored(t, "snapshot-claims")
	if !ok {
		t.Fatal("service account missing")
	}
	cr := u.Credentials
	rawClaims, err := auth.ExtractClaims(cr.SessionToken, cr.SecretKey)
	mustIAM(t, err)
	derived, ok := cr.Claims[sessionPolicyNameExtracted]
	if !ok {
		t.Fatal("control: loaded claims must contain the derived policy")
	}
	snapshot, err := serviceAccountSnapshot(u)
	mustIAM(t, err)
	if !reflect.DeepEqual(snapshot.Claims, rawClaims.Map()) {
		t.Fatal("snapshot claims differ from the raw JWT")
	}
	if u.Credentials.SessionToken != cr.SessionToken || u.Credentials.Claims[sessionPolicyNameExtracted] != derived {
		t.Fatal("snapshot changed the source token or its cached claims")
	}
}

// The parent was deleted and created again on both sites. The token of a
// service account created afterwards names that revocation, and a peer
// refuses a credential of the parent that does not: the create must carry
// the claims of the token.
func TestSiteReplicationServiceAccountOfRecreatedParent(t *testing.T) {
	const key = "snapshot-reparent"
	site := newSvcAccSite(t)
	mustIAM(t, site.sys.DeleteUser(site.ctx, site.parent.AccessKey, false))
	iamAdminUser(site.ctx, t, site.sys, site.parent.AccessKey, "refresh-parent")
	revoked, err := loadIAMRevision(site.ctx, site.sys.store, getUserIdentityPath(site.parent.AccessKey, regUser))
	mustIAM(t, err)
	if revoked.RevokedBefore.IsZero() {
		t.Fatal("control: the parent must have a revocation boundary")
	}
	site.create(t, key)
	sent := site.items(key)
	if len(sent) != 1 {
		t.Fatalf("the site sent %d items for the create", len(sent))
	}
	want := svcAccStored(t, site.groupRefreshFixture, key)

	// The peer's parent is newer than the deletion, which leaves it live
	// with the boundary: a parent that was deleted and created again.
	site.leave()
	peer := newGroupRefreshFixture(t)
	mustIAM(t, peer.sys.DeleteUser(withIAMReplicationTime(peer.ctx, revoked.RevokedBefore), peer.parent.AccessKey, false))
	if r, err := loadIAMRevision(peer.ctx, peer.sys.store, getUserIdentityPath(peer.parent.AccessKey, regUser)); err != nil || r.Deleted || !r.RevokedBefore.Equal(revoked.RevokedBefore) {
		t.Fatalf("control: the peer's parent must be live with the boundary (err=%v deleted=%v)", err, r.Deleted)
	}
	mustIAM(t, applyIAMReplicationItem(peer.ctx, sent[0]))
	if _, ok := peer.stored(t, key); !ok {
		t.Fatal("the peer dropped the new service account")
	}
	wantSvcAccRecord(t, "peer", svcAccStored(t, peer, key), want)
}

// An account that is deleted is not sent, and that is not an error. An
// account whose stored token cannot be read is not taken for deleted: the
// site signing key is not available here, and no token is read without it.
func TestSiteReplicationServiceAccountUnreadable(t *testing.T) {
	const key = "snapshot-unreadable"
	site := newSvcAccSite(t)
	site.create(t, key)
	item := madmin.SRIAMItem{Type: madmin.SRIAMItemSvcAcc, SvcAccChange: &madmin.SRSvcAccChange{Update: &madmin.SRSvcAccUpdate{AccessKey: key}}}

	globalSiteReplicatorCred.Set("")
	if _, err := globalSiteReplicationSys.replicationItem(site.ctx, item); err == nil || errors.Is(err, errIAMStaleUpdate) {
		t.Errorf("an account whose token cannot be read must be an error, got %v", err)
	}
	if err := globalSiteReplicationSys.IAMChangeHook(site.ctx, item); err == nil {
		t.Error("the hook reported an account as sent that it could not read")
	}
	globalSiteReplicatorCred.Set("snapshot-site-signing-key")

	mustIAM(t, site.sys.DeleteServiceAccount(site.ctx, key, false))
	if _, err := globalSiteReplicationSys.replicationItem(site.ctx, item); !errors.Is(err, errIAMStaleUpdate) {
		t.Errorf("a deleted account must not be sent, got %v", err)
	}
	if sent := site.items(key); len(sent) != 1 {
		t.Errorf("the site sent %d items for the account, want only the create", len(sent))
	}
}

// svcAccPausedStore holds every load of a user until proceed is closed.
type svcAccPausedStore struct {
	IAMStorageAPI
	once             sync.Once
	loading, proceed chan struct{}
}

func (s *svcAccPausedStore) loadUser(ctx context.Context, user string, userType IAMUserType, m map[string]UserIdentity) error {
	s.once.Do(func() { close(s.loading) })
	<-s.proceed
	return s.IAMStorageAPI.loadUser(ctx, user, userType, m)
}

// The hook reads the account from storage without the lock of the
// replication configuration. Loading an identity takes that lock for
// reading; if the hook held it too, a change of the configuration that
// arrives in between would wait for the hook, and the hook for it.
func TestSiteReplicationHookReadsStorageUnlocked(t *testing.T) {
	const key = "snapshot-unlocked"
	site := newSvcAccSite(t)
	site.create(t, key)
	paused := &svcAccPausedStore{IAMStorageAPI: site.sys.store.IAMStorageAPI, loading: make(chan struct{}), proceed: make(chan struct{})}
	site.sys.store.IAMStorageAPI = paused

	sent := make(chan error, 1)
	go func() {
		sent <- globalSiteReplicationSys.IAMChangeHook(site.ctx, madmin.SRIAMItem{
			Type:         madmin.SRIAMItemSvcAcc,
			SvcAccChange: &madmin.SRSvcAccChange{Update: &madmin.SRSvcAccUpdate{AccessKey: key}},
		})
	}()
	select {
	case <-paused.loading:
	case err := <-sent:
		t.Fatalf("the hook did not read the account from storage (err=%v)", err)
	}
	// A writer that had to wait here would never get the lock, nor the
	// hook its next read lock behind that writer: try, do not wait.
	if globalSiteReplicationSys.TryLock() {
		globalSiteReplicationSys.Unlock() //nolint:staticcheck // only the lock is of interest
	} else {
		t.Error("the hook holds the lock of the replication configuration while it reads storage")
	}
	close(paused.proceed)
	select {
	case err := <-sent:
		mustIAM(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("the hook did not return")
	}
	if got := site.items(key); len(got) != 2 {
		t.Errorf("the site sent %d items for the account, want the create and the edit", len(got))
	}
}
