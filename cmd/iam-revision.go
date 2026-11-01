// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	etcd "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

var errIAMStaleUpdate = errors.New("IAM update predates a stored revision or revocation")

// The parent is still live; callers must not broadcast a user deletion when
// only its revocation boundary was retained.
var errIAMRevocationRetained = errors.New("IAM revocation recorded without deleting the record")

// A revocation advances the boundary even when a newer identity already
// exists. Keep this operation distinct from replacing/deleting that identity.
type iamUserRevocation struct {
	UserIdentity
	retained bool
}

type iamGroupRevocation struct {
	GroupInfo
	retained     bool
	requireEmpty bool
}

// Natural expiration is distinct from revoking a live credential. An expired
// immutable STS token can be removed; a reusable service-account key retains
// its revision so an older non-expiring credential cannot return.
type iamExpireIdentity struct{}

// The authoritative revocation is durable even if dependent cleanup fails.
// Callers must publish it to sibling caches before returning the error.
type iamCommittedCleanupError struct {
	err      error
	retained bool
}

func (e *iamCommittedCleanupError) Error() string {
	return "IAM revocation committed; cleanup failed: " + e.err.Error()
}
func (e *iamCommittedCleanupError) Unwrap() error { return e.err }

type iamReplicationTimeKey struct{}

func withIAMReplicationTime(ctx context.Context, at time.Time) context.Context {
	return context.WithValue(ctx, iamReplicationTimeKey{}, at)
}

func iamReplicationTime(ctx context.Context) (time.Time, bool) {
	at, ok := ctx.Value(iamReplicationTimeKey{}).(time.Time)
	return at, ok
}

func iamReplicationError(err error) error {
	if errors.Is(err, errIAMStaleUpdate) {
		// Retrying an obsolete event cannot change the result.
		return nil
	}
	return wrapSRErr(err)
}

// Deletions occupy the original IAM config path. They contain no secret or
// grant and are hidden by the normal loaders, but remain available to heal
// and to timestamp comparisons after a restart. Do not age them out: a peer
// can be offline indefinitely.
type iamRevision struct {
	UpdatedAt     time.Time        `json:"updatedAt"`
	UpdateDate    time.Time        `json:"UpdateDate"`
	Deleted       bool             `json:"deleted"`
	RevokedBefore time.Time        `json:"revokedBefore"`
	ExpiresAt     time.Time        `json:"expiresAt,omitempty"`
	Credentials   auth.Credentials `json:"credentials"`
}

func (r iamRevision) timestamp() time.Time {
	if r.UpdateDate.After(r.UpdatedAt) {
		return r.UpdateDate
	}
	return r.UpdatedAt
}

func loadIAMRevision(ctx context.Context, store IAMStorageAPI, path string) (iamRevision, error) {
	var r iamRevision
	err := store.loadIAMConfig(ctx, &r, path)
	if errors.Is(err, errConfigNotFound) {
		err = nil
	}
	return r, err
}

func (store *IAMStoreSys) checkIAMRevision(ctx context.Context, path string, deleting bool) error {
	at, replicated := iamReplicationTime(ctx)
	if !replicated {
		return nil
	}
	return store.withIAMStorage(ctx, func(ctx context.Context) error {
		r, err := loadIAMRevision(ctx, store.IAMStorageAPI, path)
		if err != nil {
			return err
		}
		if r.timestamp().After(at) || (r.Deleted && !deleting && !at.After(r.timestamp())) {
			return errIAMStaleUpdate
		}
		return nil
	})
}

// This signed claim records the parent's revocation boundary at issuance.
// Unlike UpdatedAt, it cannot advance when an offline site edits an old child.
// It travels in the existing service-account Claims and STS SessionToken fields.
const iamParentRevocationClaim = "siloParentRevocation"

func setIAMParentRevocationClaim(ctx context.Context, store IAMStorageAPI, parent string, claims map[string]any) error {
	delete(claims, iamParentRevocationClaim)
	if parent == "" || parent == globalActiveCred.AccessKey {
		return nil
	}
	r, err := loadIAMRevision(ctx, store, getUserIdentityPath(parent, regUser))
	if err != nil {
		return err
	}
	if r.Deleted {
		return errIAMStaleUpdate
	}
	if !r.RevokedBefore.IsZero() {
		claims[iamParentRevocationClaim] = r.RevokedBefore.Format(time.RFC3339Nano)
	}
	return nil
}

func iamCredentialSurvivesRevocation(cred auth.Credentials, at time.Time) bool {
	if at.IsZero() {
		return true
	}
	s, _ := cred.Claims[iamParentRevocationClaim].(string)
	issuedAfter, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && !issuedAfter.Before(at)
}

// Parent revocations delete old children even if an offline peer has edited
// them later. Preserve children that prove issuance after this revocation.
func iamChildDeletionContext(ctx context.Context, child UserIdentity) (context.Context, bool) {
	if at, replicated := iamReplicationTime(ctx); replicated {
		if !at.IsZero() && iamCredentialSurvivesRevocation(child.Credentials, at) {
			return ctx, false
		}
		if child.UpdatedAt.After(at) {
			ctx = withIAMReplicationTime(ctx, child.UpdatedAt)
		}
	}
	return ctx, true
}

// A delayed service account or STS event must not outlive deletion of its
// built-in parent. The caller must populate Claims from the verified token.
func checkIAMParentRevision(ctx context.Context, store IAMStorageAPI, cred auth.Credentials) error {
	parent := cred.ParentUser
	if parent == "" || parent == globalActiveCred.AccessKey {
		return nil
	}
	r, err := loadIAMRevision(ctx, store, getUserIdentityPath(parent, regUser))
	if err != nil {
		return err
	}
	if r.Deleted || !iamCredentialSurvivesRevocation(cred, r.RevokedBefore) {
		return errIAMStaleUpdate
	}
	return nil
}

// Called with the IAM writer mutex and cache lock held. Persistence only
// touches the caller's record, not the cache. Keep writers serialized while
// allowing cached authentication reads throughout storage and lock waits.
func (store *IAMStoreSys) withIAMStorage(ctx context.Context, fn func(context.Context) error) error {
	store.IAMStorageAPI.unlock()
	defer store.IAMStorageAPI.lock()
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	return fn(ctx)
}

func (store *IAMStoreSys) saveIAMRevision(ctx context.Context, path string, item any, opts ...options) error {
	return store.withIAMStorage(ctx, func(ctx context.Context) error {
		return saveIAMRevision(ctx, store.IAMStorageAPI, path, item, opts...)
	})
}

func (store *IAMStoreSys) checkIAMParentRevision(ctx context.Context, cred auth.Credentials) error {
	return store.withIAMStorage(ctx, func(ctx context.Context) error {
		return checkIAMParentRevision(ctx, store.IAMStorageAPI, cred)
	})
}

// Update the caller's record with the persisted revision before it is cached.
func saveIAMRevision(ctx context.Context, store IAMStorageAPI, path string, item any, opts ...options) error {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()

	// Serialize compare-and-write across nodes, as well as goroutines. Use a
	// separate lock name so saving the config does not reacquire this lock.
	switch s := store.(type) {
	case *IAMObjectStore:
		lock := s.objAPI.NewNSLock(minioMetaBucket, path+".revision-lock")
		lc, err := lock.GetLock(ctx, globalOperationTimeout)
		if err != nil {
			return err
		}
		defer lock.Unlock(lc)
		ctx = lc.Context()
	case *IAMEtcdStore:
		// Mutex.Lock also uses Client.Ctx() for cleanup after cancellation.
		// Borrow the existing services with the operation's bounded context;
		// never close this facade, which does not own those services.
		client := etcd.NewCtxClient(ctx, etcd.WithZapLogger(s.client.GetLogger()))
		client.KV, client.Lease, client.Watcher = s.client.KV, s.client.Lease, s.client.Watcher
		session, err := concurrency.NewSession(client, concurrency.WithContext(ctx))
		if err != nil {
			return err
		}
		defer func() {
			session.Orphan()
			// A canceled operation must still release its lease when etcd is
			// reachable. If it is unavailable, stop waiting and let it expire.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultContextTimeout)
			defer cancel()
			_, _ = s.client.Revoke(cleanupCtx, session.Lease())
		}()
		lock := concurrency.NewMutex(session, fmt.Sprintf("%s/iam-revision-locks/%x", minioConfigPrefix, sha256.Sum256([]byte(path))))
		if err = lock.Lock(ctx); err != nil {
			return err
		}
		// Revoking the session lease releases the lock, including on cancellation.
	}
	previous, err := loadIAMRevision(ctx, store, path)
	if err != nil {
		return err
	}
	if _, expiring := item.(*iamExpireIdentity); expiring {
		sts := strings.HasPrefix(path, iamConfigSTSPrefix)
		if previous.Deleted {
			if sts && !previous.ExpiresAt.IsZero() && UTCNow().After(previous.ExpiresAt) {
				return expireIAMSTSConfig(ctx, store, path)
			}
			return nil
		}
		if previous.timestamp().IsZero() || !previous.Credentials.IsExpired() {
			return nil
		}
		if sts {
			return expireIAMSTSConfig(ctx, store, path)
		}
		item = &UserIdentity{Version: 1, Deleted: true}
		ctx = withIAMReplicationTime(ctx, previous.timestamp())
	}
	var revocation *iamUserRevocation
	if op, ok := item.(*iamUserRevocation); ok {
		revocation = op
		op.UserIdentity = UserIdentity{Version: 1, Deleted: true}
		if origin, replicated := iamReplicationTime(ctx); replicated && previous.timestamp().After(origin) {
			if previous.Deleted || !origin.After(previous.RevokedBefore) {
				return errIAMStaleUpdate
			}
			op.retained = true
			op.UserIdentity = UserIdentity{Version: 1, Credentials: previous.Credentials, UpdatedAt: previous.timestamp(), RevokedBefore: origin}
			ctx = withIAMReplicationTime(ctx, previous.timestamp())
		}
		item = &op.UserIdentity
	}
	var groupRevocation *iamGroupRevocation
	if op, ok := item.(*iamGroupRevocation); ok {
		groupRevocation = op
		var group GroupInfo
		if err := store.loadIAMConfig(ctx, &group, path); err != nil && !errors.Is(err, errConfigNotFound) {
			return err
		}
		if op.requireEmpty && !group.Deleted {
			for _, member := range group.Members {
				r := store.revisionIndex().get(getUserIdentityPath(member, regUser))
				at := group.MemberGrants[member]
				if !r.Deleted && (r.RevokedBefore.IsZero() || at.After(r.RevokedBefore)) && (group.RevokedBefore.IsZero() || at.After(group.RevokedBefore)) {
					return errGroupNotEmpty
				}
			}
		}
		op.GroupInfo = GroupInfo{Version: 1, Deleted: true}
		if origin, replicated := iamReplicationTime(ctx); replicated && previous.timestamp().After(origin) {
			if previous.Deleted || !origin.After(previous.RevokedBefore) {
				return errIAMStaleUpdate
			}
			op.retained = true
			op.GroupInfo = group
			op.RevokedBefore = origin
			ctx = withIAMReplicationTime(ctx, previous.timestamp())
		}
		item = &op.GroupInfo
	}
	var at *time.Time
	var deleted bool
	switch v := item.(type) {
	case *UserIdentity:
		at, deleted = &v.UpdatedAt, v.Deleted
		if boundary, ok := ctx.Value(iamRecordBoundaryKey{}).(time.Time); ok && boundary.After(v.RevokedBefore) {
			v.RevokedBefore = boundary
		}
		if previous.RevokedBefore.After(v.RevokedBefore) {
			v.RevokedBefore = previous.RevokedBefore
		}
	case *GroupInfo:
		at, deleted = &v.UpdatedAt, v.Deleted
		if boundary, ok := ctx.Value(iamRecordBoundaryKey{}).(time.Time); ok && boundary.After(v.RevokedBefore) {
			v.RevokedBefore = boundary
		}
		if !deleted {
			var group GroupInfo
			if err := store.loadIAMConfig(ctx, &group, path); err != nil && !errors.Is(err, errConfigNotFound) {
				return err
			}
			mergeIAMGroupMutation(ctx, group, v)
		}
		if previous.RevokedBefore.After(v.RevokedBefore) {
			v.RevokedBefore = previous.RevokedBefore
		}
	case *MappedPolicy:
		at, deleted = &v.UpdatedAt, v.Deleted
	case *PolicyDoc:
		at, deleted = &v.UpdateDate, v.Deleted
	default:
		return errInvalidArgument
	}
	if strings.HasPrefix(path, iamConfigSTSPrefix) && previous.Deleted && !deleted {
		// STS access keys identify immutable tokens, not reusable user names.
		return errIAMStaleUpdate
	}
	if strings.HasPrefix(path, iamConfigSTSPrefix) && deleted {
		// STS keys are immutable. A delayed revocation must also defeat a
		// replayed creation that was recorded with a newer event timestamp.
		if origin, replicated := iamReplicationTime(ctx); replicated && previous.timestamp().After(origin) {
			ctx = withIAMReplicationTime(ctx, previous.timestamp())
		}
	}
	if origin, replicated := iamReplicationTime(ctx); replicated {
		*at = origin
		if previous.timestamp().After(origin) || (previous.Deleted && !deleted && !origin.After(previous.timestamp())) {
			return errIAMStaleUpdate
		}
		if strings.HasPrefix(path, iamConfigServiceAccountsPrefix) && !deleted && previous.Credentials.AccessKey != "" && previous.timestamp().Equal(origin) {
			// Duplicate service snapshots are acknowledgements, not new creates
			// or edits. Reload the winner without writing, so even a stale
			// sibling cache is refreshed by the retry before acknowledging it.
			return store.loadIAMConfig(ctx, item, path)
		}
		if previous.Deleted && deleted && !origin.After(previous.timestamp()) {
			// An already-applied tombstone needs no further persistent write.
			if v, ok := item.(*UserIdentity); ok {
				v.RevokedBefore = previous.RevokedBefore
			}
			if v, ok := item.(*GroupInfo); ok {
				v.RevokedBefore = previous.RevokedBefore
			}
			return nil
		}
	} else {
		if previous.Deleted && deleted {
			// A peer notification without an originating revision must not
			// advance a tombstone past a subsequent deliberate recreation.
			*at = previous.timestamp()
			if v, ok := item.(*UserIdentity); ok {
				v.RevokedBefore = previous.RevokedBefore
			}
			if v, ok := item.(*GroupInfo); ok {
				v.RevokedBefore = previous.RevokedBefore
			}
			return nil
		}
		if at.IsZero() {
			*at = UTCNow()
		}
		if !at.After(previous.timestamp()) {
			*at = previous.timestamp().Add(time.Nanosecond)
		}
	}
	if v, ok := item.(*UserIdentity); ok {
		if deleted {
			// Retain only the parent name for root-account exclusion during heal.
			v.Credentials = auth.Credentials{ParentUser: previous.Credentials.ParentUser}
			v.RevokedBefore = *at
			if strings.HasPrefix(path, iamConfigSTSPrefix) {
				// Carry expiry when a revocation arrives before the token itself.
				// It is safe to forget this key only after its signed lifetime.
				if expiration := previous.Credentials.Expiration; !expiration.IsZero() && !expiration.Equal(timeSentinel) && expiration.Add(globalMaxSkewTime).After(v.ExpiresAt) {
					v.ExpiresAt = expiration.Add(globalMaxSkewTime)
				}
				if previous.ExpiresAt.After(v.ExpiresAt) {
					v.ExpiresAt = previous.ExpiresAt
				}
				if !v.ExpiresAt.IsZero() {
					opts = []options{{ttl: max(1, int64(time.Until(v.ExpiresAt).Seconds())+1)}}
				}
			}
		} else {
			if v.Credentials.SessionToken != "" && v.Credentials.Claims == nil {
				claims, err := extractJWTClaims(*v)
				if err != nil {
					return err
				}
				v.Credentials.Claims = claims.Map()
			}
			if err = checkIAMParentRevision(ctx, store, v.Credentials); err != nil {
				return err
			}
		}
	}
	if v, ok := item.(*GroupInfo); ok && deleted {
		v.RevokedBefore = *at
		v.Members, v.MemberGrants = nil, nil
	}
	if _, ok := item.(*MappedPolicy); ok && !deleted {
		if parentPath := iamMappingParentPath(path); parentPath != "" {
			parent, err := loadIAMRevision(ctx, store, parentPath)
			if err != nil {
				return err
			}
			if parent.Deleted {
				return errIAMStaleUpdate
			}
			if !parent.RevokedBefore.IsZero() && !at.After(parent.RevokedBefore) {
				if _, replicated := iamReplicationTime(ctx); replicated {
					return errIAMStaleUpdate
				}
				*at = parent.RevokedBefore.Add(time.Nanosecond)
			}
		}
	}
	if err := store.saveIAMConfig(ctx, item, path, opts...); err != nil {
		return err
	}
	if revocation != nil && revocation.retained {
		return errIAMRevocationRetained
	}
	if groupRevocation != nil && groupRevocation.retained {
		return errIAMRevocationRetained
	}
	return nil
}

func (iamOS *IAMObjectStore) listIAMConfigPaths(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var paths []string
	for item := range listIAMConfigItems(ctx, iamOS.objAPI, iamConfigPrefix+"/") {
		if item.Err != nil {
			return nil, item.Err
		}
		paths = append(paths, iamConfigPrefix+"/"+item.Item)
	}
	return paths, nil
}

func (ies *IAMEtcdStore) listIAMConfigPaths(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
	defer cancel()
	r, err := ies.client.Get(ctx, iamConfigPrefix+"/", etcd.WithPrefix(), etcd.WithKeysOnly())
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(r.Kvs))
	for _, kv := range r.Kvs {
		paths = append(paths, string(kv.Key))
	}
	return paths, nil
}

func iamDeletionItem(path string, r iamRevision) (item madmin.SRIAMItem, ok bool) {
	if (strings.HasPrefix(path, iamConfigUsersPrefix) || strings.HasPrefix(path, iamConfigGroupsPrefix)) && !r.RevokedBefore.IsZero() {
		// Recreating a parent does not cancel its older revocation of derived
		// credentials. Replay this boundary even after the parent is live again.
		r.Deleted = true
		r.UpdatedAt, r.UpdateDate = r.RevokedBefore, time.Time{}
	}
	if !r.Deleted {
		return item, false
	}
	item.UpdatedAt = r.timestamp()
	switch {
	case strings.HasPrefix(path, iamConfigUsersPrefix):
		name := strings.TrimSuffix(strings.TrimPrefix(path, iamConfigUsersPrefix), "/"+iamIdentityFile)
		item.Type = madmin.SRIAMItemIAMUser
		item.IAMUser = &madmin.SRIAMUser{AccessKey: name, IsDeleteReq: true}
	case strings.HasPrefix(path, iamConfigSTSPrefix):
		if !r.ExpiresAt.IsZero() && UTCNow().After(r.ExpiresAt) {
			return item, false
		}
		item.Type = iamSTSDeleteType
		item.Name = strings.TrimSuffix(strings.TrimPrefix(path, iamConfigSTSPrefix), "/"+iamIdentityFile)
	case strings.HasPrefix(path, iamConfigServiceAccountsPrefix):
		name := strings.TrimSuffix(strings.TrimPrefix(path, iamConfigServiceAccountsPrefix), "/"+iamIdentityFile)
		if name == siteReplicatorSvcAcc || r.Credentials.ParentUser == globalActiveCred.AccessKey {
			return item, false
		}
		item.Type = madmin.SRIAMItemSvcAcc
		item.SvcAccChange = &madmin.SRSvcAccChange{Delete: &madmin.SRSvcAccDelete{AccessKey: name}}
	case strings.HasPrefix(path, iamConfigGroupsPrefix):
		name := strings.TrimSuffix(strings.TrimPrefix(path, iamConfigGroupsPrefix), "/"+iamGroupMembersFile)
		item.Type = madmin.SRIAMItemGroupInfo
		item.GroupInfo = &madmin.SRGroupInfo{UpdateReq: madmin.GroupAddRemove{Group: name, IsRemove: true}}
	case strings.HasPrefix(path, iamConfigPoliciesPrefix):
		item.Type = madmin.SRIAMItemPolicy
		item.Name = strings.TrimSuffix(strings.TrimPrefix(path, iamConfigPoliciesPrefix), "/"+iamPolicyFile)
	case strings.HasPrefix(path, iamConfigPolicyDBPrefix):
		prefix, name, found := strings.Cut(strings.TrimPrefix(path, iamConfigPolicyDBPrefix), "/")
		if !found {
			return item, false
		}
		typ := regUser
		switch prefix {
		case "sts-users":
			typ = stsUser
		case "service-accounts":
			typ = svcUser
		}
		item.Type = madmin.SRIAMItemPolicyMapping
		item.PolicyMapping = &madmin.SRPolicyMapping{UserOrGroup: strings.TrimSuffix(name, ".json"), UserType: int(typ), IsGroup: prefix == "groups"}
	default:
		// Other config paths do not represent replicated IAM deletions.
		return item, false
	}
	return item, true
}

func iamDeletionPath(item madmin.SRIAMItem) string {
	switch item.Type {
	case iamSTSDeleteType:
		return getUserIdentityPath(item.Name, stsUser)
	case madmin.SRIAMItemIAMUser:
		if item.IAMUser != nil && item.IAMUser.IsDeleteReq {
			return getUserIdentityPath(item.IAMUser.AccessKey, regUser)
		}
	case madmin.SRIAMItemSvcAcc:
		if item.SvcAccChange != nil && item.SvcAccChange.Delete != nil {
			return getUserIdentityPath(item.SvcAccChange.Delete.AccessKey, svcUser)
		}
	case madmin.SRIAMItemGroupInfo:
		if item.GroupInfo != nil && item.GroupInfo.UpdateReq.IsRemove && len(item.GroupInfo.UpdateReq.Members) == 0 {
			return getGroupInfoPath(item.GroupInfo.UpdateReq.Group)
		}
	case madmin.SRIAMItemPolicy:
		if len(item.Policy) == 0 {
			return getPolicyDocPath(item.Name)
		}
	case madmin.SRIAMItemPolicyMapping:
		if p := item.PolicyMapping; p != nil && p.Policy == "" {
			return getMappedPolicyPath(p.UserOrGroup, IAMUserType(p.UserType), p.IsGroup)
		}
	}
	return ""
}

func (c *SiteReplicationSys) healIAMDeletions(ctx context.Context) (err error) {
	started := time.Now()
	defer func() {
		c.iamRevisionMetrics.healDurationMillis.Store(time.Since(started).Milliseconds())
		if err != nil {
			c.iamRevisionMetrics.healFailures.Add(1)
		} else {
			c.iamRevisionMetrics.healLastSuccess.Store(time.Now().Unix())
		}
	}()
	c.iamHealMu.Lock()
	defer c.iamHealMu.Unlock()
	c.RLock()
	defer c.RUnlock()
	if !c.enabled {
		return nil
	}
	snapshot := globalIAMSys.store.revisionIndex().snapshot()
	paths := make([]string, 0, len(snapshot))
	for path := range snapshot {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	byType := make(map[string][]iamReplicationItem)
	for _, path := range paths {
		r := snapshot[path]
		item, ok := iamDeletionItem(path, r)
		if !ok {
			continue
		}
		out := iamReplicationItem{SRIAMItem: item}
		if item.Type == iamSTSDeleteType {
			out.STSExpiresAt = r.ExpiresAt
		}
		if item.Type == madmin.SRIAMItemIAMUser && !r.Deleted {
			out.Type, out.IAMUser = iamUserBoundaryType, nil
			out.UserRevocation = &iamUserBoundary{User: item.IAMUser.AccessKey, Before: r.RevokedBefore}
		}
		if item.Type == madmin.SRIAMItemGroupInfo && !r.Deleted {
			out.Type, out.GroupInfo = iamGroupBoundaryType, nil
			out.GroupRevocation = &iamGroupBoundary{Group: item.GroupInfo.UpdateReq.Group, Before: r.RevokedBefore}
		}
		byType[item.Type] = append(byType[item.Type], out)
	}
	var items []iamReplicationItem
	for _, typ := range []string{madmin.SRIAMItemPolicyMapping, madmin.SRIAMItemIAMUser, madmin.SRIAMItemSvcAcc, iamSTSDeleteType, madmin.SRIAMItemGroupInfo, madmin.SRIAMItemPolicy} {
		items = append(items, byType[typ]...)
	}
	if len(items) == 0 {
		return nil
	}
	if c.iamRevisionProgress == nil {
		c.iamRevisionProgress = make(map[string]iamRevisionProgress)
	}
	for id := range c.iamRevisionProgress {
		if _, present := c.state.Peers[id]; !present {
			delete(c.iamRevisionProgress, id)
		}
	}
	var progressMu sync.Mutex
	cerr := c.concDo(nil, func(id string, p madmin.PeerInfo) error {
		// Bound each pass, but retain acknowledgements independently of the
		// pass deadline or unrelated changes at either site.
		peerCtx, cancel := context.WithTimeout(ctx, defaultContextTimeout)
		defer cancel()
		client, err := c.getAdminClient(peerCtx, id)
		if err != nil {
			return err
		}
		remote, err := executeIAMRevisionRequest(peerCtx, client, http.MethodGet, nil)
		if err != nil {
			return err
		}
		progressMu.Lock()
		progress := c.iamRevisionProgress[id]
		progressMu.Unlock()
		progress.observePeer(remote)
		defer func() {
			progressMu.Lock()
			c.iamRevisionProgress[id] = progress
			progressMu.Unlock()
		}()
		var pending []iamReplicationItem
		for _, item := range items {
			path, version := iamReplicationMarker(item)
			if progress.Acknowledged[path] != version {
				pending = append(pending, item)
			}
		}
		// Acknowledgements are only a replay optimization, never GC proof.
		for path := range progress.Acknowledged {
			if _, retained := snapshot[path]; !retained {
				delete(progress.Acknowledged, path)
			}
		}
		var failures []error
		for next := 0; next < len(pending); {
			end := min(next+maxIAMRevisionBatch, len(pending))
			batch := pending[next:end]
			remote, err = executeIAMRevisionRequest(peerCtx, client, http.MethodPut, &iamRevisionBatch{Version: iamRevisionProtocol, Items: batch})
			if err != nil {
				var batchErr *iamRevisionBatchError
				if !errors.As(err, &batchErr) {
					return errors.Join(append(failures, err)...)
				}
				failures = append(failures, err)
			} else {
				progress.observePeer(remote)
				for _, item := range batch {
					path, version := iamReplicationMarker(item)
					progress.Acknowledged[path] = version
				}
			}
			next = end
		}
		return errors.Join(failures...)
	}, "IAM revision convergence")
	return errors.Unwrap(cerr)
}

func iamReplicationMarker(item iamReplicationItem) (path, version string) {
	path = iamDeletionPath(item.SRIAMItem)
	if item.UserRevocation != nil {
		path = getUserIdentityPath(item.UserRevocation.User, regUser)
	}
	if item.GroupRevocation != nil {
		path = getGroupInfoPath(item.GroupRevocation.Group)
	}
	return path, item.Type + ":" + item.UpdatedAt.UTC().Format(time.RFC3339Nano)
}

func (store *IAMStoreSys) savePolicyDoc(ctx context.Context, policyName string, p *PolicyDoc) error {
	return store.saveIAMRevision(ctx, getPolicyDocPath(policyName), p)
}

func (store *IAMStoreSys) saveMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool, mp *MappedPolicy, opts ...options) error {
	return store.saveIAMRevision(ctx, getMappedPolicyPath(name, userType, isGroup), mp, opts...)
}

func (store *IAMStoreSys) saveUserIdentity(ctx context.Context, name string, userType IAMUserType, u *UserIdentity, opts ...options) error {
	return store.saveIAMRevision(ctx, getUserIdentityPath(name, userType), u, opts...)
}

func (store *IAMStoreSys) saveGroupInfo(ctx context.Context, name string, gi *GroupInfo) error {
	return store.saveIAMRevision(ctx, getGroupInfoPath(name), gi)
}

func (store *IAMStoreSys) deletePolicyDoc(ctx context.Context, name string) error {
	return store.saveIAMRevision(ctx, getPolicyDocPath(name), &PolicyDoc{Version: 1, Deleted: true})
}

func (store *IAMStoreSys) deleteMappedPolicy(ctx context.Context, name string, userType IAMUserType, isGroup bool) error {
	return store.saveIAMRevision(ctx, getMappedPolicyPath(name, userType, isGroup), &MappedPolicy{Version: 1, Deleted: true})
}

func (store *IAMStoreSys) deleteUserIdentity(ctx context.Context, name string, userType IAMUserType) error {
	return store.saveIAMRevision(ctx, getUserIdentityPath(name, userType), &UserIdentity{Version: 1, Deleted: true})
}

// Called under the identity's distributed revision lock, after verifying that
// its immutable STS token (or early-revocation retention) has expired. Only the
// old token-key mapping is removed; the reusable parent mapping is unaffected.
func expireIAMSTSConfig(ctx context.Context, store IAMStorageAPI, path string) error {
	key := strings.TrimSuffix(strings.TrimPrefix(path, iamConfigSTSPrefix), "/"+iamIdentityFile)
	if err := store.deleteIAMConfig(ctx, getMappedPolicyPath(key, stsUser, false)); err != nil && !errors.Is(err, errConfigNotFound) {
		return err
	}
	return store.deleteIAMConfig(ctx, path)
}

type (
	iamExpirationCleanupKey   struct{}
	iamExpirationCleanupState struct{ failed atomic.Bool }
)

func withIAMExpirationCleanup(ctx context.Context) context.Context {
	if _, ok := ctx.Value(iamExpirationCleanupKey{}).(*iamExpirationCleanupState); ok {
		return ctx
	}
	return context.WithValue(ctx, iamExpirationCleanupKey{}, &iamExpirationCleanupState{})
}

func bestEffortIAMExpiration(ctx context.Context, store IAMStorageAPI, path string) {
	state, _ := ctx.Value(iamExpirationCleanupKey{}).(*iamExpirationCleanupState)
	if ctx.Err() != nil || (state != nil && state.failed.Load()) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	// Failure leaves the expired record and its existing version intact.
	// Stop optional reclamation for this load, while still loading healthy
	// users. Healthy cleanup has no per-scan quota that could build a backlog.
	if err := saveIAMRevision(ctx, store, path, &iamExpireIdentity{}); err != nil {
		if state != nil {
			state.failed.Store(true)
		}
		iamLogIf(ctx, err)
	}
}
