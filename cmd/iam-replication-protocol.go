// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/minio/madmin-go/v3"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

const (
	iamRevisionProtocol  = 1
	iamRevisionPeerPath  = "/v3/site-replication/peer/iam-revisions"
	iamUserBoundaryType  = "silo-user-revocation"
	iamGroupBoundaryType = "silo-group-revocation"
	iamSTSDeleteType     = "silo-sts-revocation"
	maxIAMRevisionBatch  = 128
)

var iamRevisionInstance = mustGetUUID()

type iamUserBoundary struct {
	User   string    `json:"user"`
	Before time.Time `json:"before"`
}

type iamGroupBoundary struct {
	Group  string    `json:"group"`
	Before time.Time `json:"before"`
}

// The server owns this additive protocol, without changing the client SDK or
// overloading a policy/document field. Old servers reject the dedicated route
// before applying any change that would lose revocation or member metadata.
type iamReplicationItem struct {
	madmin.SRIAMItem
	STSExpiresAt    time.Time            `json:"stsExpiresAt,omitempty"`
	GroupGrants     map[string]time.Time `json:"groupGrants,omitempty"`
	GroupSnapshot   bool                 `json:"groupSnapshot,omitempty"`
	UserRevocation  *iamUserBoundary     `json:"userRevocation,omitempty"`
	GroupRevocation *iamGroupBoundary    `json:"groupRevocation,omitempty"`
	RevokedBefore   time.Time            `json:"revokedBefore,omitempty"`
}

type iamRevisionBatch struct {
	Version int                  `json:"version"`
	Items   []iamReplicationItem `json:"items"`
}

type iamRevisionStatus struct {
	Version  int    `json:"version"`
	Node     string `json:"node"`
	Instance string `json:"instance"`
	Digest   string `json:"digest"`
}

type iamRevisionResponse struct {
	iamRevisionStatus
	Errors []string `json:"errors,omitempty"`
}

type iamRevisionBatchError struct{ failures []string }

func (e *iamRevisionBatchError) Error() string {
	return "IAM revision batch: " + strings.Join(e.failures, "; ")
}

type iamRevisionProgress struct {
	Instances    map[string]string
	Acknowledged map[string]string
}

type iamRevisionMetrics struct {
	healFailures       atomic.Uint64
	healLastSuccess    atomic.Int64
	healDurationMillis atomic.Int64
}

func iamRevisionDigest(items map[string]iamRevision) string {
	paths := make([]string, 0, len(items))
	for path := range items {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		r := items[path]
		fmt.Fprintf(h, "%q %s %t %s\n", path, r.timestamp().UTC().Format(time.RFC3339Nano), r.Deleted, r.RevokedBefore.UTC().Format(time.RFC3339Nano))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (store *IAMStoreSys) iamRevisionStatus() iamRevisionStatus {
	node := globalLocalNodeName
	if node == "" {
		node = "local"
	}
	return iamRevisionStatus{Version: iamRevisionProtocol, Node: node, Instance: iamRevisionInstance, Digest: store.revisionIndex().digest()}
}

func executeIAMRevisionRequest(ctx context.Context, client *madmin.AdminClient, method string, batch *iamRevisionBatch) (status iamRevisionStatus, err error) {
	var content []byte
	if batch != nil {
		content, err = json.Marshal(batch)
		if err != nil {
			return status, err
		}
	}
	resp, err := client.ExecuteMethod(ctx, method, madmin.RequestData{RelPath: iamRevisionPeerPath, QueryValues: url.Values{"api-version": {madmin.SiteReplAPIVersion}}, Content: content})
	if resp != nil {
		defer xhttp.DrainBody(resp.Body)
	}
	if err != nil {
		return status, err
	}
	if resp.StatusCode != http.StatusOK {
		var remote madmin.ErrorResponse
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&remote) == nil && remote.Code != "" {
			return status, remote
		}
		return status, fmt.Errorf("IAM revision protocol requires upgraded peers: %s", resp.Status)
	}
	var response iamRevisionResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&response); err != nil {
		return status, err
	}
	status = response.iamRevisionStatus
	if status.Version != iamRevisionProtocol || status.Node == "" || status.Instance == "" || status.Digest == "" {
		return status, errors.New("peer did not acknowledge the IAM revision protocol")
	}
	if len(response.Errors) != 0 {
		return status, &iamRevisionBatchError{failures: response.Errors}
	}
	return status, nil
}

type (
	iamRecordBoundaryKey struct{}
	iamGroupSnapshotKey  struct{}
)

func (c *SiteReplicationSys) replicationItem(ctx context.Context, item madmin.SRIAMItem) (iamReplicationItem, error) {
	out := iamReplicationItem{SRIAMItem: item}
	if item.Type == iamSTSDeleteType {
		r, err := loadIAMRevision(ctx, globalIAMSys.store, getUserIdentityPath(item.Name, stsUser))
		if err != nil {
			return out, err
		}
		out.STSExpiresAt = r.ExpiresAt
	}
	if item.Type == madmin.SRIAMItemSvcAcc && item.SvcAccChange != nil {
		var key string
		if item.SvcAccChange.Create != nil {
			key = item.SvcAccChange.Create.AccessKey
		} else if item.SvcAccChange.Update != nil {
			key = item.SvcAccChange.Update.AccessKey
		}
		if key != "" {
			r, err := loadIAMRevision(ctx, globalIAMSys.store, getUserIdentityPath(key, svcUser))
			if err != nil {
				return out, err
			}
			if r.Deleted || r.timestamp().After(item.UpdatedAt) {
				return out, errIAMStaleUpdate
			}
			out.RevokedBefore = r.RevokedBefore
		}
	}
	if item.Type == madmin.SRIAMItemGroupInfo && item.GroupInfo != nil && !item.GroupInfo.UpdateReq.IsRemove {
		out.GroupSnapshot = true
		var gi GroupInfo
		if err := globalIAMSys.store.loadIAMConfig(ctx, &gi, getGroupInfoPath(item.GroupInfo.UpdateReq.Group)); err != nil {
			return out, err
		}
		// The matching persisted snapshot carries member grant times. If a
		// later write won before sending, propagate that whole newer state.
		if gi.Deleted {
			return out, errIAMStaleUpdate
		}
		out.UpdatedAt = gi.UpdatedAt
		out.RevokedBefore = gi.RevokedBefore
		out.GroupInfo = &madmin.SRGroupInfo{UpdateReq: madmin.GroupAddRemove{Group: item.GroupInfo.UpdateReq.Group, Status: madmin.GroupStatus(gi.Status)}}
		cache := globalIAMSys.store.rlock()
		out.GroupInfo.UpdateReq.Members = cache.effectiveGroupMembers(gi)
		globalIAMSys.store.runlock()
		out.GroupGrants = make(map[string]time.Time, len(out.GroupInfo.UpdateReq.Members))
		for _, member := range out.GroupInfo.UpdateReq.Members {
			out.GroupGrants[member] = gi.MemberGrants[member]
		}
	}
	if item.Type == madmin.SRIAMItemGroupInfo && item.GroupInfo != nil && item.GroupInfo.UpdateReq.IsRemove && len(item.GroupInfo.UpdateReq.Members) == 0 {
		r, err := loadIAMRevision(ctx, globalIAMSys.store, getGroupInfoPath(item.GroupInfo.UpdateReq.Group))
		if err != nil {
			return out, err
		}
		if !r.Deleted && !r.RevokedBefore.IsZero() {
			out.Type, out.GroupInfo = iamGroupBoundaryType, nil
			out.GroupRevocation = &iamGroupBoundary{Group: item.GroupInfo.UpdateReq.Group, Before: r.RevokedBefore}
			out.UpdatedAt = r.RevokedBefore
		}
	}
	if item.Type == madmin.SRIAMItemIAMUser && item.IAMUser != nil {
		r, err := loadIAMRevision(ctx, globalIAMSys.store, getUserIdentityPath(item.IAMUser.AccessKey, regUser))
		if err != nil {
			return out, err
		}
		if item.IAMUser.IsDeleteReq && !r.Deleted && !r.RevokedBefore.IsZero() {
			out.Type = iamUserBoundaryType
			out.IAMUser = nil
			out.UserRevocation = &iamUserBoundary{User: item.IAMUser.AccessKey, Before: r.RevokedBefore}
			out.UpdatedAt = r.RevokedBefore
		} else if !item.IAMUser.IsDeleteReq {
			if r.Deleted || r.timestamp().After(item.UpdatedAt) {
				return out, errIAMStaleUpdate
			}
			out.RevokedBefore = r.RevokedBefore
		}
	}
	return out, nil
}

func applyIAMReplicationItem(ctx context.Context, item iamReplicationItem) error {
	if item.GroupInfo != nil {
		if item.GroupSnapshot {
			ctx = context.WithValue(ctx, iamGroupSnapshotKey{}, true)
		}
		// A nil map also explicitly denotes unknown legacy grants. Do not
		// turn an unrelated group edit into a new grant after a revocation.
		ctx = withIAMGroupGrants(ctx, item.GroupGrants)
	}
	if !item.RevokedBefore.IsZero() {
		if item.RevokedBefore.After(item.UpdatedAt) {
			return errSRInvalidRequest(errInvalidArgument)
		}
		ctx = context.WithValue(ctx, iamRecordBoundaryKey{}, item.RevokedBefore)
	}
	switch item.Type {
	case iamSTSDeleteType:
		if item.Name == "" || strings.ContainsAny(item.Name, "/\\") || item.UpdatedAt.IsZero() {
			return errSRInvalidRequest(errInvalidArgument)
		}
		if err := globalIAMSys.store.revokeTempUser(withIAMReplicationTime(ctx, item.UpdatedAt), item.Name, item.STSExpiresAt); err != nil {
			return iamReplicationError(err)
		}
		globalIAMSys.notifyForUser(ctx, item.Name, true)
		return nil
	case iamUserBoundaryType:
		if item.UserRevocation == nil || item.UserRevocation.User == "" || item.UserRevocation.Before.IsZero() {
			return errSRInvalidRequest(errInvalidArgument)
		}
		return iamReplicationError(globalIAMSys.DeleteUser(withIAMReplicationTime(ctx, item.UserRevocation.Before), item.UserRevocation.User, true))
	case iamGroupBoundaryType:
		if item.GroupRevocation == nil || item.GroupRevocation.Group == "" || item.GroupRevocation.Before.IsZero() {
			return errSRInvalidRequest(errInvalidArgument)
		}
		_, err := globalIAMSys.RemoveUsersFromGroup(withIAMReplicationTime(ctx, item.GroupRevocation.Before), item.GroupRevocation.Group, nil)
		return iamReplicationError(err)
	case madmin.SRIAMItemPolicy:
		if len(item.Policy) == 0 {
			return globalSiteReplicationSys.PeerAddPolicyHandler(ctx, item.Name, nil, item.UpdatedAt)
		}
		p, err := policy.ParseConfig(bytes.NewReader(item.Policy))
		if err != nil {
			return err
		}
		if p.IsEmpty() {
			p = nil
		}
		return globalSiteReplicationSys.PeerAddPolicyHandler(ctx, item.Name, p, item.UpdatedAt)
	case madmin.SRIAMItemSvcAcc:
		return globalSiteReplicationSys.PeerSvcAccChangeHandler(ctx, item.SvcAccChange, item.UpdatedAt)
	case madmin.SRIAMItemPolicyMapping:
		return globalSiteReplicationSys.PeerPolicyMappingHandler(ctx, item.PolicyMapping, item.UpdatedAt)
	case madmin.SRIAMItemSTSAcc:
		return globalSiteReplicationSys.PeerSTSAccHandler(ctx, item.STSCredential, item.UpdatedAt)
	case madmin.SRIAMItemIAMUser:
		return globalSiteReplicationSys.PeerIAMUserChangeHandler(ctx, item.IAMUser, item.UpdatedAt)
	case madmin.SRIAMItemGroupInfo:
		return globalSiteReplicationSys.PeerGroupInfoChangeHandler(ctx, item.GroupInfo, item.UpdatedAt)
	default:
		return errSRInvalidRequest(errInvalidArgument)
	}
}

func (a adminAPIHandlers) SRPeerIAMRevisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if obj, _ := validateAdminReq(ctx, w, r, policy.SiteReplicationOperationAction); obj == nil {
		return
	}
	var failures []string
	if r.Method == http.MethodPut {
		var batch iamRevisionBatch
		if err := parseJSONBody(ctx, r.Body, &batch, ""); err != nil {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, err), r.URL)
			return
		}
		if batch.Version != iamRevisionProtocol || len(batch.Items) == 0 || len(batch.Items) > maxIAMRevisionBatch {
			writeErrorResponseJSON(ctx, w, toAdminAPIErr(ctx, errSRInvalidRequest(errInvalidArgument)), r.URL)
			return
		}
		for i, item := range batch.Items {
			if err := applyIAMReplicationItem(ctx, item); err != nil {
				failures = append(failures, fmt.Sprintf("item %d (%s): %v", i, item.Type, err))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(iamRevisionResponse{iamRevisionStatus: globalIAMSys.store.iamRevisionStatus(), Errors: failures})
}

// A site endpoint can balance requests across nodes sharing durable IAM state.
// Switching between known node incarnations preserves ACKs; a new incarnation
// conservatively invalidates them so restoring an old backend cannot inherit
// acknowledgements from before the restore.
func (p *iamRevisionProgress) observePeer(status iamRevisionStatus) {
	if p.Instances == nil {
		p.Instances = make(map[string]string)
	}
	if p.Instances[status.Node] != status.Instance || p.Acknowledged == nil {
		p.Instances[status.Node] = status.Instance
		p.Acknowledged = make(map[string]string)
	}
}
