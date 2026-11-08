// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/policy/condition"
	"github.com/puzpuzpuz/xsync/v3"
)

// A batch job acts on objects long after the request that submitted it has
// gone. It therefore records who submitted it and acts only as that
// principal:
//
//   - StartBatchJob binds the authenticated credential to the job
//     (batchJobSubmitter). Nothing in the submitted definition names it.
//   - Every start of the job, and every object it touches, resolves the
//     binding against IAM again. A credential that is gone, disabled,
//     expired, revoked or edited since submission fails the job; a reused
//     access key does not match the binding.
//   - Each action is evaluated with the submitter's policies and session
//     policy but without a request. A policy statement that would need
//     request context the job does not have (source address, transport,
//     headers and so on) refuses the action instead of being skipped.
//
// A job without a binding was queued by an earlier release. It is never
// authorized, whoever submitted it, and has to be submitted again.

//go:generate msgp -file $GOFILE -unexported

// batchJobSubmitter is the server-assigned identity of the credential that
// submitted a batch job.
type batchJobSubmitter struct {
	Version   int    `msg:"v"`
	Type      string `msg:"t"`
	AccessKey string `msg:"ak"`
	// ParentUser is the parent of a derived credential.
	ParentUser string `msg:"pu"`
	// UpdatedAt and RevokedBefore are the revision of the identity record;
	// any edit of the identity changes them. They are unset for root.
	UpdatedAt     time.Time `msg:"ua"`
	RevokedBefore time.Time `msg:"rb"`
	// Binding is a keyed fingerprint of the credential itself, see
	// batchSubmitterBinding.
	Binding []byte `msg:"bd"`
}

const batchJobSubmitterVersion = 1

// Submitter types. A credential is classified in the order IsAllowed
// evaluates it.
const (
	batchSubmitterRoot      = "root"
	batchSubmitterUser      = "user"
	batchSubmitterTemporary = "temporary"
	batchSubmitterService   = "service-account"
)

//msgp:ignore batchJobAuthzError

// batchJobAuthzError refuses a batch job, or one of its actions, for its
// submitter. It ends the job: it is persisted as the job's failure and is
// never retried.
type batchJobAuthzError struct {
	reason string
}

func (e batchJobAuthzError) Error() string {
	return e.reason
}

func isBatchJobAuthzError(err error) bool {
	var e batchJobAuthzError
	return errors.As(err, &e)
}

var (
	errBatchJobResubmit = batchJobAuthzError{reason: "the batch job does not record who submitted it; submit it again"}
	errBatchJobChanged  = batchJobAuthzError{reason: "the credential that submitted the batch job has changed since submission; submit it again"}
	errBatchJobInvalid  = batchJobAuthzError{reason: "the credential that submitted the batch job is no longer valid"}
)

func batchSubmitterType(cred auth.Credentials) string {
	switch {
	case cred.IsTemp():
		return batchSubmitterTemporary
	case cred.IsServiceAccount():
		return batchSubmitterService
	default:
		return batchSubmitterUser
	}
}

// batchSubmitterBinding is a fingerprint of one credential keyed with its own
// secret. It changes when the secret, the session token or the parent
// changes, and a new credential that reuses the access key does not have it.
func batchSubmitterBinding(typ string, cred auth.Credentials) []byte {
	mac := hmac.New(sha256.New, []byte(cred.SecretKey))
	for _, s := range []string{"silo batch-job submitter v1", typ, cred.AccessKey, cred.ParentUser, cred.SessionToken} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		mac.Write(n[:])
		mac.Write([]byte(s))
	}
	return mac.Sum(nil)
}

// identityRecord returns the stored identity of a non-root access key.
func (sys *IAMSys) identityRecord(accessKey string) (UserIdentity, bool, error) {
	if !sys.Initialized() {
		return UserIdentity{}, false, errServerNotInitialized
	}
	u, ok := sys.store.GetUser(accessKey)
	return u, ok, nil
}

// newBatchJobSubmitter binds the credential that authenticated a
// StartBatchJob request.
func newBatchJobSubmitter(cred auth.Credentials) (*batchJobSubmitter, error) {
	root := globalActiveCred
	if cred.AccessKey == "" {
		return nil, errBatchJobInvalid
	}
	if cred.AccessKey == root.AccessKey {
		if subtle.ConstantTimeCompare([]byte(cred.SecretKey), []byte(root.SecretKey)) != 1 {
			return nil, errBatchJobChanged
		}
		return &batchJobSubmitter{
			Version:   batchJobSubmitterVersion,
			Type:      batchSubmitterRoot,
			AccessKey: root.AccessKey,
			Binding:   batchSubmitterBinding(batchSubmitterRoot, root),
		}, nil
	}
	u, ok, err := globalIAMSys.identityRecord(cred.AccessKey)
	if err != nil {
		return nil, batchUnavailable("IAM identity lookup", err)
	}
	// The record must be the one the request was authenticated with.
	if !ok || u.Credentials.AccessKey != cred.AccessKey || u.Credentials.ParentUser != cred.ParentUser ||
		subtle.ConstantTimeCompare([]byte(u.Credentials.SecretKey), []byte(cred.SecretKey)) != 1 ||
		subtle.ConstantTimeCompare([]byte(u.Credentials.SessionToken), []byte(cred.SessionToken)) != 1 {
		return nil, errBatchJobChanged
	}
	typ := batchSubmitterType(u.Credentials)
	return &batchJobSubmitter{
		Version:       batchJobSubmitterVersion,
		Type:          typ,
		AccessKey:     u.Credentials.AccessKey,
		ParentUser:    u.Credentials.ParentUser,
		UpdatedAt:     u.UpdatedAt,
		RevokedBefore: u.RevokedBefore,
		Binding:       batchSubmitterBinding(typ, u.Credentials),
	}, nil
}

//msgp:ignore batchJobPrincipal batchAuthzRequest

// batchJobPrincipal is a submitter resolved against current IAM state.
type batchJobPrincipal struct {
	ctx        context.Context
	typ        string
	accessKey  string
	parentUser string
	groups     []string
	claims     map[string]any
	owner      bool
	temp       bool // evaluated as a temporary credential
	service    bool // evaluated as a service account
}

// principal resolves the binding against current IAM state. It fails if the
// credential no longer exists, is no longer valid, or is no longer the one
// that was bound.
func (s *batchJobSubmitter) principal(ctx context.Context) (batchJobPrincipal, error) {
	if s == nil || s.AccessKey == "" {
		return batchJobPrincipal{}, errBatchJobResubmit
	}
	if s.Version != batchJobSubmitterVersion {
		return batchJobPrincipal{}, batchJobAuthzError{reason: fmt.Sprintf("unsupported batch job submitter version %d; submit the job again", s.Version)}
	}
	if !batchIAMReady() {
		return batchJobPrincipal{}, batchUnavailable("IAM is not initialized", errServerNotInitialized)
	}
	root := globalActiveCred
	if s.Type == batchSubmitterRoot {
		if s.AccessKey != root.AccessKey || !hmac.Equal(s.Binding, batchSubmitterBinding(batchSubmitterRoot, root)) {
			return batchJobPrincipal{}, errBatchJobChanged
		}
		if !globalAPIConfig.permitRootAccess() {
			return batchJobPrincipal{}, errBatchJobInvalid
		}
		return batchJobPrincipal{ctx: ctx, typ: batchSubmitterRoot, accessKey: root.AccessKey, owner: true}, nil
	}
	switch s.Type {
	case batchSubmitterUser, batchSubmitterTemporary, batchSubmitterService:
	default:
		return batchJobPrincipal{}, errBatchJobResubmit
	}
	if s.AccessKey == root.AccessKey {
		return batchJobPrincipal{}, errBatchJobChanged
	}
	u, ok, err := globalIAMSys.CheckKey(ctx, s.AccessKey)
	if err != nil {
		return batchJobPrincipal{}, batchUnavailable("IAM credential lookup", err)
	}
	if !ok {
		// Deleted, disabled, expired or revoked.
		return batchJobPrincipal{}, errBatchJobInvalid
	}
	cred := u.Credentials
	typ := batchSubmitterType(cred)
	if typ != s.Type || cred.AccessKey != s.AccessKey || cred.ParentUser != s.ParentUser ||
		!u.UpdatedAt.Equal(s.UpdatedAt) || !u.RevokedBefore.Equal(s.RevokedBefore) ||
		!hmac.Equal(s.Binding, batchSubmitterBinding(typ, cred)) {
		return batchJobPrincipal{}, errBatchJobChanged
	}
	if cred.IsExpired() || cred.Status == auth.AccountOff {
		return batchJobPrincipal{}, errBatchJobInvalid
	}
	p := batchJobPrincipal{
		ctx:        ctx,
		typ:        typ,
		accessKey:  cred.AccessKey,
		parentUser: cred.ParentUser,
		groups:     cred.Groups,
		claims:     map[string]any{},
		temp:       cred.IsTemp(),
		service:    !cred.IsTemp() && cred.IsServiceAccount(),
	}
	if typ != batchSubmitterUser {
		// Verify the token as a request would, with the current signing keys.
		jwtClaims, err := extractJWTClaims(u)
		if err != nil {
			if errors.Is(err, errTokenSigningKeyUnavailable) {
				return batchJobPrincipal{}, batchUnavailable("token signing key", err)
			}
			return batchJobPrincipal{}, errBatchJobInvalid
		}
		p.claims = jwtClaims.Map()
		if err := decodeBatchSessionPolicy(p.claims); err != nil {
			return batchJobPrincipal{}, errBatchJobInvalid
		}
	}
	p.owner = cred.ParentUser == root.AccessKey && cred.AccessKey != siteReplicatorSvcAcc
	if p.owner && !globalAPIConfig.permitRootAccess() {
		return batchJobPrincipal{}, errBatchJobInvalid
	}
	if _, ok := p.claims[policy.SessionPolicyName]; ok {
		p.owner = false
	}
	return p, nil
}

// decodeBatchSessionPolicy decodes a session policy claim for evaluation.
// A request decodes it while verifying its token, except when an
// authorization plugin is configured; a batch job decodes it always, so the
// session policy also limits what the plugin allows.
func decodeBatchSessionPolicy(claims map[string]any) error {
	sp, ok := claims[policy.SessionPolicyName]
	if !ok {
		return nil
	}
	s, ok := sp.(string)
	if !ok {
		return errAuthentication
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return errAuthentication
	}
	claims[sessionPolicyNameExtracted] = string(b)
	return nil
}

// batchAuthzRequest is one action a batch job is about to take.
type batchAuthzRequest struct {
	action policy.Action
	bucket string
	object string // empty for a bucket action
	// versionID is the version an object version action addresses.
	versionID string
	// tags are the current tags of the object version acted on.
	tags string
	// tagsUnknown is set when the job does not read the version it acts
	// on, so s3:ExistingObjectTag is context it does not have.
	tagsUnknown bool
	// values are request values the job supplies itself, such as the
	// listing prefix or the encryption and retention it writes, keyed by
	// condition key name.
	values map[string][]string
}

// batchAuthzMarker marks the condition values of a batch job for an
// authorization plugin. Requests cannot set s3:authType.
const batchAuthzMarker = "batch-job"

// Condition keys a batch job always provides, as a request would: identity,
// time, the addressed version and the stored tags. Keys a request takes from
// itself are provided only when the job sets them (see batchAuthzRequest
// values); every other key is request context the job does not have.
var batchServerConditionKeys = map[string]bool{
	condition.AWSCurrentTime.ToKey().String():    true,
	condition.AWSEpochTime.ToKey().String():      true,
	condition.AWSPrincipalType.ToKey().String():  true,
	condition.AWSUserID.ToKey().String():         true,
	condition.AWSUsername.ToKey().String():       true,
	condition.AWSGroups.ToKey().String():         true,
	condition.S3VersionID.ToKey().String():       true,
	condition.ExistingObjectTag.ToKey().String(): true,
}

// Request keys a job may supply, by the name they have in condition values.
var batchRequestConditionKeys = map[string]condition.KeyName{
	condition.S3Prefix.Name():                              condition.S3Prefix,
	condition.S3XAmzServerSideEncryption.Name():            condition.S3XAmzServerSideEncryption,
	condition.S3XAmzServerSideEncryptionAwsKmsKeyID.Name(): condition.S3XAmzServerSideEncryptionAwsKmsKeyID,
	condition.S3ObjectLockMode.Name():                      condition.S3ObjectLockMode,
	condition.S3ObjectLockRetainUntilDate.Name():           condition.S3ObjectLockRetainUntilDate,
	condition.S3ObjectLockLegalHold.Name():                 condition.S3ObjectLockLegalHold,
	condition.RequestObjectTagKeys.Name():                  condition.RequestObjectTagKeys,
}

// suppliedConditionKeys returns the condition keys whose values req provides.
func (req batchAuthzRequest) suppliedConditionKeys() map[string]bool {
	supplied := make(map[string]bool, len(batchServerConditionKeys)+len(req.values))
	for k := range batchServerConditionKeys {
		supplied[k] = true
	}
	if req.tagsUnknown {
		delete(supplied, condition.ExistingObjectTag.ToKey().String())
	}
	for name := range req.values {
		if key, ok := batchRequestConditionKeys[name]; ok {
			supplied[key.ToKey().String()] = true
		}
		if strings.HasPrefix(name, condition.RequestObjectTag.Name()+"/") {
			supplied[condition.RequestObjectTag.ToKey().String()] = true
		}
	}
	return supplied
}

func batchKeySupplied(supplied map[string]bool, name string) bool {
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	if strings.HasPrefix(name, "jwt:") || strings.HasPrefix(name, "ldap:") {
		// Claims of the verified token, as a request has them.
		return true
	}
	return supplied[name]
}

// conditionValues are the values a request with the same identity would
// carry, without any value taken from the request itself.
func (p batchJobPrincipal) conditionValues(req batchAuthzRequest) map[string][]string {
	now := UTCNow()
	username := p.accessKey
	if p.temp || p.service {
		username = p.parentUser
	}
	principalType := "User"
	if len(p.claims) > 0 {
		principalType = "AssumedRole"
	}
	if username == globalActiveCred.AccessKey {
		principalType = "Account"
	}
	// Identity and time, then the claims over them, as a request has them
	// (an LDAP session's short username replaces its parent DN).
	values := map[string][]string{
		"CurrentTime":   {now.Format(time.RFC3339)},
		"EpochTime":     {strconv.FormatInt(now.Unix(), 10)},
		"principaltype": {principalType},
		"userid":        {username},
		"username":      {username},
	}
	for k, v := range p.claims {
		if s, ok := v.(string); ok {
			values[strings.ToLower(strings.TrimPrefix(k, "ldap"))] = []string{s}
		}
	}
	// No claim stands for a value of the object or of the job, which
	// follow and always win.
	for k := range values {
		if k == "versionid" || k == "prefix" || k == "authtype" ||
			strings.HasPrefix(k, "existingobjecttag/") || strings.HasPrefix(k, "requestobjecttag") ||
			strings.HasPrefix(k, "x-amz-") || strings.HasPrefix(k, "object-lock-") {
			delete(values, k)
		}
	}
	// For an authorization plugin: this is a batch job, not a request.
	values["authType"] = []string{batchAuthzMarker}
	if req.versionID != "" {
		values["versionid"] = []string{req.versionID}
	}
	if req.tags != "" {
		if t, err := tags.ParseObjectTags(req.tags); err == nil {
			for k, v := range t.ToMap() {
				values[pathJoin("ExistingObjectTag", k)] = []string{v}
			}
		}
	}
	for k, v := range req.values {
		values[k] = v
	}
	if grpsVal, ok := p.claims["groups"]; ok {
		if grpsIs, ok := grpsVal.([]any); ok {
			grps := []string{}
			for _, gI := range grpsIs {
				if g, ok := gI.(string); ok {
					grps = append(grps, g)
				}
			}
			if len(grps) > 0 {
				values["groups"] = grps
			}
		}
	}
	if _, ok := values["groups"]; !ok && len(p.groups) > 0 {
		values["groups"] = p.groups
	}
	return values
}

// authorize evaluates one action of the job as its submitter.
func (p batchJobPrincipal) authorize(req batchAuthzRequest) error {
	args := policy.Args{
		AccountName:     p.accessKey,
		Groups:          p.groups,
		Action:          req.action,
		BucketName:      req.bucket,
		ObjectName:      req.object,
		ConditionValues: p.conditionValues(req),
		IsOwner:         p.owner,
		Claims:          p.claims,
	}
	return p.authorizeArgs(args, &req)
}

// authorizeArgs uses the same policy snapshot for request-context checks and
// the decision. No boolean IAM evaluator re-reads and silently drops policies.
func (p batchJobPrincipal) authorizeArgs(args policy.Args, req *batchAuthzRequest) error {
	denied := batchJobAuthzError{reason: "the batch job submitter is not allowed " + string(args.Action)}
	if req != nil {
		denied.reason = batchDeniedReason(*req)
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = GlobalContext
	}
	plugin := newGlobalAuthZPluginFn()
	var snap *batchPolicySnapshot
	if plugin == nil && !args.IsOwner {
		snap = globalIAMSys.store.batchSnapshot(ctx)
		defer snap.release()
	}
	policies, err := globalIAMSys.batchLocalPolicies(p, args, plugin == nil, snap)
	if err != nil {
		if errors.Is(err, errNoSuchPolicy) || errors.Is(err, errAuthentication) || errors.Is(err, errNoSuchUser) || errors.Is(err, errNoSuchGroup) {
			return denied
		}
		return batchUnavailable("IAM policy lookup", err)
	}
	if req != nil {
		supplied := req.suppliedConditionKeys()
		for _, pol := range policies {
			for _, st := range pol.Statements {
				if batchStatementNeedsRequest(st, args, supplied) {
					return batchJobAuthzError{reason: denied.reason + ": a policy statement depends on request context that a batch job does not have"}
				}
			}
		}
	}
	if plugin != nil {
		ok, err := plugin.IsAllowedContext(ctx, args)
		if err != nil {
			return batchUnavailable("authorization plugin", err)
		}
		if !ok {
			return denied
		}
		// The plugin does not see a session policy; it only limits further.
		if has, allowed := p.sessionPolicyDecision(args); has && !allowed {
			return denied
		}
		return nil
	}
	if args.IsOwner {
		return nil
	}
	if p.service {
		if p.claims[parentClaim] != p.parentUser {
			return denied
		}
		if _, ok := p.claims[iamPolicyClaimNameSA()].(string); !ok {
			return denied
		}
	}
	if has, allowed := p.sessionPolicyDecision(args); has && !allowed {
		return denied
	}
	ownerDerived := (p.temp || p.service) && p.parentUser == globalActiveCred.AccessKey
	if !ownerDerived {
		if p.service {
			args.AccountName = p.parentUser
		}
		if len(policies) == 0 || !policies[0].IsAllowed(args) {
			return denied
		}
	}
	return nil
}

func batchDeniedReason(req batchAuthzRequest) string {
	resource := req.bucket
	if req.object != "" {
		resource = pathJoin(req.bucket, req.object)
	}
	if req.versionID != "" {
		resource += " (versionId " + req.versionID + ")"
	}
	return fmt.Sprintf("the batch job submitter is not allowed %s on %s", req.action, resource)
}

// sessionPolicyDecision evaluates the session policy the way IsAllowed would
// for this credential.
func (p batchJobPrincipal) sessionPolicyDecision(args policy.Args) (bool, bool) {
	switch {
	case p.temp:
		return isAllowedBySessionPolicy(args)
	case p.service:
		if p.claims[iamPolicyClaimNameSA()] == inheritedPolicyType {
			return false, false
		}
		return isAllowedBySessionPolicyForServiceAccount(args)
	}
	return false, false
}

// batchIAMLoadTimeout bounds one storage read of a lazy IAM load during
// batch authorization, as MergePolicies bounds a policy document load.
const batchIAMLoadTimeout = 5 * time.Second

// batchPolicySnapshot reads the mappings and policy documents of a submitter
// at one cache revision while cached authentication and authorization
// proceed.
//
// It holds the store's writer mutex, so no writer changes the cache between
// its reads, and the cache read lock, which it releases around each storage
// read: a lazy mapping load or a policy document load. Request
// authentication then neither waits for storage nor queues behind a writer
// waiting for the cache lock, which taking the write lock back after each
// read would cause. It writes nothing to the cache but the lazily loaded
// mappings, which the request path stores under the read lock as well.
//
//msgp:ignore batchPolicySnapshot
type batchPolicySnapshot struct {
	*IAMStoreSys
	ctx   context.Context
	cache *iamCache
	mu    sync.Mutex
	reads int // storage reads in progress; the read lock is released while any
}

// batchSnapshot takes the snapshot; release it with release. rlock and
// runlock are the cache's read lock (IAMStorageAPI), not IAMStoreSys.lock,
// which also takes writeMu.
func (store *IAMStoreSys) batchSnapshot(ctx context.Context) *batchPolicySnapshot {
	store.writeMu.Lock()
	return &batchPolicySnapshot{IAMStoreSys: store, ctx: ctx, cache: store.rlock()}
}

func (s *batchPolicySnapshot) release() {
	s.runlock()
	s.writeMu.Unlock()
}

// read runs one storage read without the cache lock, bounded by the job's
// context and batchIAMLoadTimeout. Concurrent reads (the group fallback of
// policyDBGetGroups) release the lock before the first and take it back
// after the last.
func (s *batchPolicySnapshot) read(fn func(ctx context.Context) error) error {
	s.mu.Lock()
	if s.reads == 0 {
		s.runlock()
	}
	s.reads++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.reads--
		if s.reads == 0 {
			s.rlock()
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, batchIAMLoadTimeout)
	defer cancel()
	return fn(ctx)
}

func (s *batchPolicySnapshot) loadMappedPolicy(_ context.Context, name string, userType IAMUserType, isGroup bool, m *xsync.MapOf[string, MappedPolicy]) error {
	return s.read(func(ctx context.Context) error {
		return s.IAMStoreSys.loadMappedPolicy(ctx, name, userType, isGroup, m)
	})
}

// loadGroup would write the cache under the read lock. The snapshot resolves
// the policies of users, which never loads a group.
func (s *batchPolicySnapshot) loadGroup(context.Context, string, map[string]GroupInfo) error {
	return errors.New("batch authorization does not load groups")
}

func (s *batchPolicySnapshot) loadPolicyDoc(name string, out map[string]PolicyDoc) error {
	return s.read(func(ctx context.Context) error { return s.IAMStoreSys.loadPolicyDoc(ctx, name, out) })
}

// batchLocalPolicies returns every local policy that can take part in the
// decision on args: the mapped policies that IsAllowed would merge when
// withMapped is set (no authorization plugin), and the session policy.
func (sys *IAMSys) batchLocalPolicies(p batchJobPrincipal, args policy.Args, withMapped bool, snap *batchPolicySnapshot) ([]policy.Policy, error) {
	var out []policy.Policy
	if withMapped && args.IsOwner {
		// IsAllowed does not evaluate any policy for the owner.
		return nil, nil
	}
	if withMapped {
		// The caller holds snap through evaluation. Lazy mapping loads and
		// selected documents therefore belong to one cache revision.
		cache := snap.cache
		mappedPolicies := func(name string) ([]string, error) {
			names, _, err := cache.policyDBGet(snap, name, false, false)
			if err != nil {
				return nil, err
			}
			groups, err := cache.policyDBGetGroups(snap, len(names) > 0, args.Groups...)
			return append(names, groups...), err
		}
		var names []string
		ownerDerived := (p.temp || p.service) && p.parentUser == globalActiveCred.AccessKey
		switch {
		case p.typ == batchSubmitterRoot || ownerDerived:
		case p.temp || p.service:
			if roleArn := args.GetRoleArn(); roleArn != "" {
				a, err := arn.Parse(roleArn)
				if err != nil {
					return nil, err
				}
				names = append(names, newMappedPolicy(sys.rolesMap[a]).toSlice()...)
			} else {
				mapped, err := mappedPolicies(p.parentUser)
				if err != nil {
					return nil, err
				}
				names = append(names, mapped...)
				// The claimed policies apply only when nothing is mapped.
				if len(mapped) == 0 {
					if claimed, ok := policy.GetPoliciesFromClaims(args.Claims, iamPolicyClaimNameOpenID()); ok {
						names = append(names, claimed.ToSlice()...)
					}
				}
			}
		default:
			mapped, err := mappedPolicies(p.accessKey)
			if err != nil {
				return nil, err
			}
			names = append(names, mapped...)
		}
		var selected []policy.Policy
		for _, name := range names {
			doc, ok := cache.iamPolicyDocsMap[name]
			if !ok {
				loaded := make(map[string]PolicyDoc)
				err := snap.loadPolicyDoc(name, loaded)
				if errors.Is(err, errNoSuchPolicy) {
					// Confirmed absent, as when a mapping still names a
					// deleted policy: it takes no part in the decision, as
					// in MergePolicies. Any other failure could hide a Deny.
					continue
				}
				if err != nil {
					return nil, err
				}
				doc, ok = loaded[name]
				if !ok {
					return nil, fmt.Errorf("load IAM policy %q returned no document", name)
				}
			}
			selected = append(selected, doc.Policy)
		}
		out = append(out, policy.MergePolicies(selected...))
	}
	if p.temp || p.service {
		if p.service && p.claims[iamPolicyClaimNameSA()] == inheritedPolicyType {
			return out, nil
		}
		if sp, ok := p.claims[sessionPolicyNameExtracted]; ok {
			s, ok := sp.(string)
			if !ok {
				return nil, errAuthentication
			}
			parsed, err := policy.ParseConfig(strings.NewReader(s))
			if err != nil {
				return nil, err
			}
			out = append(out, *parsed)
		}
	}
	return out, nil
}

// batchStatementNeedsRequest reports whether a statement that applies to
// args depends on a condition key that the job does not supply. Applying
// such a statement without its value could grant (Allow) or drop (Deny)
// what a request with that context would not, so the job refuses the action.
// Resources are matched without conditions; a statement is taken to apply
// whenever it might.
func batchStatementNeedsRequest(st policy.Statement, args policy.Args, supplied map[string]bool) bool {
	if (!st.Actions.Match(args.Action) && !st.Actions.IsEmpty()) || st.NotActions.Match(args.Action) {
		return false
	}
	// Policy variables in resources or condition values.
	if data, err := json.Marshal(st); err == nil {
		s := string(data)
		for {
			i := strings.Index(s, "${")
			if i < 0 {
				break
			}
			s = s[i+2:]
			j := strings.IndexByte(s, '}')
			if j < 0 {
				break
			}
			if !batchKeySupplied(supplied, s[:j]) {
				return true
			}
			s = s[j+1:]
		}
	}
	if !batchStatementMayApply(st, args) {
		return false
	}
	for key := range st.Conditions.Keys() {
		if !batchKeySupplied(supplied, key.String()) {
			return true
		}
	}
	return false
}

// batchStatementMayApply matches the resources of a statement, in both forms
// a bucket request can take. A statement whose resources the evaluator
// translates (S3 Tables and vectors actions cover S3 data actions) is taken
// to apply.
func batchStatementMayApply(st policy.Statement, args policy.Args) bool {
	for _, actions := range []policy.ActionSet{st.Actions, st.NotActions} {
		for action := range actions {
			if policy.TableAction(action).IsValid() || policy.VectorsAction(action).IsValid() {
				return true
			}
		}
	}
	for _, resources := range []policy.ResourceSet{st.Resources, st.NotResources} {
		for r := range resources {
			if r.Type != policy.ResourceARNS3 && r.Type != policy.ResourceARNAll {
				return true
			}
		}
	}
	resources := []string{args.BucketName + "/" + strings.TrimPrefix(args.ObjectName, "/")}
	if args.ObjectName == "" {
		resources = []string{args.BucketName, args.BucketName + "/"}
	}
	for _, resource := range resources {
		if len(st.Resources) > 0 && !st.Resources.Match(resource, args.ConditionValues) {
			continue
		}
		if len(st.NotResources) > 0 && st.NotResources.Match(resource, args.ConditionValues) {
			continue
		}
		return true
	}
	return false
}

// authorize resolves the submitter and evaluates each request.
func (s *batchJobSubmitter) authorize(ctx context.Context, reqs ...batchAuthzRequest) error {
	p, err := s.principal(ctx)
	if err != nil {
		return err
	}
	for _, req := range reqs {
		if err := p.authorize(req); err != nil {
			return err
		}
	}
	return nil
}

// startAuthzRequests are the bucket actions a job needs before it acts on any
// object: the listings it walks. Object actions are authorized per object.
func (j BatchJobRequest) startAuthzRequests() []batchAuthzRequest {
	list := func(bucket string, prefixes []string) []batchAuthzRequest {
		if len(prefixes) == 0 {
			prefixes = []string{""}
		}
		var reqs []batchAuthzRequest
		for _, prefix := range prefixes {
			values := map[string][]string{condition.S3Prefix.Name(): {prefix}}
			reqs = append(reqs,
				batchAuthzRequest{action: policy.ListBucketAction, bucket: bucket, values: values},
				batchAuthzRequest{action: policy.ListBucketVersionsAction, bucket: bucket, values: values},
			)
		}
		return reqs
	}
	// The same order as Type() and the job pool.
	switch {
	case j.Replicate != nil:
		if !j.Replicate.RemoteToLocal() {
			return list(j.Replicate.Source.Bucket, j.Replicate.Source.Prefix.F())
		}
	case j.KeyRotate != nil:
		return list(j.KeyRotate.Bucket, []string{j.KeyRotate.Prefix})
	case j.Expire != nil:
		return list(j.Expire.Bucket, batchCanonicalPrefixes(j.Expire.Prefix.F()))
	}
	return nil
}

// jobSections counts the job types a definition holds. A job is one of them.
func (j BatchJobRequest) jobSections() int {
	n := 0
	for _, set := range []bool{j.Replicate != nil, j.KeyRotate != nil, j.Expire != nil} {
		if set {
			n++
		}
	}
	return n
}

var errBatchJobSections = batchJobAuthzError{reason: "a batch job must define exactly one job type"}

// refuse ends the job for its submitter.
func (ri *batchJobInfo) refuse(err error) {
	ri.mu.Lock()
	defer ri.mu.Unlock()
	if ri.FailureReason == "" {
		ri.FailureReason = err.Error()
	}
	ri.Complete = false
	ri.Failed = true
	ri.PausedReason = ""
}

func (ri *batchJobInfo) refused() bool {
	ri.mu.RLock()
	defer ri.mu.RUnlock()
	return ri.FailureReason != ""
}

// startAuthorized checks the submitter of a job that is about to run. It
// returns done for a job that must not run now: one refused before, which
// stays refused, or one refused now, which is persisted as failed first.
// An error that is not a decision leaves the job to a later start.
func (ri *batchJobInfo) startAuthorized(ctx context.Context, api ObjectLayer, job BatchJobRequest) (done bool, err error) {
	if !ri.refused() {
		err := job.Submitter.authorize(ctx, job.startAuthzRequests()...)
		if err == nil && job.jobSections() != 1 {
			err = errBatchJobSections
		}
		if err == nil {
			ri.mu.Lock()
			ri.PausedReason = ""
			ri.mu.Unlock()
			// Persist the report version before acting. Older binaries must not
			// resume an authorization-bearing job with server authority.
			if err := ri.updateAfter(ctx, api, 0, job); err != nil {
				return true, batchUnavailable("saving job progress", err)
			}
			return false, nil
		}
		if isBatchJobUnavailable(err) {
			return true, ri.savePaused(ctx, api, job, err)
		}
		if !isBatchJobAuthzError(err) {
			return true, err
		}
		ri.refuse(err)
		batchLogIf(ctx, fmt.Errorf("batch job %s refused: %w", job.ID, err))
	}
	globalBatchJobsMetrics.save(job.ID, ri)
	if err := ri.updateAfter(ctx, api, 0, job); err != nil {
		return true, batchUnavailable("saving job refusal", err)
	}
	return true, nil
}
