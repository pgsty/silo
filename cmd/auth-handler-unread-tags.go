// Copyright (c) 2026 Denis Babchuk
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
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/minio/minio-go/v7/pkg/set"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/logger"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/policy/condition"
	"github.com/puzpuzpuz/xsync/v3"
)

// authorizeRequestWithUnreadTags decides whether to disclose readErr for an
// object whose stored tags could not be read. It must not grant object access.
//
// Without the tags, an Allow statement that tests s3:ExistingObjectTag cannot
// match, so a caller allowed only by such a statement would get AccessDenied,
// which clients do not retry, for a transient server error such as lost read
// quorum. For a server error, try a bounded set of tags from the caller's
// policies and return the storage error if normal authorization accepts one.
// If no candidate passes, keep AccessDenied. This is not an exhaustive policy
// solver. For any other error, NoSuchKey among them, the tags stay empty.
func authorizeRequestWithUnreadTags(ctx context.Context, r *http.Request, action policy.Action, readErr error) APIErrorCode {
	s3Err := authorizeRequest(ctx, r, action)
	if s3Err == ErrNone || toAPIError(ctx, readErr).HTTPStatusCode < http.StatusInternalServerError {
		return s3Err
	}
	return authorizeRequestWithTagCandidates(ctx, r, action, s3Err)
}

// authorizeRequestWithPotentialTags performs the authorization needed before
// a remote replica can be read. An empty tag set is enough to reject a caller
// with no possible access, but a caller whose Allow depends on existing tags
// must be admitted so the remote copy can supply the authoritative tags.
// The returned decision is only a gate; the actual tags must be authorized
// again after they are read.
func authorizeRequestWithPotentialTags(ctx context.Context, r *http.Request, action policy.Action) APIErrorCode {
	s3Err := authorizeRequest(ctx, r, action)
	if s3Err == ErrNone {
		return ErrNone
	}
	return authorizeRequestWithTagCandidates(ctx, r, action, s3Err)
}

func authorizeRequestWithTagCandidates(ctx context.Context, r *http.Request, action policy.Action, s3Err APIErrorCode) APIErrorCode {
	for _, existingTags := range policyExistingObjectTags(ctx, r, action) {
		if authorizeRequestWithExistingTags(ctx, r, action, existingTags) == ErrNone {
			return ErrNone
		}
	}
	return s3Err
}

// maxExistingTagCandidates bounds the tag sets tried for one request; each
// one costs an authorization.
const maxExistingTagCandidates = 64

// policyExistingObjectTags returns tag sets under which the policies that
// authorize the request may let action through on its object: the bucket
// policy for an anonymous request, else the cached IAM policies and, as a
// second policy set, the session policy of the credential. A tag set passes
// the s3:ExistingObjectTag tests of one Allow statement of each policy set and,
// as far as the same tags allow, keeps the Deny statements that test tags from
// matching. The tag sets are only candidates; the regular authorization
// decides what they allow.
func policyExistingObjectTags(ctx context.Context, r *http.Request, action policy.Action) []string {
	reqInfo := logger.GetReqInfo(ctx)
	if reqInfo == nil {
		return nil
	}
	bucket, object := reqInfo.BucketName, reqInfo.ObjectName
	var (
		allows [][]map[string]string // per policy set, the tags its Allow statements ask for
		denies [][]map[string]string // per Deny statement, alternative tags that keep it from matching
	)
	// add collects the tags of a statement that applies to action on the
	// object, whatever its conditions.
	add := func(effect policy.Effect, conditions condition.Functions, values map[string][]string, fromSet *[]map[string]string) {
		candidates := existingObjectTagsCandidatesFor(effect, conditions, values)
		if effect == policy.Allow {
			*fromSet = append(*fromSet, candidates...)
		} else if len(candidates) > 0 {
			denies = append(denies, candidates)
		}
	}
	switch {
	case reqInfo.Cred.AccessKey == "":
		p, err := globalPolicySys.Get(bucket)
		if err != nil {
			return nil
		}
		values := getConditionValues(r, reqInfo.Region, auth.AnonymousCredentials)
		var fromSet []map[string]string
		for _, st := range p.Statements {
			match := st
			match.Effect, match.Conditions = policy.Allow, nil
			if match.IsAllowed(policy.BucketPolicyArgs{Action: action, BucketName: bucket, ObjectName: object, ConditionValues: values}) {
				add(st.Effect, st.Conditions, values, &fromSet)
			}
		}
		allows = append(allows, fromSet)
	case newGlobalAuthZPluginFn() == nil && globalIAMSys.Initialized():
		values := getConditionValues(r, "", reqInfo.Cred)
		policySets := globalIAMSys.unreadTagPolicySets(reqInfo.Cred)
		for _, policies := range policySets {
			var fromSet []map[string]string
			for _, p := range policies {
				for _, st := range p.Statements {
					match := st
					match.Effect, match.Conditions = policy.Allow, nil
					if match.IsAllowed(policy.Args{Action: action, BucketName: bucket, ObjectName: object, ConditionValues: values}) {
						add(st.Effect, st.Conditions, values, &fromSet)
					}
				}
			}
			allows = append(allows, fromSet)
		}
	}
	return combineExistingObjectTags(append(allows, denies...))
}

// unreadTagMappings reuses the normal user/group mapping lookup without lazy
// storage reads. Missing cache entries contribute no candidates; the regular
// authorization still decides whether any candidate is allowed.
type unreadTagMappings struct {
	*IAMStoreSys
}

func (unreadTagMappings) loadMappedPolicy(context.Context, string, IAMUserType, bool, *xsync.MapOf[string, MappedPolicy]) error {
	return errNoSuchPolicy
}

func (unreadTagMappings) loadGroup(context.Context, string, map[string]GroupInfo) error {
	return errNoSuchGroup
}

// unreadTagPolicySets selects only this credential's cached policies. Base
// and session policies remain separate because both must allow the request.
// This only supplies candidates, so identity, claims and policy validity are
// left to the normal authorization on each candidate.
func (sys *IAMSys) unreadTagPolicySets(cred auth.Credentials) [][]policy.Policy {
	derived := cred.IsTemp() || cred.IsServiceAccount()
	name := cred.AccessKey
	if derived {
		name = cred.ParentUser
	}
	cache := sys.store.rlock()
	defer sys.store.runlock()
	var names []string
	roleARN := (policy.Args{Claims: cred.Claims}).GetRoleArn()
	switch {
	case name == globalActiveCred.AccessKey:
	case derived && roleARN != "":
		parsed, err := arn.Parse(roleARN)
		if err != nil {
			return nil
		}
		names = newMappedPolicy(sys.rolesMap[parsed]).toSlice()
	default:
		loader := unreadTagMappings{sys.store}
		var err error
		names, _, err = cache.policyDBGet(loader, name, false, false)
		if err != nil {
			return nil
		}
		groups, err := cache.policyDBGetGroups(loader, len(names) > 0, cred.Groups...)
		if err != nil {
			return nil
		}
		names = append(names, groups...)
		if derived && len(names) == 0 {
			claims, _ := policy.GetPoliciesFromClaims(cred.Claims, iamPolicyClaimNameOpenID())
			names = claims.ToSlice()
		}
	}

	sets := [][]policy.Policy{nil}
	slices.Sort(names)
	for _, name := range slices.Compact(names) {
		if doc, ok := cache.iamPolicyDocsMap[name]; ok {
			sets[0] = append(sets[0], doc.Policy)
		}
	}
	if derived && (cred.IsTemp() || cred.Claims[iamPolicyClaimNameSA()] != inheritedPolicyType) {
		if sp, ok := cred.Claims[sessionPolicyNameExtracted].(string); ok {
			if p, err := policy.ParseConfig(strings.NewReader(sp)); err == nil {
				sets = append(sets, []policy.Policy{*p})
			}
		}
	}
	return sets
}

// combineExistingObjectTags combines alternatives from each base/session
// Allow set and each tag-dependent Deny. A set may also contribute no tags:
// another statement or another set may already supply what it needs. First
// values win conflicts; the normal authorization decides whether they work.
func combineExistingObjectTags(sets [][]map[string]string) []string {
	combos := []map[string]string{{}}
	for _, fromSet := range sets {
		fromSet = append(uniqueExistingObjectTagMaps(fromSet), nil)
		var next []map[string]string
		seen := set.NewStringSet()
	combinations:
		for _, combo := range combos {
			for _, addition := range fromSet {
				merged := maps.Clone(combo)
				for k, v := range addition {
					if _, ok := merged[k]; !ok {
						merged[k] = v
					}
				}
				t, err := tags.MapToObjectTags(merged)
				if err != nil || seen.Contains(t.String()) {
					continue
				}
				seen.Add(t.String())
				next = append(next, merged)
				if len(next) == maxExistingTagCandidates {
					break combinations
				}
			}
		}
		combos = next
	}
	var candidates []string
	for _, combo := range combos {
		if len(combo) != 0 { // empty tags were already authorized
			t, _ := tags.MapToObjectTags(combo)
			candidates = append(candidates, t.String())
		}
	}
	return candidates
}

// existingObjectTagsCandidatesFor returns tag sets under which the
// s3:ExistingObjectTag tests of conditions all pass, for an Allow statement,
// or one of them fails, for a Deny statement; a tag left out is absent. For an
// Allow, values for different tag keys are combined, while a Deny needs only
// one failing key. It tries the values named in the conditions, with policy
// variables resolved, wildcard fillers, and absence, then lets the policy
// engine decide whether each candidate really satisfies the conditions.
func existingObjectTagsCandidatesFor(effect policy.Effect, conditions condition.Functions, values map[string][]string) []map[string]string {
	// Each function tests one key, so the tests of one tag pass or fail
	// whatever the other tags are.
	byKey := make(map[string]condition.Functions)
	for _, f := range conditions {
		for key := range condition.NewFunctions(f).Keys() {
			if key.Is(condition.ExistingObjectTag) {
				byKey[key.Name()] = append(byKey[key.Name()], f)
			}
		}
	}
	if len(byKey) == 0 {
		return nil
	}

	keys := slices.Sorted(maps.Keys(byKey))
	if effect == policy.Deny {
		var candidates []map[string]string
		for _, key := range keys {
			candidates = append(candidates, existingObjectTagValues(key, strings.TrimPrefix(key, condition.ExistingObjectTag.Name()+"/"), byKey[key], values, false)...)
		}
		return uniqueExistingObjectTagMaps(candidates)
	}

	candidates := []map[string]string{{}}
	for _, key := range keys {
		keyCandidates := existingObjectTagValues(key, strings.TrimPrefix(key, condition.ExistingObjectTag.Name()+"/"), byKey[key], values, true)
		if len(keyCandidates) == 0 {
			return nil
		}
		next := make([]map[string]string, 0, min(maxExistingTagCandidates, len(candidates)*len(keyCandidates)))
		for _, base := range candidates {
			for _, keyCandidate := range keyCandidates {
				merged := maps.Clone(base)
				maps.Copy(merged, keyCandidate)
				next = append(next, merged)
				if len(next) == maxExistingTagCandidates {
					break
				}
			}
			if len(next) == maxExistingTagCandidates {
				break
			}
		}
		candidates = next
	}
	return uniqueExistingObjectTagMaps(candidates)
}

func uniqueExistingObjectTagMaps(candidates []map[string]string) []map[string]string {
	seen := set.NewStringSet()
	unique := make([]map[string]string, 0, len(candidates))
	for _, candidate := range candidates {
		t, err := tags.MapToObjectTags(candidate)
		if err != nil || seen.Contains(t.String()) {
			continue
		}
		seen.Add(t.String())
		unique = append(unique, candidate)
	}
	return unique
}

// existingObjectTagValues looks for values of tag tagKey, or its absence,
// under which the functions that test the condition key key evaluate to want.
func existingObjectTagValues(key, tagKey string, tests condition.Functions, values map[string][]string, want bool) []map[string]string {
	defer delete(values, key)
	delete(values, key)
	var candidates []map[string]string
	if tests.Evaluate(values) == want {
		candidates = append(candidates, map[string]string{})
	}
	// The functions keep their values unexported; JSON exposes them.
	buf, err := json.Marshal(tests)
	if err != nil {
		return candidates
	}
	var byName map[string]map[string]condition.ValueSet
	if err = json.Unmarshal(buf, &byName); err != nil {
		return candidates
	}
	var tried []string
	for name, byKey := range byName {
		if name == "Null" {
			continue // its operand says whether the tag is there, not a value
		}
		for _, valueSet := range byKey {
			for _, v := range valueSet.ToSlice() {
				s := substituteConditionVariables(v.String(), values)
				tried = append(tried, s, strings.NewReplacer("*", "", "?", "_").Replace(s))
			}
		}
	}
	slices.Sort(tried)
	for _, v := range append(slices.Compact(tried), "", "_") {
		if _, err := tags.MapToObjectTags(map[string]string{tagKey: v}); err != nil {
			continue
		}
		values[key] = []string{v}
		if tests.Evaluate(values) == want {
			candidates = append(candidates, map[string]string{tagKey: v})
			if len(candidates) == maxExistingTagCandidates {
				break
			}
		}
	}
	return uniqueExistingObjectTagMaps(candidates)
}

// substituteConditionVariables resolves the policy variables in v from the
// condition values as the policy engine does for the values of a condition;
// silo-pkg keeps its own function for this unexported.
func substituteConditionVariables(v string, values map[string][]string) string {
	for _, key := range condition.CommonKeys {
		if rvalues, ok := values[key.Name()]; ok && len(rvalues) > 0 && rvalues[0] != "" {
			v = strings.ReplaceAll(v, key.VarName(), rvalues[0])
		}
	}
	return v
}
