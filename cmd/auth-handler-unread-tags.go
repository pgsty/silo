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
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/logger"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/policy/condition"
)

// authorizeRequestWithUnreadTags authorizes action on an object whose stored
// tags could not be read because reading the object failed with readErr.
//
// Without the tags, an Allow statement that tests s3:ExistingObjectTag cannot
// match, so a caller allowed only by such a statement would get AccessDenied,
// which clients do not retry, for a transient server error such as lost read
// quorum. For a server error the request is therefore also authorized as if
// the object carried tags that the policies ask for: a caller that some tags
// let through gets the error, a caller that no tags let through still gets
// AccessDenied. For any other error, NoSuchKey among them, the tags stay empty.
func authorizeRequestWithUnreadTags(ctx context.Context, r *http.Request, action policy.Action, readErr error) APIErrorCode {
	s3Err := authorizeRequest(ctx, r, action)
	if s3Err == ErrNone || toAPIError(ctx, readErr).HTTPStatusCode < http.StatusInternalServerError {
		return s3Err
	}
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
		denies []map[string]string   // tags that keep a Deny statement from matching
	)
	// add files the tags of a statement that applies to action on the
	// object, whatever its conditions.
	add := func(effect policy.Effect, conditions condition.Functions, values map[string][]string, fromSet *[]map[string]string) {
		if tagMap, ok := existingObjectTagsFor(effect, conditions, values); ok {
			if effect == policy.Allow {
				*fromSet = append(*fromSet, tagMap)
			} else {
				denies = append(denies, tagMap)
			}
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
		// From the cache only: reading the drives may be what just failed.
		docs, _ := globalIAMSys.store.listPolicyDocs(ctx, "")
		policySets := [][]policy.Policy{nil}
		for _, name := range slices.Sorted(maps.Keys(docs)) {
			policySets[0] = append(policySets[0], docs[name].Policy)
		}
		if sp, ok := reqInfo.Cred.Claims[sessionPolicyNameExtracted].(string); ok {
			if p, err := policy.ParseConfig(strings.NewReader(sp)); err == nil {
				policySets = append(policySets, []policy.Policy{*p})
			}
		}
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
	return combineExistingObjectTags(allows, denies)
}

// combineExistingObjectTags merges the tags of one Allow statement of each
// policy set, or of none for a set that may allow without tags, and tries each
// result also with the tags that keep the Deny statements from matching. The
// first tags win a conflict; the authorization of the result settles it.
func combineExistingObjectTags(allows [][]map[string]string, denies []map[string]string) []string {
	merge := func(parts ...map[string]string) map[string]string {
		merged := make(map[string]string)
		for _, part := range parts {
			for k, v := range part {
				if _, ok := merged[k]; !ok {
					merged[k] = v
				}
			}
		}
		return merged
	}
	combos := [][]map[string]string{nil}
	for _, fromSet := range allows {
		// Many statements ask for the same tags.
		seen := set.NewStringSet()
		fromSet = slices.DeleteFunc(slices.Clone(fromSet), func(tagMap map[string]string) bool {
			t, err := tags.MapToObjectTags(tagMap)
			if err != nil || seen.Contains(t.String()) {
				return true
			}
			seen.Add(t.String())
			return false
		})
		next := make([][]map[string]string, 0, len(combos)*(len(fromSet)+1))
		for _, combo := range combos {
			next = append(next, combo)
			for _, tagMap := range fromSet {
				next = append(next, append(slices.Clip(combo), tagMap))
			}
		}
		combos = next[:min(len(next), maxExistingTagCandidates)]
	}
	deny := merge(denies...)
	found := set.NewStringSet()
	var candidates []string
	for _, combo := range combos {
		for _, tagMap := range []map[string]string{merge(combo...), merge(append(slices.Clip(combo), deny)...)} {
			t, err := tags.MapToObjectTags(tagMap)
			if len(tagMap) == 0 || err != nil || found.Contains(t.String()) {
				continue
			}
			found.Add(t.String())
			if candidates = append(candidates, t.String()); len(candidates) == maxExistingTagCandidates {
				return candidates
			}
		}
	}
	return candidates
}

// existingObjectTagsFor returns tags under which the s3:ExistingObjectTag tests
// of conditions all pass, for an Allow statement, or one of them fails, for a
// Deny statement; a tag left out is absent. It returns false if the conditions
// test no tag, or if no such tags were found among those tried for each tag:
// none, the values the tests name, with policy variables taken from values and
// wildcards filled, and the fillers "" and "_". The policy engine itself
// evaluates the tests for each of them.
func existingObjectTagsFor(effect policy.Effect, conditions condition.Functions, values map[string][]string) (map[string]string, bool) {
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
		return nil, false
	}
	tagMap := make(map[string]string)
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		tagKey := strings.TrimPrefix(key, condition.ExistingObjectTag.Name()+"/")
		value, present, found := existingObjectTagValue(key, tagKey, byKey[key], values, effect == policy.Allow)
		switch {
		case effect == policy.Deny && found:
			if present {
				tagMap[tagKey] = value
			}
			return tagMap, true
		case effect == policy.Allow && !found:
			return nil, false
		case present:
			tagMap[tagKey] = value
		}
	}
	if effect == policy.Deny {
		return nil, false
	}
	return tagMap, true
}

// existingObjectTagValue looks for a value of tag tagKey, or its absence,
// under which tests, the functions that test the condition key key, evaluate
// to want.
func existingObjectTagValue(key, tagKey string, tests condition.Functions, values map[string][]string, want bool) (value string, present, found bool) {
	defer delete(values, key)
	delete(values, key)
	if tests.Evaluate(values) == want {
		return "", false, true
	}
	// The functions keep their values unexported; JSON exposes them.
	buf, err := json.Marshal(tests)
	if err != nil {
		return "", false, false
	}
	var byName map[string]map[string]condition.ValueSet
	if err = json.Unmarshal(buf, &byName); err != nil {
		return "", false, false
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
			return v, true, true
		}
	}
	return "", false, false
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
