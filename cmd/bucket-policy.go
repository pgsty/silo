// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	miniogopolicy "github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/handlers"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/policy/condition"
)

// PolicySys - policy subsystem.
type PolicySys struct{}

// Get returns stored bucket policy
func (sys *PolicySys) Get(bucket string) (*policy.BucketPolicy, error) {
	policy, _, err := globalBucketMetadataSys.GetPolicyConfig(bucket)
	return policy, err
}

// IsAllowed - checks given policy args is allowed to continue the Rest API.
func (sys *PolicySys) IsAllowed(args policy.BucketPolicyArgs) bool {
	p, err := sys.Get(args.BucketName)
	if err == nil {
		return p.IsAllowed(args)
	}

	// Log unhandled errors.
	if _, ok := err.(BucketPolicyNotFound); !ok {
		internalLogIf(GlobalContext, err, logger.WarningKind)
	}

	// As policy is not available for given bucket name, returns IsOwner i.e.
	// operation is allowed only for owner.
	return args.IsOwner
}

// NewPolicySys - creates new policy system.
func NewPolicySys() *PolicySys {
	return &PolicySys{}
}

func getSTSConditionValues(r *http.Request, lc string, cred auth.Credentials) map[string][]string {
	m := make(map[string][]string)
	if d := r.Form.Get("DurationSeconds"); d != "" {
		m["DurationSeconds"] = []string{d}
	}
	return m
}

type conditionValueSource uint8

const (
	conditionValueFromHeader conditionValueSource = 1 << iota
	conditionValueFromQuery
)

// clientSuppliedConditionKeys records where each request-derived condition
// value actually comes from. Most x-amz-* values are headers, list parameters
// are query-only, and storage class retains the compatible query form consumed
// by object operations.
var clientSuppliedConditionKeys = map[string]conditionValueSource{
	"prefix":    conditionValueFromQuery,
	"delimiter": conditionValueFromQuery,
	"max-keys":  conditionValueFromQuery,
	// AWS explicitly excludes the query-string form from this policy key,
	// even though MinIO may consume it separately while verifying a presign.
	"x-amz-content-sha256":                            conditionValueFromHeader,
	"x-amz-copy-source":                               conditionValueFromHeader,
	"x-amz-metadata-directive":                        conditionValueFromHeader,
	"x-amz-server-side-encryption":                    conditionValueFromHeader,
	"x-amz-server-side-encryption-aws-kms-key-id":     conditionValueFromHeader,
	"x-amz-server-side-encryption-customer-algorithm": conditionValueFromHeader,
	"x-amz-storage-class":                             conditionValueFromHeader | conditionValueFromQuery,
}

func acceptsConditionValueSource(key string, source conditionValueSource) bool {
	name := strings.ToLower(key)
	allowed, ok := clientSuppliedConditionKeys[name]
	if !ok {
		return true
	}
	if allowed&source == 0 {
		return false
	}
	return source != conditionValueFromQuery || key == name
}

// internalConditionKeys holds every other name a condition key can resolve to.
// Those name values MinIO derives for itself - identity from the credential,
// time from the clock, transport from the connection - and a request must never
// write one, whether or not the server populated it this time round: a name the
// server left empty is as forgeable as one it filled in, and the condition
// reading it cannot tell the difference.
//
// Deriving the set from the condition keys rather than from what
// getConditionValues writes is what makes it complete. The engine reads by key
// name, so the key list is the attack surface; enumerating the writes misses
// every key the server has no value for, which is most of jwt: and ldap:. It
// also defaults new upstream keys to reserved, which is the safe direction.
//
// Reserving a name only removes it from the condition map. Request handling is
// untouched - a handler still reads its own query parameters and headers.
//
// aws:SourceIp is still only as trustworthy as the forwarding headers it is
// computed from, see the note on GetSourceIPFromHeaders.
var internalConditionKeys = func() map[string]struct{} {
	keys := make(map[string]struct{}, 2*len(condition.AllSupportedKeys))
	for _, keyName := range condition.AllSupportedKeys {
		name := keyName.ToKey().Name()
		if _, clientSupplied := clientSuppliedConditionKeys[name]; clientSupplied {
			continue
		}
		// A condition key resolves against its exact name and falls back to the
		// canonical MIME form, so both spellings have to be held. This is also
		// what covers object lock, stored as Object-Lock-Mode and read as
		// s3:object-lock-mode.
		keys[name] = struct{}{}
		keys[http.CanonicalHeaderKey(name)] = struct{}{}
	}
	return keys
}()

// Tag conditions name one tag key each, so the variable forms are reserved by
// prefix; the bare names come from the loop above.
var internalConditionKeyPrefixes = []string{"ExistingObjectTag/", "RequestObjectTag/"}

func isInternalConditionKey(key string) bool {
	if _, ok := internalConditionKeys[key]; ok {
		return true
	}
	for _, prefix := range internalConditionKeyPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func getConditionValues(r *http.Request, lc string, cred auth.Credentials) map[string][]string {
	return getConditionValuesWithExistingTags(r, lc, cred, "")
}

func getConditionValuesWithExistingTags(r *http.Request, lc string, cred auth.Credentials, existingTags string) map[string][]string {
	return getConditionValuesWithTags(r, lc, cred, existingTags, nil)
}

func getConditionValuesWithTags(r *http.Request, lc string, cred auth.Credentials, existingTags string, requestTags *string) map[string][]string {
	currTime := UTCNow()

	var (
		username = cred.AccessKey
		claims   = cred.Claims
		groups   = cred.Groups
	)

	if cred.IsTemp() || cred.IsServiceAccount() {
		// For derived credentials, check the parent user's permissions.
		username = cred.ParentUser
	}

	principalType := "Anonymous"
	if username != "" {
		principalType = "User"
		if len(claims) > 0 {
			principalType = "AssumedRole"
		}
		if username == globalActiveCred.AccessKey {
			principalType = "Account"
		}
	}

	// Match the version the object layer will act on: newContext and getOpts both
	// TrimSpace this value, so leaving it untrimmed here would let a padded
	// ?versionId=V%20 present a different s3:versionid than the effective version.
	vid := strings.TrimSpace(r.Form.Get(xhttp.VersionID))
	if vid == "" {
		if u, err := url.Parse(r.Header.Get(xhttp.AmzCopySource)); err == nil {
			vid = strings.TrimSpace(u.Query().Get(xhttp.VersionID))
		}
	}

	authType := getRequestAuthType(r)
	var signatureVersion string
	switch authType {
	case authTypeSignedV2, authTypePresignedV2:
		signatureVersion = signV2Algorithm
	case authTypeSigned, authTypePresigned, authTypeStreamingSigned,
		authTypeStreamingSignedTrailer, authTypePostPolicy:
		signatureVersion = signV4Algorithm
	case authTypeStreamingUnsignedTrailer:
		// This form is also valid for a genuinely anonymous request. Only
		// expose SigV4 condition values when header authentication is present.
		if r.Header.Get(xhttp.Authorization) != "" {
			signatureVersion = signV4Algorithm
		}
	}

	var authtype string
	switch authType {
	case authTypePresignedV2, authTypePresigned:
		authtype = "REST-QUERY-STRING"
	case authTypeSignedV2, authTypeSigned, authTypeStreamingSigned, authTypeStreamingSignedTrailer:
		authtype = "REST-HEADER"
	case authTypeStreamingUnsignedTrailer:
		if r.Header.Get(xhttp.Authorization) != "" {
			authtype = "REST-HEADER"
		}
	case authTypePostPolicy:
		authtype = "POST"
	}

	args := map[string][]string{
		"CurrentTime":      {currTime.Format(time.RFC3339)},
		"EpochTime":        {strconv.FormatInt(currTime.Unix(), 10)},
		"SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"SourceIp":         {handlers.GetSourceIPRaw(r)},
		"UserAgent":        {r.UserAgent()},
		"Referer":          {r.Referer()},
		"principaltype":    {principalType},
		"userid":           {username},
		"username":         {username},
		"signatureversion": {signatureVersion},
		"authType":         {authtype},
	}

	// Null conditions distinguish an absent key from a present key with an
	// empty value. Only expose s3:versionid when the request names a version.
	if vid != "" {
		args["versionid"] = []string{vid}
	}

	if lc != "" {
		args["LocationConstraint"] = []string{lc}
	}
	if storageClass, ok := getRequestHeaderOrQueryValue(r, xhttp.AmzStorageClass); ok {
		args[strings.ToLower(xhttp.AmzStorageClass)] = []string{storageClass}
	}

	cloneHeader := r.Header.Clone()

	// s3:signatureAge is derived from the presigned X-Amz-Date rather than from
	// anything the verifier writes back: PutObject and UploadPart authorize
	// before they verify the signature, so a post-verification value is not yet
	// available on the first evaluation. The date is bound by the signature
	// (doesPresignedSignatureMatch rebuilds and compares it), so a forged date
	// only changes the authorization outcome of a request that then fails
	// verification. A date that does not parse leaves the key absent; the
	// verifier rejects the request as ErrMalformedPresignedDate.
	if authType == authTypePresigned {
		if signedDate, err := time.Parse(iso8601Format, r.Form.Get(xhttp.AmzDate)); err == nil {
			args["signatureAge"] = []string{strconv.FormatInt(currTime.Sub(signedDate).Milliseconds(), 10)}
		}
	}

	// s3:x-amz-content-sha256 must name the payload hash the request is actually
	// verified and enforced against, and only one such value. Presence of the
	// header controls whether the key exists at all (AWS documents that the
	// query-string form does not populate it), but the value comes from the same
	// selection getContentSha256Cksum makes for verification: the presigned query
	// value takes precedence over the header, and a repeated header contributes
	// only its first value. Exposing every raw header value instead let a
	// request satisfy a policy with a value the verifier never checked.
	if _, ok := cloneHeader[xhttp.AmzContentSha256]; ok {
		args[xhttp.AmzContentSha256] = []string{getContentSha256Cksum(r, serviceS3)}
		cloneHeader.Del(xhttp.AmzContentSha256)
	}

	userTags := cloneHeader.Get(xhttp.AmzObjectTagging)
	if requestTags != nil {
		userTags = *requestTags
	}
	if userTags != "" {
		tag, _ := tags.ParseObjectTags(userTags)
		if tag != nil {
			tagMap := tag.ToMap()
			keys := make([]string, 0, len(tagMap))
			for k, v := range tagMap {
				args[pathJoin("RequestObjectTag", k)] = []string{v}
				keys = append(keys, k)
			}
			args["RequestObjectTagKeys"] = keys
		}
	}
	if existingTags != "" {
		tag, _ := tags.ParseObjectTags(existingTags)
		if tag != nil {
			for k, v := range tag.ToMap() {
				args[pathJoin("ExistingObjectTag", k)] = []string{v}
			}
		}
	}

	for _, objLock := range []string{
		xhttp.AmzObjectLockMode,
		xhttp.AmzObjectLockLegalHold,
		xhttp.AmzObjectLockRetainUntilDate,
	} {
		if values, ok := cloneHeader[objLock]; ok {
			args[strings.TrimPrefix(objLock, "X-Amz-")] = values
		}
		cloneHeader.Del(objLock)
	}

	// The two loops below fold raw header and query values into the same map
	// the server just filled in. Anything they add is indistinguishable, to a
	// condition, from a value the server derived - and they merge by appending,
	// so a supplied entry sits alongside the real one rather than replacing it.
	// The source check keeps headers and query parameters in their actual roles;
	// isInternalConditionKey keeps both apart from server-derived values.
	for key, values := range cloneHeader {
		if strings.EqualFold(key, xhttp.AmzObjectTagging) || strings.EqualFold(key, xhttp.AmzStorageClass) {
			continue
		}
		if !acceptsConditionValueSource(key, conditionValueFromHeader) {
			continue
		}
		if isInternalConditionKey(key) {
			continue
		}
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	cloneURLValues := make(url.Values, len(r.Form))
	maps.Copy(cloneURLValues, r.Form)

	for key, values := range cloneURLValues {
		if strings.EqualFold(key, xhttp.AmzObjectTagging) || strings.EqualFold(key, xhttp.AmzStorageClass) {
			continue
		}
		if !acceptsConditionValueSource(key, conditionValueFromQuery) {
			continue
		}
		if isInternalConditionKey(key) {
			continue
		}
		if existingValues, found := args[key]; found {
			args[key] = append(existingValues, values...)
		} else {
			args[key] = values
		}
	}

	// JWT specific values
	//
	// Add all string claims
	for k, v := range claims {
		vStr, ok := v.(string)
		if ok {
			// Trim any LDAP specific prefix
			args[strings.ToLower(strings.TrimPrefix(k, "ldap"))] = []string{vStr}
		}
	}

	// Add groups claim which could be a list. This will ensure that the claim
	// `jwt:groups` works.
	if grpsVal, ok := claims["groups"]; ok {
		if grpsIs, ok := grpsVal.([]any); ok {
			grps := []string{}
			for _, gI := range grpsIs {
				if g, ok := gI.(string); ok {
					grps = append(grps, g)
				}
			}
			if len(grps) > 0 {
				args["groups"] = grps
			}
		}
	}

	// if not claim groups are available use the one with auth.Credentials
	if _, ok := args["groups"]; !ok {
		if len(groups) > 0 {
			args["groups"] = groups
		}
	}

	return args
}

// PolicyToBucketAccessPolicy converts a MinIO policy into a minio-go policy data structure.
func PolicyToBucketAccessPolicy(bucketPolicy *policy.BucketPolicy) (*miniogopolicy.BucketAccessPolicy, error) {
	// Return empty BucketAccessPolicy for empty bucket policy.
	if bucketPolicy == nil {
		return &miniogopolicy.BucketAccessPolicy{Version: policy.DefaultVersion}, nil
	}

	data, err := json.Marshal(bucketPolicy)
	if err != nil {
		// This should not happen because bucketPolicy is valid to convert to JSON data.
		return nil, err
	}

	var policyInfo miniogopolicy.BucketAccessPolicy
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if err = json.Unmarshal(data, &policyInfo); err != nil {
		// This should not happen because data is valid to JSON data.
		return nil, err
	}

	return &policyInfo, nil
}

// BucketAccessPolicyToPolicy - converts minio-go/policy.BucketAccessPolicy to policy.BucketPolicy.
func BucketAccessPolicyToPolicy(policyInfo *miniogopolicy.BucketAccessPolicy) (*policy.BucketPolicy, error) {
	data, err := json.Marshal(policyInfo)
	if err != nil {
		// This should not happen because policyInfo is valid to convert to JSON data.
		return nil, err
	}

	var bucketPolicy policy.BucketPolicy
	json := jsoniter.ConfigCompatibleWithStandardLibrary
	if err = json.Unmarshal(data, &bucketPolicy); err != nil {
		// This should not happen because data is valid to JSON data.
		return nil, err
	}

	return &bucketPolicy, nil
}
