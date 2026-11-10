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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/minio/internal/arn"
	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
	"github.com/pgsty/silo-pkg/v3/policy/condition"
)

// objectReadFault takes the first n drives of the set that holds object
// offline for the metadata reads of that object only, so that IAM and bucket
// metadata stay readable. It returns a function that restores the drives.
func objectReadFault(z *erasureServerPools, bucket, object string, n int) func() {
	pool := z.serverPools[0]
	setIndex := pool.getHashedSetIndex(object)
	pool.erasureDisksMu.Lock()
	defer pool.erasureDisksMu.Unlock()
	previous := pool.erasureDisks[setIndex]
	disks := append([]StorageAPI(nil), previous...)
	for i := range n {
		disks[i] = consistencyReadFaultDisk{StorageAPI: disks[i], bucket: bucket, object: object}
	}
	pool.erasureDisks[setIndex] = disks
	return func() {
		pool.erasureDisksMu.Lock()
		pool.erasureDisks[setIndex] = previous
		pool.erasureDisksMu.Unlock()
	}
}

// A caller allowed to read an object only through s3:ExistingObjectTag must
// get the storage error, which clients retry, and not AccessDenied, when the
// object's tags cannot be read because read quorum is lost. A caller that no
// tags would let through must still get AccessDenied, and nothing changes
// while the tags can be read.
func TestExistingObjectTagAuthReadQuorumLost(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	obj, dirs, err := prepareErasure16(ctx)
	if err != nil {
		t.Fatal(err)
	}
	z := obj.(*erasureServerPools)
	previous := newObjectLayerFn()
	setObjectLayer(z)
	defer func() {
		z.Shutdown(context.Background())
		removeRoots(dirs)
		setObjectLayer(previous)
	}()
	bucket, router, err := initAPIHandlerTest(ctx, z, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}

	statement := func(effect, resource, conditions string) string {
		st := fmt.Sprintf(`{"Effect": %q, "Action": ["s3:GetObject", "s3:PutObjectTagging"], "Resource": ["arn:aws:s3:::%s/%s"]`,
			effect, bucket, resource)
		if conditions != "" {
			st += `, "Condition": ` + conditions
		}
		return st + "}"
	}
	tagStatement := func(effect, resource, value string) string {
		return statement(effect, resource, fmt.Sprintf(`{"StringEquals": {"s3:ExistingObjectTag/k": %q}}`, value))
	}
	newUser := func(statements ...string) auth.Credentials {
		return newDeleteAuthzPolicyUser(t, "", bucket, "["+strings.Join(statements, ",")+"]")
	}
	newServiceAccount := func(parent auth.Credentials, statements string) auth.Credentials {
		sessionPolicy, err := policy.ParseConfig(strings.NewReader(`{"Version": "2012-10-17", "Statement": [` + statements + `]}`))
		if err != nil {
			t.Fatal(err)
		}
		cred, _, err := globalIAMSys.NewServiceAccount(ctx, parent.AccessKey, nil, newServiceAccountOpts{sessionPolicy: sessionPolicy})
		if err != nil {
			t.Fatal(err)
		}
		return cred
	}
	newTempUser := func(parent auth.Credentials, statements string) auth.Credentials {
		session := `{"Version": "2012-10-17", "Statement": [` + statements + `]}`
		secret, err := getTokenSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		cred, err := auth.GetNewCredentialsWithMetadata(map[string]any{
			parentClaim: parent.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(),
			policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(session)),
		}, secret)
		if err != nil {
			t.Fatal(err)
		}
		cred.ParentUser = parent.AccessKey
		if _, err := globalIAMSys.SetTempUser(ctx, cred.AccessKey, cred, ""); err != nil {
			t.Fatal(err)
		}
		return cred
	}
	// An unrelated cached policy must not consume the candidate limit. The
	// target user's policy is created below and sorts after this policy.
	fillerStatements := make([]string, 0, maxExistingTagCandidates)
	for i := range maxExistingTagCandidates {
		fillerStatements = append(fillerStatements, statement("Allow", "*",
			fmt.Sprintf(`{"StringEquals": {"s3:ExistingObjectTag/fill%02d": "v"}}`, i)))
	}
	fillerPolicy, err := policy.ParseConfig(strings.NewReader(`{"Version": "2012-10-17", "Statement": [` + strings.Join(fillerStatements, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	fillerPolicyName := "000-unread-tags-filler-" + mustGetUUID()
	if _, err = globalIAMSys.SetPolicy(ctx, fillerPolicyName, *fillerPolicy); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := globalIAMSys.DeletePolicy(ctx, fillerPolicyName, false); err != nil {
			t.Logf("delete filler policy: %v", err)
		}
	}()

	type user struct {
		name  string
		creds auth.Credentials
		// The status with the object's tags readable and with read quorum
		// lost: 200 and 503 for a caller that some tags let through, 403
		// and 403 for a caller that none do.
		healthy, quorumLost int
	}
	allowedByTags := func(name string, creds auth.Credentials) user {
		return user{name, creds, http.StatusOK, http.StatusServiceUnavailable}
	}
	deniedByAnyTags := func(name string, creds auth.Credentials) user {
		return user{name, creds, http.StatusForbidden, http.StatusForbidden}
	}
	// Each case below that tests a tag key of its own uses a key no other
	// policy asks for.
	ownerCondition := `{"StringEquals": {"s3:ExistingObjectTag/owner": "${aws:username}"}}`
	owner := newUser(statement("Allow", "*", ownerCondition))
	users := []user{
		// Allowed only while the object carries k=v.
		allowedByTags("tagged", newUser(tagStatement("Allow", "*", "v"))),
		// Allowed while the object carries a tag np, whatever its value.
		allowedByTags("nullFalse", newUser(statement("Allow", "*", `{"Null": {"s3:ExistingObjectTag/np": "false"}}`))),
		// Allowed while a tag ne is there and is not w.
		allowedByTags("notEquals", newUser(statement("Allow", "*",
			`{"Null": {"s3:ExistingObjectTag/ne": "false"}, "StringNotEquals": {"s3:ExistingObjectTag/ne": "w"}}`))),
		// Allowed while every value of tag fa differs from w; that needs a tag fa.
		allowedByTags("forAllNotEquals", newUser(statement("Allow", "*", `{"ForAllValues:StringNotEquals": {"s3:ExistingObjectTag/fa": "w"}}`))),
		// Allowed while the object is tagged with the caller's name.
		allowedByTags("owner", owner),
		// Allowed, but denied unless the object carries du=1.
		allowedByTags("denyUnlessTagged", newUser(statement("Allow", "*", ""),
			statement("Deny", "*", `{"StringNotEquals": {"s3:ExistingObjectTag/du": "1"}}`))),
		// A service account whose parent asks for k=v and whose own policy
		// asks for j=w: only an object carrying both lets it through.
		allowedByTags("serviceAccount", newServiceAccount(newUser(tagStatement("Allow", "*", "v")),
			statement("Allow", "*", `{"StringEquals": {"s3:ExistingObjectTag/j": "w"}}`))),
		allowedByTags("temporary", newTempUser(newUser(tagStatement("Allow", "*", "v")),
			statement("Allow", "*", `{"StringEquals": {"s3:ExistingObjectTag/j": "w"}}`))),
		allowedByTags("rootTemporary", newTempUser(globalActiveCred, tagStatement("Allow", "*", "v"))),
		allowedByTags("rootServiceAccount", newServiceAccount(globalActiveCred, tagStatement("Allow", "*", "v"))),
		// The effective policy must be selected before applying the candidate
		// limit; the unrelated cached policy above has 64 other tag statements.
		allowedByTags("unrelatedPolicies", newUser(statement("Allow", "*",
			`{"StringEquals": {"s3:ExistingObjectTag/target": "ok"}}`))),
		// An alternative allowed value must survive a Deny that excludes the
		// first value. With unread tags, k=v is the only valid candidate.
		allowedByTags("alternativeAllowedValue", newUser(
			statement("Allow", "*", `{"StringEquals": {"s3:ExistingObjectTag/k": ["a", "v"]}}`),
			tagStatement("Deny", "*", "a"))),
		allowedByTags("alternativeValuesAcrossKeys", newUser(
			statement("Allow", "*", `{"StringEquals": {"s3:ExistingObjectTag/k": ["a", "v"], "s3:ExistingObjectTag/j": ["b", "w"]}}`),
			tagStatement("Deny", "*", "a"),
			statement("Deny", "*", `{"StringEquals": {"s3:ExistingObjectTag/j": "b"}}`))),
		// Both Deny statements must be avoided. The first candidate (k="")
		// avoids the Null Deny but still matches the second Deny.
		allowedByTags("multipleDenies", newUser(statement("Allow", "*", ""),
			statement("Deny", "*", `{"Null": {"s3:ExistingObjectTag/k": "true"}}`),
			tagStatement("Deny", "*", ""))),
		// The Deny can be avoided by k=v OR j=w. Only j=w is compatible
		// with this Allow, so stopping at the first Deny key loses it.
		{
			"alternativeDenyKey", newUser(tagStatement("Allow", "*", "a"),
				statement("Deny", "*", `{"StringNotEquals": {"s3:ExistingObjectTag/k": "v", "s3:ExistingObjectTag/j": "w"}}`)),
			http.StatusForbidden, http.StatusServiceUnavailable,
		},

		// Allowed only for k=w: the decision still depends on the tags.
		{"otherValue", newUser(tagStatement("Allow", "*", "w")), http.StatusForbidden, http.StatusServiceUnavailable},

		// Allowed for k=v under another prefix only.
		deniedByAnyTags("otherPrefix", newUser(tagStatement("Allow", "other/*", "v"))),
		// Allowed and denied for k=v alike.
		deniedByAnyTags("allowDeny", newUser(tagStatement("Allow", "*", "v"), tagStatement("Deny", "*", "v"))),
		// Allowed only without a tag nc that is 1.
		deniedByAnyTags("nullConflict", newUser(statement("Allow", "*",
			`{"Null": {"s3:ExistingObjectTag/nc": "true"}, "StringEquals": {"s3:ExistingObjectTag/nc": "1"}}`))),
		// Tagged with the caller's name, under another prefix only.
		deniedByAnyTags("ownerPrefix", newUser(statement("Allow", "other/*", ownerCondition))),
		// Denied unless the object carries db=1, and denied if it does.
		deniedByAnyTags("denyBoth", newUser(statement("Allow", "*", ""),
			statement("Deny", "*", `{"StringNotEquals": {"s3:ExistingObjectTag/db": "1"}}`),
			statement("Deny", "*", `{"StringEquals": {"s3:ExistingObjectTag/db": "1"}}`))),
		// The parent asks for k=v and the service account for k=x.
		deniedByAnyTags("serviceAccountConflict", newServiceAccount(newUser(tagStatement("Allow", "*", "v")),
			tagStatement("Allow", "*", "x"))),
	}

	const object, missing = "tagged", "missing"
	if _, err := z.PutObject(ctx, bucket, object, mustGetPutObjReader(t, bytes.NewReader([]byte("data")), 4, "", ""),
		ObjectOptions{UserDefined: map[string]string{xhttp.AmzObjectTagging: "k=v&j=w&np=1&ne=1&fa=1&du=1&target=ok&owner=" + owner.AccessKey}}); err != nil {
		t.Fatal(err)
	}
	// Anonymous reads are allowed by the bucket policy while the object carries k=v.
	if _, err := globalBucketMetadataSys.Update(ctx, bucket, bucketPolicyConfig, []byte(`{"Version": "2012-10-17", "Statement": [
  {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::`+bucket+`/*"],
   "Condition": {"StringEquals": {"s3:ExistingObjectTag/k": "v"}}}]}`)); err != nil {
		t.Fatal(err)
	}

	type request struct {
		name           string
		method, target string
		header         map[string]string
		body           []byte
	}
	objectURL := getGetObjectURL("", bucket, object)
	get := request{"GET", http.MethodGet, objectURL, nil, nil}
	head := request{"HEAD", http.MethodHead, objectURL, nil, nil}
	taggingURL := makeTestTargetURL("", bucket, object, url.Values{"tagging": []string{""}})
	taggingBody := []byte(`<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`)
	putTagging := request{"PutObjectTagging", http.MethodPut, taggingURL, nil, taggingBody}
	check := func(stage string, creds auth.Credentials, name string, req request, want int) {
		t.Helper()
		var rec *httptest.ResponseRecorder
		if creds.AccessKey == "" {
			anonymous, err := newTestRequest(req.method, req.target, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, anonymous)
		} else {
			var body io.ReadSeeker
			if req.body != nil {
				body = bytes.NewReader(req.body)
			}
			header := make(map[string]string)
			for k, v := range req.header {
				header[k] = v
			}
			if creds.IsTemp() {
				header[xhttp.AmzSecurityToken] = creds.SessionToken
			}
			signed, err := newTestSignedRequestV4(req.method, req.target, int64(len(req.body)), body, creds.AccessKey, creds.SecretKey, header)
			if err != nil {
				t.Fatal(err)
			}
			rec = httptest.NewRecorder()
			router.ServeHTTP(rec, signed)
		}
		if rec.Code != want {
			var apiErr APIErrorResponse
			_ = xml.Unmarshal(rec.Body.Bytes(), &apiErr)
			t.Errorf("%s: %s by %s: status %d %s, want %d", stage, req.name, name, rec.Code, apiErr.Code, want)
		}
	}

	var anonymous auth.Credentials
	for _, u := range users {
		check("healthy", u.creds, u.name, get, u.healthy)
	}
	check("healthy", anonymous, "anonymous", get, http.StatusOK)
	// The tags were read and allow the request: the range error is the answer.
	check("healthy", users[0].creds, users[0].name,
		request{"GET bytes=100-200", http.MethodGet, objectURL, map[string]string{xhttp.Range: "bytes=100-200"}, nil},
		http.StatusRequestedRangeNotSatisfiable)
	// Without an object there are no tags: AccessDenied, as before.
	missingURL := getGetObjectURL("", bucket, missing)
	check("missing key", users[0].creds, users[0].name, request{"GET", http.MethodGet, missingURL, nil, nil}, http.StatusForbidden)
	check("missing key", users[0].creds, users[0].name, request{"HEAD", http.MethodHead, missingURL, nil, nil}, http.StatusForbidden)

	defer objectReadFault(z, bucket, object, 10)()
	if _, err := z.GetObjectInfo(ctx, bucket, object, ObjectOptions{}); !isErrReadQuorum(err) {
		t.Fatalf("GetObjectInfo with 10 of 16 drives failing: %v, want InsufficientReadQuorum", err)
	}
	for _, req := range []request{get, head, putTagging} {
		for _, u := range users {
			check("read quorum lost", u.creds, u.name, req, u.quorumLost)
		}
	}
	check("read quorum lost", anonymous, "anonymous", get, http.StatusServiceUnavailable)
	check("read quorum lost", anonymous, "anonymous", head, http.StatusServiceUnavailable)
}

func TestExistingObjectTagsFor(t *testing.T) {
	values := map[string][]string{"username": {"alice"}, "sub": {"u1"}}
	for _, tc := range []struct {
		effect     policy.Effect
		conditions string
		want       string // the tags to set, encoded as in x-amz-tagging
		ok         bool   // false: no tags for this statement
	}{
		{policy.Allow, `{"StringEquals": {"s3:ExistingObjectTag/k": "v"}}`, "k=v", true},
		{policy.Allow, `{"StringEqualsIgnoreCase": {"s3:ExistingObjectTag/k": "V"}, "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}`, "k=V", true},
		{policy.Allow, `{"ForAnyValue:StringEquals": {"s3:ExistingObjectTag/k": ["b", "a"]}}`, "k=a", true},
		{policy.Allow, `{"StringLike": {"s3:ExistingObjectTag/k": "a?c*"}}`, "k=a_c", true},
		{policy.Allow, `{"StringEquals": {"s3:ExistingObjectTag/b": "2", "s3:ExistingObjectTag/a": "1"}}`, "a=1&b=2", true},
		// Passed without the tag.
		{policy.Allow, `{"StringNotEquals": {"s3:ExistingObjectTag/k": "v"}}`, "", true},
		{policy.Allow, `{"Null": {"s3:ExistingObjectTag/k": "true"}}`, "", true},
		// Null "false" asks for the tag, with any value.
		{policy.Allow, `{"Null": {"s3:ExistingObjectTag/k": "false"}}`, "k=", true},
		{policy.Allow, `{"Null": {"s3:ExistingObjectTag/k": "false"}, "StringNotEquals": {"s3:ExistingObjectTag/k": ["", "w"]}}`, "k=_", true},
		{policy.Allow, `{"Null": {"s3:ExistingObjectTag/k": "false"}, "StringNotLike": {"s3:ExistingObjectTag/k": "*w"}}`, "k=", true},
		{policy.Allow, `{"ForAllValues:StringNotEquals": {"s3:ExistingObjectTag/k": "w"}}`, "k=", true},
		{policy.Allow, `{"Null": {"s3:ExistingObjectTag/k": "true"}, "StringEquals": {"s3:ExistingObjectTag/k": "v"}}`, "", false},
		// Policy variables take the values of the request.
		{policy.Allow, `{"StringEquals": {"s3:ExistingObjectTag/owner": "${aws:username}"}}`, "owner=alice", true},
		{policy.Allow, `{"StringLike": {"s3:ExistingObjectTag/owner": "${jwt:sub}-*"}}`, "owner=u1-", true},
		{policy.Allow, `{"StringEquals": {"s3:ExistingObjectTag/owner": "${ldap:user}"}}`, "", false},
		// A Deny is kept from matching.
		{policy.Deny, `{"StringNotEquals": {"s3:ExistingObjectTag/k": "v"}}`, "k=v", true},
		{policy.Deny, `{"Null": {"s3:ExistingObjectTag/k": "true"}}`, "k=", true},
		{policy.Deny, `{"StringEquals": {"s3:ExistingObjectTag/k": "v"}}`, "", true},
		{policy.Deny, `{"StringEquals": {"s3:prefix": "v"}}`, "", false},
		// No tag tests.
		{policy.Allow, `{"StringEquals": {"s3:prefix": "v"}}`, "", false},
		{policy.Allow, "", "", false},
	} {
		var conditions condition.Functions // nil: a statement without a Condition
		if tc.conditions != "" {
			if err := json.Unmarshal([]byte(tc.conditions), &conditions); err != nil {
				t.Fatalf("%s: %v", tc.conditions, err)
			}
		}
		candidates := existingObjectTagsCandidatesFor(tc.effect, conditions, values)
		ok := len(candidates) > 0
		got := ""
		if ok {
			encoded, err := tags.MapToObjectTags(candidates[0])
			if err != nil {
				t.Fatalf("%s: %v", tc.conditions, err)
			}
			got = encoded.String()
		}
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s %s: got %q %v, want %q %v", tc.effect, tc.conditions, got, ok, tc.want, tc.ok)
		}
	}
}

// Group-only and external identities need mapping lookups that normally
// fall back to storage. Candidate collection must stay within the cache even
// for those identities, while still finding their group/claim/role policy.
func TestUnreadTagPolicySetsCacheOnly(t *testing.T) {
	ctx, sys, _ := prepareIAMRevisionFixture(t)
	const policyName = "unread-tag-policy"
	batchAuthzPolicy(ctx, t, sys, policyName, `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::bucket/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/k":"v"}}}`)
	member := iamAdminUser(ctx, t, sys, "unread-group-member", "")
	_, err := sys.AddUsersToGroup(ctx, "unread-group", []string{member.AccessKey})
	mustIAM(t, err)
	_, err = sys.PolicyDBSet(ctx, "unread-group", policyName, regUser, true)
	mustIAM(t, err)
	role, err := arn.NewIAMRoleARN("unread-role", "")
	mustIAM(t, err)
	sys.rolesMap = map[arn.ARN]string{role: policyName}
	claimUser := auth.Credentials{
		AccessKey: "unread-sts", ParentUser: "external-parent", SessionToken: "token",
		Expiration: UTCNow().Add(time.Hour), Claims: map[string]any{iamPolicyClaimNameOpenID(): policyName},
	}
	roleUser := claimUser
	roleUser.Claims = map[string]any{roleArnClaim: role.String()}
	original := sys.store.IAMStorageAPI
	defer func() { sys.store.IAMStorageAPI = original }()
	for _, tc := range []struct {
		name string
		cred auth.Credentials
	}{
		{"group", member},
		{"claims", claimUser},
		{"role", roleUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.cred.AccessKey
			if tc.cred.ParentUser != "" {
				name = tc.cred.ParentUser
			}
			probe := &batchBlockedIAMStore{
				IAMStorageAPI: original, mapping: name, doc: policyName,
				started: make(chan struct{}), release: make(chan struct{}),
			}
			close(probe.release) // report an accidental read without blocking the test
			sys.store.IAMStorageAPI = probe
			sets := sys.unreadTagPolicySets(tc.cred)
			select {
			case <-probe.started:
				t.Error("candidate collection attempted a storage read")
			default:
			}
			if len(sets) != 1 || len(sets[0]) != 1 {
				t.Fatalf("expected the cached policy through %s, got %v", tc.name, sets)
			}
		})
	}
}
