// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/auth"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

type trailerFaultReader struct {
	err   error
	reads int
}

func (r *trailerFaultReader) Read([]byte) (int, error) {
	r.reads++
	if r.reads > 2 {
		return 0, io.EOF // Bound a broken parser rather than exhausting test memory.
	}
	return 0, r.err
}

func TestTrailerReadPreservesConnectionErrors(t *testing.T) {
	for _, signed := range []bool{false, true} {
		for _, prefix := range []string{"", "checksum:value\r", "checksum:value\r\n", "checksum:value\r\nx-amz-trailer-signature:a\r"} {
			if !signed && strings.Contains(prefix, "\r\n") {
				continue
			}
			t.Run(fmt.Sprintf("signed=%t/prefix=%q", signed, prefix), func(t *testing.T) {
				failure := errors.New("injected connection reset")
				fault := &trailerFaultReader{err: failure}
				reader := bufio.NewReader(io.MultiReader(strings.NewReader(prefix), fault))
				var err error
				if signed {
					err = (&s3ChunkedReader{reader: reader}).readTrailers()
				} else {
					err = (&s3UnsignedChunkedReader{reader: reader}).readTrailers()
				}
				if !errors.Is(err, failure) || fault.reads != 1 {
					t.Fatalf("got err=%v reads=%d, want original connection error after one read", err, fault.reads)
				}
			})
		}
	}
}

func TestLatestMetadataListingDoesNotRequireVersionGrants(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
			_, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
			mustIAM(t, err)
			_, err = obj.PutObject(t.Context(), bucket, "latest", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{
				Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "classification=public"},
			})
			mustIAM(t, err)
			cred := createTestPolicyUser(t, fmt.Sprintf(`{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:ListBucket","s3:ListBucketVersions"],"Resource":["arn:aws:s3:::%s"]},
				{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectTagging"],"Resource":["arn:aws:s3:::%s/*"]},
				{"Effect":"Deny","Action":["s3:GetObjectVersion","s3:GetObjectVersionTagging"],"Resource":["arn:aws:s3:::%s/*"]}]}`, bucket, bucket, bucket))
			for _, query := range []string{"list-type=2", "versions="} {
				req, err := newTestSignedRequestV4(http.MethodGet, "/"+bucket+"?"+query+"&metadata=true&prefix=latest", 0, nil, cred.AccessKey, cred.SecretKey, nil)
				mustIAM(t, err)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				wantTags := query == "list-type=2"
				if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "classification=public") != wantTags {
					t.Fatalf("%s %s: status=%d body=%s, want tags=%t", backend, query, rec.Code, rec.Body.String(), wantTags)
				}
			}
		},
	})
}

func TestVersionDeniesSurviveInheritedAndSessionPolicies(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, _ auth.Credentials, t *testing.T) {
		ctx := t.Context()
		_, err := globalBucketMetadataSys.Update(ctx, bucket, bucketVersioningConfig, enabledBucketVersioningConfig)
		mustIAM(t, err)
		oi, err := obj.PutObject(ctx, bucket, "item", mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{
			Versioned: true, UserDefined: map[string]string{xhttp.AmzObjectTagging: "classification=public"},
		})
		mustIAM(t, err)
		allow := fmt.Sprintf(`{"Effect":"Allow","Action":["s3:GetObject","s3:GetObjectTagging"],"Resource":["arn:aws:s3:::%s/*"]}`, bucket)
		deny := fmt.Sprintf(`{"Effect":"Deny","Action":["s3:GetObjectVersion","s3:GetObjectVersionTagging"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:versionid":%q}}}`, bucket, oi.VersionID)
		document := func(statements string) string {
			return `{"Version":"2012-10-17","Statement":[` + statements + `]}`
		}
		baseOnly := createTestPolicyUser(t, document(allow))
		denied := createTestPolicyUser(t, document(allow+","+deny))
		inherited, _, err := globalIAMSys.NewServiceAccount(ctx, denied.AccessKey, nil, newServiceAccountOpts{})
		mustIAM(t, err)
		session, err := policy.ParseConfig(strings.NewReader(document(allow + "," + deny)))
		mustIAM(t, err)
		inline, _, err := globalIAMSys.NewServiceAccount(ctx, globalActiveCred.AccessKey, nil, newServiceAccountOpts{sessionPolicy: session})
		mustIAM(t, err)
		secret, err := getTokenSigningKey()
		mustIAM(t, err)
		temporary, err := auth.GetNewCredentialsWithMetadata(map[string]any{
			parentClaim: globalActiveCred.AccessKey, "exp": UTCNow().Add(time.Hour).Unix(),
			policy.SessionPolicyName: base64.StdEncoding.EncodeToString([]byte(document(allow + "," + deny))),
		}, secret)
		mustIAM(t, err)
		temporary.ParentUser = globalActiveCred.AccessKey
		_, err = globalIAMSys.SetTempUser(ctx, temporary.AccessKey, temporary, "")
		mustIAM(t, err)
		groupUser := createTestPolicyUser(t, document(allow))
		groupPolicy, err := policy.ParseConfig(strings.NewReader(document(deny)))
		mustIAM(t, err)
		_, err = globalIAMSys.SetPolicy(ctx, "version-deny", *groupPolicy)
		mustIAM(t, err)
		_, err = globalIAMSys.AddUsersToGroup(ctx, "version-deny-group", []string{groupUser.AccessKey})
		mustIAM(t, err)
		_, err = globalIAMSys.PolicyDBSet(ctx, "version-deny-group", "version-deny", regUser, true)
		mustIAM(t, err)
		for _, tc := range []struct {
			name string
			cred auth.Credentials
			deny bool
		}{
			{"legacy-base-grant", baseOnly, false},
			{"regular", denied, true},
			{"inherited-service-account", inherited, true},
			{"root-service-account-session", inline, true},
			{"root-sts-session", temporary, true},
			{"group", groupUser, true},
		} {
			for _, query := range []string{"", "?versionId=" + oi.VersionID, "?tagging=&versionId=" + oi.VersionID} {
				headers := map[string]string{xhttp.AmzTagDirective: "ACCESS"}
				if tc.cred.IsTemp() {
					headers[xhttp.AmzSecurityToken] = tc.cred.SessionToken
				}
				req, err := newTestSignedRequestV4(http.MethodGet, "/"+bucket+"/item"+query, 0, nil, tc.cred.AccessKey, tc.cred.SecretKey, headers)
				mustIAM(t, err)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				want := http.StatusOK
				if tc.deny && query != "" {
					want = http.StatusForbidden
				}
				if rec.Code != want {
					t.Errorf("%s %s %s: got %d %s, want %d", backend, tc.name, query, rec.Code, rec.Body.String(), want)
				}
			}
		}
	}})
}
