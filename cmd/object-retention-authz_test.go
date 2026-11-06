// Copyright (c) 2015-2026 MinIO, Inc.
// Copyright (c) 2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/amztime"
	"github.com/minio/minio/internal/auth"
	objectlock "github.com/minio/minio/internal/bucket/object/lock"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func retentionAuthzRequest(t *testing.T, router http.Handler, creds auth.Credentials, method, target string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.ReadSeeker
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := newTestSignedRequestV4(method, target, int64(len(body)), rd, creds.AccessKey, creds.SecretKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func retentionBody(mode string, until time.Time) []byte {
	if mode == "" {
		return []byte(`<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></Retention>`)
	}
	return fmt.Appendf(nil, `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
		mode, until.UTC().Format(time.RFC3339))
}

func putRetention(t *testing.T, router http.Handler, cred auth.Credentials, bucket, key, vid, mode string, until time.Time, bypass bool) int {
	t.Helper()
	body := retentionBody(mode, until)
	sum := md5.Sum(body)
	headers := map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])}
	if bypass {
		headers[objectlock.AmzObjectLockBypassRetGovernance] = "true"
	}
	rec := retentionAuthzRequest(t, router, cred, http.MethodPut,
		makeTestTargetURL("", bucket, key, url.Values{"retention": {""}, "versionId": {vid}}), body, headers)
	return rec.Code
}

func newRetentionPolicyUser(t *testing.T, instanceType, policyJSON string) auth.Credentials {
	t.Helper()
	ctx := t.Context()
	accessKey, secretKey, err := auth.GenerateCredentials()
	if err != nil {
		t.Fatalf("%s: generate credentials: %v", instanceType, err)
	}
	creds := auth.Credentials{AccessKey: accessKey, SecretKey: secretKey}
	if _, err = globalIAMSys.CreateUser(ctx, creds.AccessKey, madmin.AddOrUpdateUserReq{
		SecretKey: creds.SecretKey,
		Status:    madmin.AccountEnabled,
	}); err != nil {
		t.Fatalf("%s: create user: %v", instanceType, err)
	}
	parsed, err := policy.ParseConfig(strings.NewReader(policyJSON))
	if err != nil {
		t.Fatalf("%s: parse policy: %v", instanceType, err)
	}
	policyName := "retention-authz-" + mustGetUUID()
	if _, err = globalIAMSys.SetPolicy(ctx, policyName, *parsed); err != nil {
		t.Fatalf("%s: install policy: %v", instanceType, err)
	}
	if _, err = globalIAMSys.PolicyDBSet(ctx, creds.AccessKey, policyName, regUser, false); err != nil {
		t.Fatalf("%s: attach policy: %v", instanceType, err)
	}
	return creds
}

// TestAPIPutObjectRetentionAuthorization covers SN-2026-015: the governance
// bypass header is intent only; s3:PutObjectRetention is always required and
// weakening unexpired GOVERNANCE also requires s3:BypassGovernanceRetention.
func TestAPIPutObjectRetentionAuthorization(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:          t,
		objAPITest: testAPIPutObjectRetentionAuthorization,
	})
}

func testAPIPutObjectRetentionAuthorization(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	enableBucketObjectLock(t, bucket)

	noRet := newObjectAttributesAuthzUser(t, instanceType, bucket, `"s3:GetObject"`)
	retOnly := newObjectAttributesAuthzUser(t, instanceType, bucket, `"s3:PutObjectRetention"`)
	retBypass := newObjectAttributesAuthzUser(t, instanceType, bucket, `"s3:PutObjectRetention","s3:BypassGovernanceRetention"`)
	bypassOnly := newObjectAttributesAuthzUser(t, instanceType, bucket, `"s3:BypassGovernanceRetention"`)
	condDenyShort := newRetentionPolicyUser(t, instanceType, `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3:PutObjectRetention", "s3:BypassGovernanceRetention"],
				"Resource": ["arn:aws:s3:::`+bucket+`/*"]
			},
			{
				"Effect": "Deny",
				"Action": ["s3:PutObjectRetention"],
				"Resource": ["arn:aws:s3:::`+bucket+`/*"],
				"Condition": {"NumericLessThan": {"s3:object-lock-remaining-retention-days": "60"}}
			}
		]
	}`)
	explicitDenyBypass := newRetentionPolicyUser(t, instanceType, `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": ["s3:*"],
				"Resource": ["arn:aws:s3:::`+bucket+`/*"]
			},
			{
				"Effect": "Deny",
				"Action": ["s3:BypassGovernanceRetention"],
				"Resource": ["arn:aws:s3:::`+bucket+`/*"]
			}
		]
	}`)

	far := UTCNow().Add(365 * 24 * time.Hour).Truncate(time.Second)
	nearer := UTCNow().Add(30 * 24 * time.Hour).Truncate(time.Second)
	farther := far.Add(24 * time.Hour)

	put := func(t *testing.T, object, mode string) string {
		t.Helper()
		payload := []byte("retention authorization")
		opts := ObjectOptions{Versioned: true, UserDefined: map[string]string{}}
		if mode != "" {
			opts.UserDefined[strings.ToLower(xhttp.AmzObjectLockMode)] = mode
			opts.UserDefined[strings.ToLower(xhttp.AmzObjectLockRetainUntilDate)] = amztime.ISO8601Format(far)
		}
		info, err := obj.PutObject(t.Context(), bucket, object,
			mustGetPutObjReader(t, bytes.NewReader(payload), int64(len(payload)), "", ""), opts)
		if err != nil {
			t.Fatal(err)
		}
		return info.VersionID
	}
	stored := func(t *testing.T, object, vid string) objectlock.ObjectRetention {
		t.Helper()
		info, err := obj.GetObjectInfo(t.Context(), bucket, object, ObjectOptions{VersionID: vid})
		if err != nil {
			t.Fatal(err)
		}
		return objectlock.GetObjectRetentionMeta(info.UserDefined)
	}

	for _, test := range []struct {
		name     string
		creds    auth.Credentials
		existing string // stored retention mode on the version, until far
		mode     string // requested mode, "" removes retention
		until    time.Time
		bypass   bool
		want     int
		changed  bool
	}{
		{name: "no-permission removal", creds: noRet, existing: "GOVERNANCE", bypass: true, want: http.StatusForbidden},
		{name: "no-permission mode change", creds: noRet, existing: "GOVERNANCE", mode: "COMPLIANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "no-permission new compliance", creds: noRet, mode: "COMPLIANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "retention-only shorten with header", creds: retOnly, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "retention-only removal with header", creds: retOnly, existing: "GOVERNANCE", bypass: true, want: http.StatusForbidden},
		{name: "retention-only mode change with header", creds: retOnly, existing: "GOVERNANCE", mode: "COMPLIANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "retention-only shorten without header", creds: retOnly, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, want: http.StatusBadRequest},
		{name: "retention-only extend with header", creds: retOnly, existing: "GOVERNANCE", mode: "GOVERNANCE", until: farther, bypass: true, want: http.StatusOK, changed: true},
		{name: "retention-only new retention", creds: retOnly, mode: "GOVERNANCE", until: nearer, want: http.StatusOK, changed: true},
		{name: "bypass shorten with header", creds: retBypass, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, bypass: true, want: http.StatusOK, changed: true},
		{name: "bypass removal with header", creds: retBypass, existing: "GOVERNANCE", bypass: true, want: http.StatusOK, changed: true},
		{name: "bypass shorten without header", creds: retBypass, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, want: http.StatusBadRequest},
		{name: "bypass shorten compliance", creds: retBypass, existing: "COMPLIANCE", mode: "COMPLIANCE", until: nearer, bypass: true, want: http.StatusBadRequest},
		{name: "bypass-only extend", creds: bypassOnly, existing: "GOVERNANCE", mode: "GOVERNANCE", until: farther, bypass: true, want: http.StatusForbidden},
		{name: "conditional-deny-put-retention with bypass header", creds: condDenyShort, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "conditional-allow-put-retention satisfied", creds: condDenyShort, existing: "GOVERNANCE", mode: "GOVERNANCE", until: farther, bypass: true, want: http.StatusOK, changed: true},
		{name: "explicit-deny-bypass shorten with header", creds: explicitDenyBypass, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, bypass: true, want: http.StatusForbidden},
		{name: "owner shorten with header", creds: root, existing: "GOVERNANCE", mode: "GOVERNANCE", until: nearer, bypass: true, want: http.StatusOK, changed: true},
	} {
		t.Run(instanceType+"/"+test.name, func(t *testing.T) {
			object := "retention-authz/" + strings.ReplaceAll(test.name, " ", "-")
			vid := put(t, object, test.existing)
			before := stored(t, object, vid)

			body := retentionBody(test.mode, test.until)
			sum := md5.Sum(body)
			headers := map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])}
			if test.bypass {
				headers[objectlock.AmzObjectLockBypassRetGovernance] = "true"
			}
			target := makeTestTargetURL("", bucket, object, url.Values{"retention": {""}, "versionId": {vid}})
			rec := retentionAuthzRequest(t, router, test.creds, http.MethodPut, target, body, headers)
			if rec.Code != test.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, test.want, rec.Body.String())
			}
			after := stored(t, object, vid)
			if changed := after.Mode != before.Mode || !after.RetainUntilDate.Equal(before.RetainUntilDate.Time); changed != test.changed {
				t.Fatalf("retention changed = %v, want %v (before %s, after %s)", changed, test.changed, before.String(), after.String())
			}
		})
	}

	t.Run(instanceType+"/no-permission missing bucket", func(t *testing.T) {
		body := retentionBody("", time.Time{})
		sum := md5.Sum(body)
		target := makeTestTargetURL("", "retention-authz-missing", "object", url.Values{"retention": {""}})
		rec := retentionAuthzRequest(t, router, noRet, http.MethodPut, target, body,
			map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 before bucket lookup: %s", rec.Code, rec.Body.String())
		}
	})
}

// TestAPIVersionAddressedWriteRequiresReplicationTrust covers SN-2026-016: a
// caller-chosen destination versionId is honored only for trusted replication,
// and write paths cannot overwrite locked versions via directory keys or
// version-addressed multipart completions.
func TestAPIVersionAddressedWriteRequiresReplicationTrust(t *testing.T) {
	defer DetectTestLeak(t)()
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		objAPITest:        testAPIVersionAddressedWriteRequiresReplicationTrust,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
	})
}

func testAPIVersionAddressedWriteRequiresReplicationTrust(obj ObjectLayer, instanceType, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
	writer := newObjectAttributesAuthzUser(t, instanceType, bucket, `"s3:GetObject","s3:PutObject"`)
	original := []byte("original version content")
	info, err := obj.PutObject(t.Context(), bucket, "addressed",
		mustGetPutObjReader(t, bytes.NewReader(original), int64(len(original)), "", ""), ObjectOptions{Versioned: true})
	if err != nil {
		t.Fatal(err)
	}
	vid := info.VersionID

	unchanged := func(t *testing.T) {
		t.Helper()
		got, err := obj.GetObjectInfo(t.Context(), bucket, "addressed", ObjectOptions{VersionID: vid})
		if err != nil {
			t.Fatal(err)
		}
		if got.Size != int64(len(original)) || got.ETag != info.ETag {
			t.Fatalf("version %s was rewritten: size %d etag %s", vid, got.Size, got.ETag)
		}
	}

	for _, creds := range []struct {
		name  string
		creds auth.Credentials
	}{{"writer", writer}, {"owner", root}} {
		t.Run(instanceType+"/"+creds.name+"/put", func(t *testing.T) {
			body := []byte("replacement")
			target := makeTestTargetURL("", bucket, "addressed", url.Values{"versionId": {vid}})
			rec := retentionAuthzRequest(t, router, creds.creds, http.MethodPut, target, body, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
			unchanged(t)
		})
		t.Run(instanceType+"/"+creds.name+"/null-version", func(t *testing.T) {
			body := []byte("replacement")
			target := makeTestTargetURL("", bucket, "addressed", url.Values{"versionId": {nullVersionID}})
			rec := retentionAuthzRequest(t, router, creds.creds, http.MethodPut, target, body, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
		})
		t.Run(instanceType+"/"+creds.name+"/copy", func(t *testing.T) {
			target := makeTestTargetURL("", bucket, "addressed", url.Values{"versionId": {vid}})
			req, err := newTestSignedRequestV4(http.MethodPut, target, 0, nil, creds.creds.AccessKey, creds.creds.SecretKey,
				map[string]string{xhttp.AmzCopySource: "/" + bucket + "/addressed?versionId=" + vid, xhttp.AmzMetadataDirective: "REPLACE"})
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
			unchanged(t)
		})
		t.Run(instanceType+"/"+creds.name+"/multipart", func(t *testing.T) {
			target := makeTestTargetURL("", bucket, "addressed", url.Values{"uploads": {""}, "versionId": {vid}})
			rec := retentionAuthzRequest(t, router, creds.creds, http.MethodPost, target, nil, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
		})
		t.Run(instanceType+"/"+creds.name+"/complete-multipart-existing-version", func(t *testing.T) {
			// Simulate a pending upload persisted with an existing version ID
			// (e.g. initiated pre-upgrade or by a replication peer).
			up, err := obj.NewMultipartUpload(t.Context(), bucket, "addressed", ObjectOptions{
				Versioned: true,
				VersionID: vid,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer obj.AbortMultipartUpload(t.Context(), bucket, "addressed", up.UploadID, ObjectOptions{})

			partPayload := []byte("replacement-part")
			pi, err := obj.PutObjectPart(t.Context(), bucket, "addressed", up.UploadID, 1,
				mustGetPutObjReader(t, bytes.NewReader(partPayload), int64(len(partPayload)), "", ""), ObjectOptions{})
			if err != nil {
				t.Fatal(err)
			}
			completeBody := fmt.Appendf(nil, `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part></CompleteMultipartUpload>`, pi.ETag)
			target := makeTestTargetURL("", bucket, "addressed", url.Values{"uploadId": {up.UploadID}})
			rec := retentionAuthzRequest(t, router, creds.creds, http.MethodPost, target, completeBody, nil)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
			}
			unchanged(t)
		})
	}

	t.Run(instanceType+"/locked-directory-object", func(t *testing.T) {
		far := UTCNow().Add(365 * 24 * time.Hour).Truncate(time.Second)
		for _, lockCase := range []struct {
			name string
			meta map[string]string
		}{
			{
				name: "governance",
				meta: map[string]string{
					strings.ToLower(xhttp.AmzObjectLockMode):            "GOVERNANCE",
					strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): amztime.ISO8601Format(far),
				},
			},
			{
				name: "compliance",
				meta: map[string]string{
					strings.ToLower(xhttp.AmzObjectLockMode):            "COMPLIANCE",
					strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): amztime.ISO8601Format(far),
				},
			},
			{
				name: "legal-hold",
				meta: map[string]string{
					strings.ToLower(xhttp.AmzObjectLockLegalHold): "ON",
				},
			},
		} {
			t.Run(lockCase.name, func(t *testing.T) {
				dirKey := "locked-dir-" + lockCase.name + "/"
				if _, err := obj.PutObject(t.Context(), bucket, dirKey,
					mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""),
					ObjectOptions{Versioned: true, VersionID: nullVersionID, UserDefined: lockCase.meta}); err != nil {
					t.Fatal(err)
				}
				target := makeTestTargetURL("", bucket, dirKey, nil)
				rec := retentionAuthzRequest(t, router, writer, http.MethodPut, target, nil, nil)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("PUT locked dir status = %d, want 400: %s", rec.Code, rec.Body.String())
				}
				got, err := obj.GetObjectInfo(t.Context(), bucket, dirKey, ObjectOptions{VersionID: nullVersionID})
				if err != nil {
					t.Fatal(err)
				}
				for k, wantVal := range lockCase.meta {
					if got.UserDefined[k] != wantVal {
						t.Fatalf("metadata %s = %q, want %q", k, got.UserDefined[k], wantVal)
					}
				}
			})
		}
	})

	t.Run(instanceType+"/snowball-archive-version-id", func(t *testing.T) {
		var tarBuf bytes.Buffer
		tw := tar.NewWriter(&tarBuf)
		entryData := []byte("snowball-overwrite")
		if err := tw.WriteHeader(&tar.Header{
			Typeflag:   tar.TypeReg,
			Name:       "addressed",
			Size:       int64(len(entryData)),
			Format:     tar.FormatPAX,
			PAXRecords: map[string]string{"minio.versionId": vid},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entryData); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}

		// Untrusted writer cannot overwrite an existing version via PAX minio.versionId.
		target := makeTestTargetURL("", bucket, "archive.tar", nil)
		rec := retentionAuthzRequest(t, router, writer, http.MethodPut, target, tarBuf.Bytes(),
			map[string]string{"x-amz-meta-snowball-auto-extract": "true"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("untrusted snowball status = %d, want 403: %s", rec.Code, rec.Body.String())
		}
		unchanged(t)

		// Trusted batch replication (with outer MinIOSourceReplicationRequest) preserves PAX minio.versionId.
		replicaVID := mustGetUUID()
		var repBuf bytes.Buffer
		repTW := tar.NewWriter(&repBuf)
		repData := []byte("replicated-via-snowball")
		if err := repTW.WriteHeader(&tar.Header{
			Typeflag:   tar.TypeReg,
			Name:       "snowball-replicated",
			Size:       int64(len(repData)),
			Format:     tar.FormatPAX,
			PAXRecords: map[string]string{"minio.versionId": replicaVID},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := repTW.Write(repData); err != nil {
			t.Fatal(err)
		}
		if err := repTW.Close(); err != nil {
			t.Fatal(err)
		}
		repRec := retentionAuthzRequest(t, router, root, http.MethodPut, target, repBuf.Bytes(),
			map[string]string{
				"x-amz-meta-snowball-auto-extract":  "true",
				xhttp.MinIOSourceReplicationRequest: "true",
			})
		if repRec.Code != http.StatusOK {
			t.Fatalf("trusted snowball status = %d, want 200: %s", repRec.Code, repRec.Body.String())
		}
		if _, err := obj.GetObjectInfo(t.Context(), bucket, "snowball-replicated", ObjectOptions{VersionID: replicaVID}); err != nil {
			t.Fatalf("trusted snowball replication did not preserve version ID: %v", err)
		}
	})

	t.Run(instanceType+"/trusted replication", func(t *testing.T) {
		replicaVID := mustGetUUID()
		body := []byte("replicated version")
		target := makeTestTargetURL("", bucket, "replicated", url.Values{"versionId": {replicaVID}})
		rec := retentionAuthzRequest(t, router, root, http.MethodPut, target, body,
			map[string]string{xhttp.MinIOSourceReplicationRequest: "true"})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if _, err := obj.GetObjectInfo(t.Context(), bucket, "replicated", ObjectOptions{VersionID: replicaVID}); err != nil {
			t.Fatalf("trusted replication did not keep its version ID: %v", err)
		}
	})
}

func TestPutObjectRetentionClearMinimumDaysPolicy(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			for _, conditionalAllow := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/conditional-allow-%v", instance, conditionalAllow), func(t *testing.T) {
					statement := `{"Effect":"Allow","Action":["s3:PutObjectRetention","s3:BypassGovernanceRetention"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}, {"Effect":"Deny","Action":["s3:PutObjectRetention"],"Resource":["arn:aws:s3:::` + bucket + `/*"],"Condition":{"NumericLessThan":{"s3:object-lock-remaining-retention-days":"60"}}}`
					if conditionalAllow {
						statement = `{"Effect":"Allow","Action":["s3:BypassGovernanceRetention"],"Resource":["arn:aws:s3:::` + bucket + `/*"]}, {"Effect":"Allow","Action":["s3:PutObjectRetention"],"Resource":["arn:aws:s3:::` + bucket + `/*"],"Condition":{"NumericGreaterThanEquals":{"s3:object-lock-remaining-retention-days":"60"}}}`
					}
					cred := newRetentionPolicyUser(t, instance, `{"Version":"2012-10-17","Statement":[`+statement+`]}`)
					key := fmt.Sprintf("review-minimum-%v", conditionalAllow)
					far := UTCNow().Add(365 * 24 * time.Hour).Truncate(time.Second)
					info, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(nil), 0, "", ""), ObjectOptions{
						Versioned: true,
						UserDefined: map[string]string{
							strings.ToLower(xhttp.AmzObjectLockMode):            "GOVERNANCE",
							strings.ToLower(xhttp.AmzObjectLockRetainUntilDate): amztime.ISO8601Format(far),
						},
					})
					if err != nil {
						t.Fatal(err)
					}
					if status := putRetention(t, router, cred, bucket, key, info.VersionID, "GOVERNANCE", UTCNow().Add(30*24*time.Hour), true); status != http.StatusForbidden {
						t.Fatalf("shortening to 30 days status = %d, want 403", status)
					}
					status := putRetention(t, router, cred, bucket, key, info.VersionID, "", time.Time{}, true)
					after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: info.VersionID})
					if err != nil {
						t.Fatal(err)
					}
					ret := objectlock.GetObjectRetentionMeta(after.UserDefined)
					if status != http.StatusForbidden || ret.Mode != objectlock.RetGovernance {
						t.Fatalf("clearing retention status = %d, stored retention = %s; want 403 and original GOVERNANCE", status, ret.String())
					}
				})
			}
		},
	})
}

type hookBeforeWrite struct {
	ObjectLayer
	key    string
	before func()
}

func (p *hookBeforeWrite) fire(key string) {
	if key == p.key && p.before != nil {
		f := p.before
		p.before = nil
		f()
	}
}

func (p *hookBeforeWrite) PutObject(ctx context.Context, bucket, key string, r *PutObjReader, opts ObjectOptions) (ObjectInfo, error) {
	p.fire(key)
	return p.ObjectLayer.PutObject(ctx, bucket, key, r, opts)
}

func (p *hookBeforeWrite) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo ObjectInfo, srcOpts, dstOpts ObjectOptions) (ObjectInfo, error) {
	p.fire(dstObject)
	return p.ObjectLayer.CopyObject(ctx, srcBucket, srcObject, dstBucket, dstObject, srcInfo, srcOpts, dstOpts)
}

func (p *hookBeforeWrite) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletePart, opts ObjectOptions) (ObjectInfo, error) {
	p.fire(key)
	return p.ObjectLayer.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, opts)
}

// The COPY handler checks Object Lock under its destination's write lock, so
// no writer can land between that check and the copy. The latest a writer can
// land is just before the handler takes its locks.
func (p *hookBeforeWrite) lockObjects(ctx context.Context, reqs ...objectLockRequest) (LockContext, func(), error) {
	for _, r := range reqs {
		if r.write {
			p.fire(r.object)
		}
	}
	return p.ObjectLayer.lockObjects(ctx, reqs...)
}

func TestDirectoryObjectLockAfterPreflight(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t:                 t,
		makeBucketOptions: MakeBucketOptions{VersioningEnabled: true, LockEnabled: true},
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:GetObject","s3:PutObject"`)
			srcDir := "other-dir/"
			if rec := retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, srcDir, nil), nil, nil); rec.Code != http.StatusOK {
				t.Fatalf("srcDir PUT: %d %s", rec.Code, rec.Body.String())
			}

			for _, mode := range []string{"GOVERNANCE", "COMPLIANCE", "LEGAL-HOLD"} {
				for _, op := range []string{"PutObject", "CopyObject", "SelfCopy"} {
					t.Run(instance+"/"+mode+"/"+op, func(t *testing.T) {
						key := fmt.Sprintf("review-race-%s-%s/", mode, op)
						if rec := retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, key, nil), nil, nil); rec.Code != http.StatusOK {
							t.Fatalf("initial PUT: %d %s", rec.Code, rec.Body.String())
						}

						var locked ObjectInfo
						hook := &hookBeforeWrite{ObjectLayer: obj, key: key}
						hook.before = func() {
							if mode == "LEGAL-HOLD" {
								body := []byte(`<LegalHold><Status>ON</Status></LegalHold>`)
								sum := md5.Sum(body)
								rec := retentionAuthzRequest(t, router, root, http.MethodPut, makeTestTargetURL("", bucket, key, url.Values{"legal-hold": {""}, "versionId": {nullVersionID}}), body, map[string]string{xhttp.ContentMD5: base64.StdEncoding.EncodeToString(sum[:])})
								if rec.Code != http.StatusOK {
									t.Fatalf("set legal hold: %d %s", rec.Code, rec.Body.String())
								}
							} else if status := putRetention(t, router, root, bucket, key, nullVersionID, mode, UTCNow().Add(365*24*time.Hour), false); status != http.StatusOK {
								t.Fatalf("set retention: %d", status)
							}
							var err error
							locked, err = obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
							if err != nil {
								t.Fatal(err)
							}
						}
						setObjectLayer(hook)
						defer setObjectLayer(obj)

						var rec *httptest.ResponseRecorder
						switch op {
						case "PutObject":
							rec = retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, key, nil), nil, nil)
						case "CopyObject":
							rec = retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, key, nil), nil, map[string]string{
								xhttp.AmzCopySource: pathJoin(bucket, srcDir),
							})
						case "SelfCopy":
							rec = retentionAuthzRequest(t, router, writer, http.MethodPut, makeTestTargetURL("", bucket, key, nil), nil, map[string]string{
								xhttp.AmzCopySource: pathJoin(bucket, key), xhttp.AmzMetadataDirective: "REPLACE", "x-amz-meta-updated": "true",
							})
						}
						if hook.before != nil {
							t.Fatalf("%s never reached backend: %d %s", op, rec.Code, rec.Body.String())
						}
						after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: nullVersionID})
						if err != nil {
							t.Fatal(err)
						}
						if rec.Code != http.StatusBadRequest {
							t.Fatalf("locked null write via %s: %d %s", op, rec.Code, rec.Body.String())
						}
						multipartConditionError(t, rec, "InvalidRequest")
						retentionOverwriteUnchanged(t, locked, after)
					})
				}
			}
		},
	})
}

func TestMultipartVersioningTransitions(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		objAPITest: func(obj ObjectLayer, instance, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
			t.Run(instance+"/unversioned-to-enabled", func(t *testing.T) {
				key := "review-upload-before-versioning"
				initRec := retentionAuthzRequest(t, router, root, http.MethodPost, makeTestTargetURL("", bucket, key, url.Values{"uploads": {""}}), nil, nil)
				if initRec.Code != http.StatusOK {
					t.Fatalf("init: %d %s", initRec.Code, initRec.Body.String())
				}
				var mp InitiateMultipartUploadResponse
				if err := xml.Unmarshal(initRec.Body.Bytes(), &mp); err != nil {
					t.Fatal(err)
				}
				part := retentionAuthzRequest(t, router, root, http.MethodPut, getPutObjectPartURL("", bucket, key, mp.UploadID, "1"), []byte("ordinary pending upload"), nil)
				if part.Code != http.StatusOK {
					t.Fatalf("part: %d %s", part.Code, part.Body.String())
				}
				if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, []byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)); err != nil {
					t.Fatal(err)
				}
				body := fmt.Appendf(nil, `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, multipartConditionResponseETag(part))
				rec := retentionAuthzRequest(t, router, root, http.MethodPost, makeTestTargetURL("", bucket, key, url.Values{"uploadId": {mp.UploadID}}), body, nil)
				if rec.Code != http.StatusOK {
					t.Fatalf("ordinary upload initiated before versioning fails completion: %d %s", rec.Code, rec.Body.String())
				}
			})
			t.Run(instance+"/addressed-upload-after-suspension", func(t *testing.T) {
				key := "review-addressed-before-suspension"
				original := []byte("original")
				info, err := obj.PutObject(t.Context(), bucket, key, mustGetPutObjReader(t, bytes.NewReader(original), int64(len(original)), "", ""), ObjectOptions{Versioned: true})
				if err != nil {
					t.Fatal(err)
				}
				up, err := obj.NewMultipartUpload(t.Context(), bucket, key, ObjectOptions{Versioned: true, VersionID: info.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				part := []byte("replaced existing version")
				pi, err := obj.PutObjectPart(t.Context(), bucket, key, up.UploadID, 1, mustGetPutObjReader(t, bytes.NewReader(part), int64(len(part)), "", ""), ObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := globalBucketMetadataSys.Update(t.Context(), bucket, bucketVersioningConfig, []byte(`<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`)); err != nil {
					t.Fatal(err)
				}
				writer := newObjectAttributesAuthzUser(t, instance, bucket, `"s3:PutObject"`)
				body := fmt.Appendf(nil, `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part></CompleteMultipartUpload>`, pi.ETag)
				rec := retentionAuthzRequest(t, router, writer, http.MethodPost, makeTestTargetURL("", bucket, key, url.Values{"uploadId": {up.UploadID}}), body, nil)
				after, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{VersionID: info.VersionID})
				if err != nil {
					t.Fatal(err)
				}
				if rec.Code != http.StatusForbidden || after.ETag != info.ETag {
					t.Fatalf("suspended-bucket existing UUID overwritten: status=%d old-etag=%s new-etag=%s body=%s", rec.Code, info.ETag, after.ETag, rec.Body.String())
				}
			})
		},
	})
}
