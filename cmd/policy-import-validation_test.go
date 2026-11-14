// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIAMImportRejectsUnknownPolicyFields(t *testing.T) {
	_, _ = iamAdminFixture(t)
	for _, raw := range []string{
		`{"Version":"2012-10-17","Statements":[]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::b/*"],"Conditions":{"StringEquals":{"s3:ExistingObjectTag/classification":"public"}}}]}`,
	} {
		data := iamImportArchive(t, map[string]any{allPoliciesFile: map[string]json.RawMessage{"import-policy": json.RawMessage(raw)}})
		req, err := newTestSignedRequestV4(http.MethodPut, "http://localhost/minio/admin/v3/import-iam-v2", int64(len(data)), bytes.NewReader(data), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
		mustIAM(t, err)
		mustIAM(t, req.ParseForm())
		rec := httptest.NewRecorder()
		adminAPIHandlers{}.ImportIAMV2(rec, req.WithContext(newContext(req, rec, "ImportIAM")))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("import malformed policy: got %d %s, want 400", rec.Code, rec.Body.String())
		}
	}
}

func TestSessionPolicyWriteKeepsStrictSemanticValidation(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:GetBucketQuota"],"Resource":["arn:aws:s3:::mybucket"],"NotResource":["arn:aws:s3:::otherbucket"]}]}`)
	if _, err := parseSessionPolicyStrictBytes(raw); err == nil {
		t.Fatal("new session policy accepted conflicting Resource and NotResource")
	}
	if _, err := parsePolicySnapshotBytes(raw); err != nil {
		t.Fatalf("historical snapshot compatibility lost: %v", err)
	}
}

func TestBucketPolicyRejectsUnsupportedNotPrincipal(t *testing.T) {
	raw := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotPrincipal":{"AWS":"excluded-user"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	if _, err := parseBucketPolicyStrictBytes(raw, "b"); err == nil {
		t.Fatal("unsupported NotPrincipal was silently discarded")
	}
}
