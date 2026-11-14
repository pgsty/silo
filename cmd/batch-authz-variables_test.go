// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pgsty/silo-pkg/v3/policy"
)

// Use explicit condition values to exercise the evaluator, including literal
// spellings that S3 tag validation does not permit in stored tags.
func TestBatchPolicyConditionVariableParity(t *testing.T) {
	f := newBatchAuthzFixture(t)
	cases := []struct {
		value, actual string
		matches       bool
		requestOnly   bool
	}{
		{"${$}100", "${$}100", true, false},
		{"${$}100", "$100", false, false},
		{"${*}", "${*}", true, false},
		{"${?}", "${?}", true, false},
		{"${custom:unknown}", "${custom:unknown}", true, false},
		{"${aws:Unknown}", "${aws:Unknown}", true, false},
		{"${aws:UserAgent", "${aws:UserAgent", true, false},
		{"${aws:username}", "", true, false},
		{"${aws:UserAgent}", "test-agent", true, true},
		{"${prefix${aws:UserAgent}}", "${prefixtest-agent}", true, true},
	}
	for i, tc := range cases {
		for opIndex, op := range []string{
			"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
			"StringLike", "StringNotLike", "ForAnyValue:StringEquals", "ForAllValues:StringEquals", "BinaryEquals",
		} {
			for _, effect := range []string{"Allow", "Deny"} {
				t.Run(fmt.Sprintf("%d/%s/%s", i, op, effect), func(t *testing.T) {
					name := fmt.Sprintf("var-%d-%d-%s", i, opIndex, effect)
					conditionValue := tc.value
					if op == "BinaryEquals" {
						conditionValue = base64.StdEncoding.EncodeToString([]byte(conditionValue))
					}
					statement := fmt.Sprintf(`{"Effect":%q,"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/data/*"],"Condition":{%q:{"s3:ExistingObjectTag/label":%q}}}`, effect, op, conditionValue)
					if effect == "Deny" {
						statement += `,{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/data/*"]}`
					}
					cred, sub := batchContextUser(t, f, name, statement)
					actual := tc.actual
					if tc.value == "${aws:username}" {
						actual = cred.AccessKey
					}
					values := map[string][]string{"ExistingObjectTag/label": {actual}}
					ordinaryValues := maps.Clone(values)
					ordinaryValues["username"] = []string{cred.AccessKey}
					ordinaryValues["UserAgent"] = []string{"test-agent"}
					ordinaryAllowed := f.sys.isAllowedLocally(policy.Args{
						AccountName:     cred.AccessKey,
						Action:          policy.GetObjectAction,
						BucketName:      f.bucket,
						ObjectName:      "data/" + name,
						ConditionValues: ordinaryValues,
					})
					matches := tc.matches
					if strings.Contains(op, "Not") {
						matches = !matches
					}
					if want := matches == (effect == "Allow"); ordinaryAllowed != want {
						t.Fatalf("ordinary evaluator allowed=%v want %v", ordinaryAllowed, want)
					}
					batchErr := sub.authorize(f.ctx, batchAuthzRequest{
						action: policy.GetObjectAction, bucket: f.bucket, object: "data/" + name, values: values,
					})
					if tc.requestOnly {
						if !isBatchJobAuthzError(batchErr) {
							t.Fatalf("missing request context must deny: %v", batchErr)
						}
						if (effect == "Deny") != isBatchContextRefusal(batchErr) {
							t.Fatalf("only a Deny must refuse missing context: %v", batchErr)
						}
						return
					}
					if (batchErr == nil) != ordinaryAllowed {
						t.Fatalf("ordinary allowed=%v; batch=%v", ordinaryAllowed, batchErr)
					}
				})
			}
		}
	}

	// Condition keys themselves are never expanded.
	const statement = `{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/${aws:UserAgent}":"literal"}}}`
	cred, sub := batchContextUser(t, f, "literal-condition-key", statement)
	values := map[string][]string{"ExistingObjectTag/${aws:UserAgent}": {"literal"}}
	if !f.sys.isAllowedLocally(policy.Args{AccountName: cred.AccessKey, Action: policy.GetObjectAction, BucketName: f.bucket, ObjectName: "data/key", ConditionValues: values}) {
		t.Fatal("ordinary evaluator did not match the literal condition key")
	}
	if err := sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: "data/key", values: values}); err != nil {
		t.Fatalf("batch treated a condition key as a variable: %v", err)
	}
}

// Object names permit these spellings, so also compare real S3 GETs with batch.
func TestBatchPolicyResourceVariableParity(t *testing.T) {
	f := newBatchAuthzFixture(t)
	router := initTestAPIEndPoints(f.obj, []string{"GetObject"})
	for i, raw := range []string{"${$}100", "${*}", "${?}", "${custom:unknown}", "${prefix${aws:UserAgent}}", "${aws:username}", "${aws:UserAgent}"} {
		for _, effect := range []string{"Allow", "Deny"} {
			t.Run(fmt.Sprintf("%d/%s", i, effect), func(t *testing.T) {
				name := fmt.Sprintf("res-%d-%s", i, effect)
				statement := fmt.Sprintf(`{"Effect":%q,"Action":["s3:GetObject"],"Resource":[%q]}`, effect, "arn:aws:s3:::batch-authz/"+raw)
				if effect == "Deny" {
					statement += `,{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::batch-authz/*"]}`
				}
				cred, sub := batchContextUser(t, f, name, statement)
				object := strings.ReplaceAll(raw, "${aws:username}", cred.AccessKey)
				if raw == "${aws:UserAgent}" {
					object = "test-agent"
				}
				_, err := f.obj.PutObject(f.ctx, f.bucket, object, mustGetPutObjReader(t, strings.NewReader("data"), 4, "", ""), ObjectOptions{})
				mustIAM(t, err)
				req, err := newTestSignedRequestV4(http.MethodGet, getGetObjectURL("", f.bucket, object), 0, nil, cred.AccessKey, cred.SecretKey, map[string]string{"User-Agent": "test-agent"})
				mustIAM(t, err)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				wantStatus := http.StatusOK
				if effect == "Deny" {
					wantStatus = http.StatusForbidden
				}
				if rec.Code != wantStatus {
					t.Fatalf("S3 read: %d want %d: %s", rec.Code, wantStatus, rec.Body.String())
				}
				err = sub.authorize(f.ctx, batchAuthzRequest{action: policy.GetObjectAction, bucket: f.bucket, object: object})
				if raw == "${aws:UserAgent}" {
					if !isBatchJobAuthzError(err) || (effect == "Deny") != isBatchContextRefusal(err) {
						t.Fatalf("batch did not reject missing request context: %v", err)
					}
					return
				}
				if (err == nil) != (rec.Code == http.StatusOK) {
					t.Fatalf("resource %q %s: S3=%d batch=%v", raw, effect, rec.Code, err)
				}
			})
		}
	}
}
