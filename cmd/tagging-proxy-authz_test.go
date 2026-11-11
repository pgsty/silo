// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/bucket/replication"
	xhttp "github.com/minio/minio/internal/http"
)

func TestAPITaggingProxyAuthorization(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, root auth.Credentials, t *testing.T) {
		conditional := newDeleteAuthzPolicyUser(t, backend, bucket, fmt.Sprintf(`[
			{"Effect":"Allow","Action":["s3:GetObjectTagging","s3:PutObjectTagging","s3:DeleteObjectTagging"],"Resource":["arn:aws:s3:::%s/*"]},
			{"Effect":"Deny","Action":["s3:GetObjectTagging","s3:PutObjectTagging","s3:DeleteObjectTagging"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/secret":"true"}}}
		]`, bucket, bucket))
		tagAllow := newDeleteAuthzPolicyUser(t, backend, bucket, fmt.Sprintf(`[
			{"Effect":"Allow","Action":["s3:GetObjectTagging","s3:PutObjectTagging","s3:DeleteObjectTagging"],"Resource":["arn:aws:s3:::%s/*"],"Condition":{"StringEquals":{"s3:ExistingObjectTag/secret":"false"}}}
		]`, bucket))
		denied := newDeleteAuthzPolicyUser(t, backend, bucket, fmt.Sprintf(`[
			{"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::%s/*"]}
		]`, bucket))
		zero := iamAdminUser(t.Context(), t, globalIAMSys, "tagging-no-policy-"+mustGetUUID(), "")
		versionID := mustGetUUID()
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			for _, tc := range []struct {
				name                                string
				tags                                []string
				cred                                auth.Credentials
				readStatus, writeStatus, wantStatus int
				wantWrites                          int32
				disabledFirst                       bool
				firstReadStatus                     int
				noReads                             bool
			}{
				{name: "deny-second-target", tags: []string{"false", "true"}, cred: conditional, wantStatus: http.StatusForbidden},
				{name: "deny-first-target", tags: []string{"true", "false"}, cred: conditional, wantStatus: http.StatusForbidden},
				{name: "all-authorized", tags: []string{"false", "false"}, cred: conditional, wantWrites: 2},
				{name: "anonymous", tags: []string{"false"}, wantStatus: http.StatusForbidden, noReads: true},
				{name: "invalid-credentials", tags: []string{"false"}, cred: auth.Credentials{AccessKey: root.AccessKey, SecretKey: "wrong-secret-key"}, wantStatus: http.StatusForbidden, noReads: true},
				{name: "zero-permissions", tags: []string{"false"}, cred: zero, wantStatus: http.StatusForbidden, noReads: true},
				{name: "zero-permissions-missing", tags: []string{"false"}, cred: zero, readStatus: http.StatusNotFound, wantStatus: http.StatusForbidden, noReads: true},
				{name: "unconditional-deny", tags: []string{"false"}, cred: denied, wantStatus: http.StatusForbidden, noReads: true},
				{name: "unreadable", tags: []string{"false"}, cred: root, readStatus: http.StatusServiceUnavailable, wantStatus: http.StatusServiceUnavailable},
				{name: "missing-version", tags: []string{"false", "false"}, cred: root, readStatus: http.StatusNotFound, wantStatus: http.StatusNotFound},
				{name: "tag-allow-missing-version", tags: []string{"false"}, cred: tagAllow, readStatus: http.StatusNotFound, wantStatus: http.StatusForbidden},
				{name: "tag-allow-lagging-first", tags: []string{"false", "false"}, cred: tagAllow, firstReadStatus: http.StatusNotFound, wantWrites: 1},
				{name: "tag-allow-lagging-second", tags: []string{"false", "false"}, cred: tagAllow, firstReadStatus: http.StatusOK, readStatus: http.StatusNotFound, wantWrites: 1},
				{name: "tag-allow-present-untagged", tags: []string{"false", ""}, cred: tagAllow, wantStatus: http.StatusForbidden},
				{name: "tag-allow-unreadable-first", tags: []string{"false", "false"}, cred: tagAllow, firstReadStatus: http.StatusServiceUnavailable, wantStatus: http.StatusServiceUnavailable},
				{name: "tag-allow-unreadable-second", tags: []string{"false", "false"}, cred: tagAllow, firstReadStatus: http.StatusOK, readStatus: http.StatusServiceUnavailable, wantStatus: http.StatusServiceUnavailable},
				{name: "disabled-target", tags: []string{"true", "false"}, cred: conditional, disabledFirst: true, wantWrites: 1},
				{name: "no-available-target", tags: []string{"false"}, cred: tagAllow, disabledFirst: true, wantStatus: http.StatusServiceUnavailable, noReads: true},
				{name: "skipped-target-cannot-mask-failure", tags: []string{"false", "false"}, cred: root, disabledFirst: true, writeStatus: http.StatusServiceUnavailable, wantStatus: http.StatusServiceUnavailable, wantWrites: 1},
			} {
				if method == http.MethodGet && tc.writeStatus != 0 {
					continue // This case only exercises a remote mutation failure.
				}
				t.Run(backend+"/"+method+"/"+tc.name, func(t *testing.T) {
					var reads, writes atomic.Int32
					globalBucketTargetSys.Lock()
					globalBucketTargetSys.targetsMap[bucket] = nil
					globalBucketTargetSys.Unlock()
					cfg := replication.Config{}
					for i, value := range tc.tags {
						readStatus := tc.readStatus
						if i == 0 && tc.firstReadStatus != 0 {
							readStatus = tc.firstReadStatus
						}
						target := newILMTestTarget(t)
						registerILMTestTarget(t, obj, bucket, target, func(w http.ResponseWriter, r *http.Request) {
							if r.URL.Query().Get("versionId") != versionID || !r.URL.Query().Has("tagging") || r.Header.Get(xhttp.MinIOSourceProxyRequest) != "true" {
								t.Errorf("remote request lost addressed version or proxy marker: %s", r.URL)
							}
							status := tc.writeStatus
							if r.Method == http.MethodGet {
								reads.Add(1)
								status = readStatus
							} else {
								writes.Add(1)
								if readStatus == http.StatusNotFound {
									t.Error("tagging write reached a missing replica")
								}
							}
							w.Header().Set("Content-Type", "application/xml")
							if status != 0 && status != http.StatusOK {
								w.WriteHeader(status)
								code := "ServiceUnavailable"
								if status == http.StatusNotFound {
									code = "NoSuchVersion"
								}
								fmt.Fprintf(w, "<Error><Code>%s</Code><Message>injected remote result</Message></Error>", code)
								return
							}
							switch r.Method {
							case http.MethodGet:
								if value == "" {
									fmt.Fprint(w, "<Tagging><TagSet></TagSet></Tagging>")
								} else {
									fmt.Fprintf(w, "<Tagging><TagSet><Tag><Key>secret</Key><Value>%s</Value></Tag></TagSet></Tagging>", value)
								}
							case http.MethodDelete:
								w.WriteHeader(http.StatusNoContent)
							}
						})
						globalBucketTargetSys.Lock()
						globalBucketTargetSys.targetsMap[bucket][i].Credentials = &madmin.Credentials{AccessKey: "proxy-test", SecretKey: "proxy-test-secret"}
						globalBucketTargetSys.arnRemotesMap[target.arn].Client.disableProxy = tc.disabledFirst && i == 0
						globalBucketTargetSys.Unlock()
						rule := configs[0].Rules[0]
						rule.Priority = i + 1
						rule.Destination = replication.Destination{ARN: target.arn, Bucket: target.bucket}
						cfg.Rules = append(cfg.Rules, rule)
					}
					meta, err := globalBucketMetadataSys.Get(bucket)
					if err != nil {
						t.Fatal(err)
					}
					meta.replicationConfig = &cfg
					globalBucketMetadataSys.Set(bucket, meta)
					body := ""
					if method == http.MethodPut {
						body = "<Tagging><TagSet><Tag><Key>new</Key><Value>value</Value></Tag></TagSet></Tagging>"
					}
					path := "/" + bucket + "/remote-only?tagging&versionId=" + versionID
					var req *http.Request
					if tc.cred.AccessKey == "" {
						req = httptest.NewRequest(method, path, strings.NewReader(body))
					} else {
						req, err = newTestSignedRequestV4(method, path, int64(len(body)), strings.NewReader(body), tc.cred.AccessKey, tc.cred.SecretKey, nil)
						if err != nil {
							t.Fatal(err)
						}
					}
					rec := httptest.NewRecorder()
					router.ServeHTTP(rec, req)
					wantStatus := tc.wantStatus
					if wantStatus == 0 {
						wantStatus = http.StatusOK
						if method == http.MethodDelete {
							wantStatus = http.StatusNoContent
						}
					}
					wantWrites := tc.wantWrites
					if method == http.MethodGet {
						wantWrites = 0
					}
					if rec.Code != wantStatus || writes.Load() != wantWrites {
						t.Errorf("status=%d writes=%d, want status=%d writes=%d: %s", rec.Code, writes.Load(), wantStatus, wantWrites, rec.Body.String())
					}
					if tc.noReads && reads.Load() != 0 {
						t.Errorf("unauthorized request reached %d remote reads", reads.Load())
					}
				})
			}
		}
	}})
}
