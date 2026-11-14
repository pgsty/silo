// Copyright (c) 2026 PGSTY
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
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func iamImportArchive(t *testing.T, assets map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, value := range assets {
		w, err := zw.Create(pathJoin(iamAssetsDir, name))
		mustIAM(t, err)
		mustIAM(t, json.NewEncoder(w).Encode(value))
	}
	mustIAM(t, zw.Close())
	return buf.Bytes()
}

func iamImportCall(t *testing.T, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	req, err := newTestSignedRequestV4(http.MethodPut, "http://localhost/minio/admin/v3/import-iam-v2", int64(len(data)), bytes.NewReader(data), globalActiveCred.AccessKey, globalActiveCred.SecretKey, nil)
	mustIAM(t, err)
	mustIAM(t, req.ParseForm())
	rec := httptest.NewRecorder()
	adminAPIHandlers{}.ImportIAMV2(rec, req.WithContext(newContext(req, rec, "ImportIAM")))
	if rec.Code != http.StatusOK {
		t.Fatalf("import-iam-v2: %d %s", rec.Code, rec.Body.String())
	}
	return rec
}

func TestIAMImportExportState(t *testing.T) {
	for _, target := range []string{"fresh", "existing"} {
		t.Run(target, func(t *testing.T) {
			ctx, sys := iamAdminFixture(t)
			parent := iamAdminUser(ctx, t, sys, "import-parent", "")
			for _, status := range []string{statusDisabled, statusEnabled} {
				group := "import-" + status
				_, err := sys.AddUsersToGroup(ctx, group, []string{parent.AccessKey})
				mustIAM(t, err)
				_, err = sys.SetGroupStatus(ctx, group, status == statusEnabled)
				mustIAM(t, err)
			}
			_, err := sys.PolicyDBSet(ctx, "import-disabled", "readwrite", regUser, true)
			mustIAM(t, err)
			sp, err := policy.ParseConfig(strings.NewReader(svcAccEditPolicy))
			mustIAM(t, err)
			expires := UTCNow().Add(time.Hour).Truncate(time.Second)
			_, _, err = sys.NewServiceAccount(ctx, parent.AccessKey, nil, newServiceAccountOpts{
				accessKey: "import-service", secretKey: "import-service-secret", status: auth.AccountOff,
				sessionPolicy: sp, expiration: &expires, name: "disabled service", claims: map[string]any{"identity-attribute": "preserved"},
			})
			mustIAM(t, err)
			exported := iamAdminCall(t, globalActiveCred, http.MethodGet, "/minio/admin/v3/export-iam", nil, nil, adminAPIHandlers{}.ExportIAM)
			if exported.Code != http.StatusOK {
				t.Fatalf("export-iam: %d %s", exported.Code, exported.Body.String())
			}
			if target == "fresh" {
				ctx, sys = iamAdminFixture(t)
			} else {
				// Import must also replace an existing enabled account/group and
				// restore an enabled group that is disabled on the target.
				_, err = sys.UpdateServiceAccount(ctx, "import-service", updateServiceAccountOpts{status: auth.AccountOn})
				mustIAM(t, err)
				_, err = sys.SetGroupStatus(ctx, "import-disabled", true)
				mustIAM(t, err)
				_, err = sys.SetGroupStatus(ctx, "import-enabled", false)
				mustIAM(t, err)
			}
			rec := iamImportCall(t, exported.Body.Bytes())
			var result madmin.ImportIAMResult
			mustIAM(t, json.Unmarshal(rec.Body.Bytes(), &result))
			if len(result.Failed.Groups) != 0 || len(result.Failed.ServiceAccounts) != 0 || len(result.Added.ServiceAccounts) != 1 {
				t.Fatalf("import did not restore the exported entities: %s", rec.Body.String())
			}
			mustIAM(t, sys.store.LoadIAMCache(ctx, false))
			for _, status := range []string{statusDisabled, statusEnabled} {
				group, err := sys.GetGroupDescription("import-" + status)
				mustIAM(t, err)
				if group.Status != status || len(group.Members) != 1 || group.Members[0] != parent.AccessKey {
					t.Fatalf("group status or members changed: %+v", group)
				}
			}
			if sys.IsAllowed(policy.Args{AccountName: parent.AccessKey, Action: policy.GetObjectAction, BucketName: "edit", ObjectName: "object"}) {
				t.Error("the disabled imported group grants access")
			}
			cr, gotPolicy, err := sys.GetServiceAccount(ctx, "import-service")
			mustIAM(t, err)
			if cr.Status != auth.AccountOff || !cr.Expiration.Equal(expires) || cr.Name != "disabled service" || gotPolicy == nil || !gotPolicy.Equals(*sp) {
				t.Fatal("import changed the service account status, expiration, name or inline policy")
			}
			if _, valid, err := sys.CheckKey(ctx, "import-service"); err != nil || valid {
				t.Fatalf("imported disabled credential is usable: valid=%v err=%v", valid, err)
			}
			var stored UserIdentity
			mustIAM(t, sys.store.loadIAMConfig(ctx, &stored, getUserIdentityPath("import-service", svcUser)))
			raw, err := auth.ExtractClaims(stored.Credentials.SessionToken, stored.Credentials.SecretKey)
			mustIAM(t, err)
			if _, ok := raw.Map()[sessionPolicyNameExtracted]; ok || raw.Map()["identity-attribute"] != "preserved" {
				t.Fatal("import polluted the raw JWT or lost identity claims")
			}
			// Old exports may contain a derived claim and omit the policy version.
			snapshot, err := serviceAccountSnapshot(stored)
			mustIAM(t, err)
			snapshot.Claims[sessionPolicyNameExtracted] = "stale decoded policy"
			snapshot.SessionPolicy = []byte(strings.ReplaceAll(svcAccEditPolicy, `"Version":"2012-10-17",`, ""))
			rec = iamImportCall(t, iamImportArchive(t, map[string]any{allSvcAcctsFile: map[string]madmin.SRSvcAccCreate{"import-service": snapshot}}))
			mustIAM(t, json.Unmarshal(rec.Body.Bytes(), &result))
			if len(result.Failed.ServiceAccounts) != 0 {
				t.Fatalf("legacy snapshot import failed: %s", rec.Body.String())
			}
			_, gotPolicy, err = sys.GetServiceAccount(ctx, "import-service")
			mustIAM(t, err)
			if gotPolicy == nil || !gotPolicy.Equals(*sp) {
				t.Fatal("import did not normalize the inline policy")
			}
			mustIAM(t, sys.store.loadIAMConfig(ctx, &stored, getUserIdentityPath("import-service", svcUser)))
			raw, err = auth.ExtractClaims(stored.Credentials.SessionToken, stored.Credentials.SecretKey)
			mustIAM(t, err)
			if _, ok := raw.Map()[sessionPolicyNameExtracted]; ok {
				t.Fatal("legacy import signed a derived claim into the JWT")
			}
		})
	}
}

type iamImportGroupFailureStore struct {
	IAMStorageAPI
	statusOnly bool
	err        error
}

func (s *iamImportGroupFailureStore) saveIAMConfig(ctx context.Context, item any, path string, opts ...options) error {
	mutation, _ := ctx.Value(iamGroupMutationKey{}).(iamGroupMutation)
	if path == getGroupInfoPath("import-failure") && mutation.StatusOnly == s.statusOnly {
		return s.err
	}
	return s.IAMStorageAPI.saveIAMConfig(ctx, item, path, opts...)
}

func TestIAMImportGroupFailure(t *testing.T) {
	for _, operation := range []string{"members", "status"} {
		t.Run(operation, func(t *testing.T) {
			_, sys := iamAdminFixture(t)
			injected := madmin.ErrorResponse{Code: "InjectedGroupWrite", Message: operation + " write failed"}
			sys.store.IAMStorageAPI = &iamImportGroupFailureStore{IAMStorageAPI: sys.store.IAMStorageAPI, statusOnly: operation == "status", err: injected}
			rec := iamImportCall(t, iamImportArchive(t, map[string]any{allGroupsFile: map[string]GroupInfo{
				"import-failure": {Status: statusDisabled},
			}}))
			var result struct {
				Added  madmin.IAMEntities `json:"added"`
				Failed struct {
					Groups []struct {
						Name  string          `json:"name"`
						Error json.RawMessage `json:"error"`
					} `json:"groups"`
				} `json:"failed"`
			}
			mustIAM(t, json.Unmarshal(rec.Body.Bytes(), &result))
			wantError, err := json.Marshal(injected)
			mustIAM(t, err)
			if len(result.Added.Groups) != 0 || len(result.Failed.Groups) != 1 || result.Failed.Groups[0].Name != "import-failure" || !bytes.Equal(result.Failed.Groups[0].Error, wantError) {
				t.Fatalf("import did not report the actual %s error: %s", operation, rec.Body.String())
			}
		})
	}
}
