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
	"slices"
	"testing"

	"github.com/pgsty/silo-pkg/v3/ldap"
)

// LDAP-mode IAM on one erasure set of the given number of drives.
func prepareIAMLongNameFixture(t *testing.T, drives int) (context.Context, *IAMSys) {
	t.Helper()
	resetTestGlobals()
	ctx, cancel := context.WithCancel(context.Background())
	obj, disks, err := prepareErasure(ctx, drives)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	initAllSubsystems(ctx)
	globalIAMSys.SetUsersSysType(LDAPUsersSysType)
	globalIAMSys.initStore(obj, nil)
	t.Cleanup(func() {
		cancel()
		obj.Shutdown(context.Background())
		removeRoots(disks)
		resetTestGlobals()
	})
	mustIAM(t, globalIAMSys.Load(ctx, true))
	return ctx, globalIAMSys
}

// A normalized LDAP DN hex-escapes every non-ASCII byte, so a typical
// Cyrillic DN names IAM records with a path element longer than NAME_MAX.
// No drive can hold such a record. Reads must find nothing and writes must
// fail as name-too-long, on an erasure set exactly as on a single drive,
// where the drive's own error says so.
func TestIAMLongNameRecordsOnErasureSet(t *testing.T) {
	norm := func(dn string) string {
		t.Helper()
		n, err := ldap.NormalizeDN(dn)
		mustIAM(t, err)
		return n
	}
	longDN := norm("cn=Иванов Иван Иванович,ou=Особый Отдел,ou=Центральный Офис,dc=intra,dc=net")
	shortDN := norm("cn=Petrov,ou=Users,dc=intra,dc=net")
	group := norm("cn=Storage Users,ou=Groups,dc=intra,dc=net")
	longPolicyPath := getMappedPolicyPath(longDN, stsUser, false)
	longParentPath := getUserIdentityPath(longDN, regUser)
	if len(longDN) <= 255 || checkPathLength(longPolicyPath) != nil {
		t.Fatalf("normalized DN must exceed NAME_MAX yet pass checkPathLength: %d characters, %v", len(longDN), checkPathLength(longPolicyPath))
	}

	for _, tc := range []struct {
		name   string
		drives int
	}{
		{"single drive", 1},
		{"erasure set", 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, sys := prepareIAMLongNameFixture(t, tc.drives)
			store := sys.store.IAMStorageAPI
			_, err := sys.PolicyDBSet(ctx, group, "readonly", regUser, true)
			mustIAM(t, err)
			// Create the parent directories on every drive, so that the
			// filesystem itself rejects the long element.
			_, err = sys.PolicyDBSet(ctx, shortDN, "readwrite", stsUser, false)
			mustIAM(t, err)
			mustIAM(t, saveIAMRevision(ctx, store, getUserIdentityPath("existing-user", regUser), &iamUserRevocation{}))

			lookup := func(stage string) {
				t.Helper()
				// AssumeRoleWithLDAPIdentity: the parent revision and the
				// policy mapping of the DN.
				if r, err := loadIAMRevision(ctx, store, longParentPath); err != nil || !r.timestamp().IsZero() {
					t.Errorf("%s: parent revision: %+v, %v", stage, r, err)
				}
				policies, err := sys.PolicyDBGet(longDN, group)
				if err != nil {
					t.Errorf("%s: policy lookup: %v", stage, err)
				} else if !slices.Equal(policies, []string{"readonly"}) {
					t.Errorf("%s: got policies %v, want the group policy only", stage, policies)
				}
			}
			lookup("before writes")

			_, err = sys.PolicyDBSet(ctx, longDN, "readwrite", stsUser, false)
			if !iamConfigNameTooLong(longPolicyPath, err) {
				t.Errorf("attach to the long DN: got %v, want a name-too-long error", err)
			}
			if err := saveIAMRevision(ctx, store, longParentPath, &iamUserRevocation{}); !iamConfigNameTooLong(longParentPath, err) {
				t.Errorf("revocation of the long DN: got %v, want a name-too-long error", err)
			}
			// Detaching writes a tombstone, which cannot be stored either.
			if _, err := sys.PolicyDBSet(ctx, longDN, "", stsUser, false); !iamConfigNameTooLong(longPolicyPath, err) {
				t.Errorf("detach from the long DN: got %v, want a name-too-long error", err)
			}
			lookup("after writes")
		})
	}
}
