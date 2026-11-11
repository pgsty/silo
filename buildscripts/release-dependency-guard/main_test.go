// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestReleaseDependencySelection(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		name, pkg, console, tag, mcSHA string
		local, upstream, wantError     bool
	}{
		{name: "coordinated", pkg: "v3.16.1", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit},
		{name: "old-package", pkg: "v3.16.0", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit, wantError: true},
		{name: "prerelease-package", pkg: "v3.16.1-rc.1", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit, wantError: true},
		{name: "old-embedded-console", pkg: "v3.16.1", console: "2.7.0", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit, wantError: true},
		{name: "old-container-client", pkg: "v3.16.1", console: "2.7.1", tag: "RELEASE.2026-11-09T00-00-00Z", mcSHA: commit, wantError: true},
		{name: "source-binary-mismatch", pkg: "v3.16.1", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: "ffffffffffffffffffffffffffffffffffffffff", wantError: true},
		{name: "workspace-console", pkg: "v3.16.1", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit, local: true, wantError: true},
		{name: "upstream-console", pkg: "v3.16.1", console: "2.7.1", tag: "RELEASE.2026-11-12T00-00-00Z", mcSHA: commit, upstream: true, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modules := map[string]module{
				"github.com/pgsty/silo-pkg/v3": {Path: "github.com/pgsty/silo-pkg/v3", Version: tc.pkg},
				"github.com/minio/console": {Path: "github.com/minio/console", Replace: &module{
					Path: "github.com/pgsty/silo-console", Version: "v0.0.0-20261112000000-0123456789ab",
				}},
				"github.com/minio/mc": {Path: "github.com/minio/mc", Replace: &module{
					Path: "github.com/pgsty/mc", Version: "v0.0.0-20261112000000-0123456789ab",
				}},
			}
			if tc.local {
				modules["github.com/minio/console"].Replace.Version = ""
			}
			if tc.upstream {
				modules["github.com/minio/console"].Replace.Path = "github.com/minio/console"
			}
			if err := validate(modules, tc.console, tc.tag, tc.mcSHA); (err != nil) != tc.wantError {
				t.Fatalf("got %v, wantError=%t", err, tc.wantError)
			}
		})
	}
}
