// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

// release-dependency-guard checks the modules and bundled client actually used
// by a release. A local workspace must not substitute unreleased source trees.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

type module struct {
	Path, Version, Dir string
	Main               bool
	Replace            *module
}

func selected(m module, path string) (module, error) {
	if m.Replace != nil {
		m = *m.Replace
	}
	if m.Main || m.Path != path || m.Version == "" {
		return module{}, fmt.Errorf("%s must select an immutable maintained module, got %s@%s", path, m.Path, m.Version)
	}
	return m, nil
}

func atLeast(version, minimum string) bool {
	return semver.IsValid(version) && semver.Prerelease(version) == "" && semver.Compare(version, minimum) >= 0
}

func validate(modules map[string]module, consoleVersion, mcTag, mcCommit string) error {
	pkg, err := selected(modules["github.com/pgsty/silo-pkg/v3"], "github.com/pgsty/silo-pkg/v3")
	if err != nil {
		return err
	}
	if !atLeast(pkg.Version, "v3.16.1") {
		return fmt.Errorf("silo-pkg %s lacks the strict policy release; need v3.16.1 or newer", pkg.Version)
	}
	if _, err := selected(modules["github.com/minio/console"], "github.com/pgsty/silo-console"); err != nil {
		return err
	}
	if !atLeast("v"+consoleVersion, "v2.7.2") {
		return fmt.Errorf("embedded Console %s lacks the v2.7.2 release; need 2.7.2 or newer", consoleVersion)
	}
	mc, err := selected(modules["github.com/minio/mc"], "github.com/pgsty/mc")
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^RELEASE\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z$`).MatchString(mcTag) || mcTag <= "RELEASE.2026-11-09T00-00-00Z" {
		return fmt.Errorf("bundled mcli %s must be a release after 20261109", mcTag)
	}
	if len(mcCommit) != 40 || !strings.HasSuffix(mc.Version, "-"+mcCommit[:12]) {
		return fmt.Errorf("mc module %s does not match Dockerfile.goreleaser tag %s (%s)", mc.Version, mcTag, mcCommit)
	}
	return nil
}

func command(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func check() error {
	if err := os.Setenv("GOWORK", "off"); err != nil {
		return err
	}
	data, err := command("go", "list", "-mod=readonly", "-m", "-json", "github.com/pgsty/silo-pkg/v3", "github.com/minio/console", "github.com/minio/mc")
	if err != nil {
		return err
	}
	modules := make(map[string]module)
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var m module
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		modules[m.Path] = m
	}
	pkg, err := selected(modules["github.com/pgsty/silo-pkg/v3"], "github.com/pgsty/silo-pkg/v3")
	if err != nil {
		return err
	}
	if !atLeast(pkg.Version, "v3.16.1") {
		return fmt.Errorf("release blocked: select silo-pkg v3.16.1 or newer (currently %s)", pkg.Version)
	}
	console, err := selected(modules["github.com/minio/console"], "github.com/pgsty/silo-console")
	if err != nil {
		return err
	}
	if console.Dir == "" {
		data, err = command("go", "mod", "download", "-json", console.Path+"@"+console.Version)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &console); err != nil {
			return err
		}
	}
	data, err = os.ReadFile(filepath.Join(console.Dir, "web-app", "package.json"))
	if err != nil {
		return err
	}
	var metadata struct{ Version string }
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}
	data, err = os.ReadFile("Dockerfile.goreleaser")
	if err != nil {
		return err
	}
	match := regexp.MustCompile(`(?m)^ARG MC_VERSION=(\S+)\s*$`).FindSubmatch(data)
	if len(match) != 2 {
		return fmt.Errorf("Dockerfile.goreleaser must pin MC_VERSION")
	}
	tag := string(match[1])
	data, err = command("gh", "api", "repos/pgsty/mc/commits/"+tag, "--jq", ".sha")
	if err != nil {
		return err
	}
	commit := strings.TrimSpace(string(data))
	if err := validate(modules, metadata.Version, tag, commit); err != nil {
		return err
	}
	data, err = command("gh", "api", "repos/pgsty/mc/compare/d7262c2a5fbdf2b9503cc0283f1d37ae8da41baf..."+commit, "--jq", ".status")
	if err != nil {
		return err
	}
	if status := strings.TrimSpace(string(data)); status != "ahead" && status != "identical" {
		return fmt.Errorf("mcli %s does not include the access-key policy repair", tag)
	}
	fmt.Printf("Release dependencies verified: silo-pkg %s, Console %s, mcli %s (%s)\n", pkg.Version, metadata.Version, tag, commit)
	return nil
}

func main() {
	if err := check(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
