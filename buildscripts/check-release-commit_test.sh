#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${script_dir}/check-release-commit.sh"
commit="0123456789abcdef0123456789abcdef01234567"
other_commit="89abcdef0123456789abcdef0123456789abcdef"
fixture="$(mktemp)"
stdout_file="$(mktemp)"
stderr_file="$(mktemp)"
trap 'rm -f "${fixture}" "${stdout_file}" "${stderr_file}"' EXIT

expect_success() {
	if ! "${checker}" "$@" >"${stdout_file}" 2>"${stderr_file}"; then
		cat "${stderr_file}" >&2
		return 1
	fi
}

expect_failure() {
	if "${checker}" "$@" >"${stdout_file}" 2>"${stderr_file}"; then
		echo "Expected release-commit check to fail: $*" >&2
		cat "${stdout_file}" >&2
		return 1
	fi
}

# run <path> <conclusion> [event] [branch] [sha] [run_number] [status]
run() {
	local path="$1" conclusion="$2"
	local event="${3:-push}" branch="${4:-main}" sha="${5:-${commit}}"
	local number="${6:-1}" status="${7:-completed}"
	local conclusion_json="\"${conclusion}\""
	[ "${conclusion}" = "null" ] && conclusion_json=null
	printf '{"path":"%s","event":"%s","head_branch":"%s","head_sha":"%s","status":"%s","conclusion":%s,"run_number":%s,"run_attempt":1}' \
		"${path}" "${event}" "${branch}" "${sha}" "${status}" "${conclusion_json}" "${number}"
}

go_ok="$(run .github/workflows/go.yml success)"
vuln_ok="$(run .github/workflows/vulncheck.yml success)"

all_green() {
	printf '[%s,%s]\n' "${go_ok}" "${vuln_ok}" >"${fixture}"
}

# Baseline: both required workflows green on a push to main.
all_green
expect_success "${commit}" "${fixture}"
grep -qF "Required workflows are green for ${commit}." "${stdout_file}"

# A manual dispatch is not evidence: it can be run from any ref.
printf '[%s,%s]\n' \
	"$(run .github/workflows/go.yml success workflow_dispatch main)" \
	"${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "no qualifying run" "${stderr_file}"

# A re-run that finally succeeded is enough; the earlier failure is history.
printf '[%s,%s,%s]\n' \
	"$(run .github/workflows/go.yml failure push main "${commit}" 1)" \
	"$(run .github/workflows/go.yml success push main "${commit}" 2)" \
	"${vuln_ok}" >"${fixture}"
expect_success "${commit}" "${fixture}"

# ...but a LATER failure must not be papered over by an earlier success.
printf '[%s,%s,%s]\n' \
	"$(run .github/workflows/go.yml success push main "${commit}" 1)" \
	"$(run .github/workflows/go.yml failure push main "${commit}" 2)" \
	"${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "Required workflow .github/workflows/go.yml did not succeed" "${stderr_file}"
grep -qF "(failure)" "${stderr_file}"

# A decoy workflow that merely calls itself "Go CI" must not satisfy the gate.
printf '[%s,%s]\n' \
	"$(run .github/workflows/decoy.yml success)" "${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "Required workflow .github/workflows/go.yml has no qualifying run" "${stderr_file}"

# A pull_request run tests GitHub's merge ref, not this commit on its own.
printf '[%s,%s]\n' \
	"$(run .github/workflows/go.yml success pull_request feature)" "${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "no qualifying run" "${stderr_file}"

# A push run on some other branch is not evidence that main accepted it.
printf '[%s,%s]\n' \
	"$(run .github/workflows/go.yml success push feature)" "${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "no qualifying run" "${stderr_file}"

# A run reporting a different head_sha must be ignored.
printf '[%s,%s]\n' \
	"$(run .github/workflows/go.yml success push main "${other_commit}")" "${vuln_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "no qualifying run" "${stderr_file}"

# Missing workflow entirely.
printf '[%s]\n' "${go_ok}" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "Required workflow .github/workflows/vulncheck.yml has no qualifying run" "${stderr_file}"

# Still running.
printf '[%s,%s]\n' "${go_ok}" \
	"$(run .github/workflows/vulncheck.yml null push main "${commit}" 1 in_progress)" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "(in_progress)" "${stderr_file}"

# Cancelled counts as not green.
printf '[%s,%s]\n' "${go_ok}" \
	"$(run .github/workflows/vulncheck.yml cancelled)" >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "(cancelled)" "${stderr_file}"

# Malformed API response.
printf '{not-json}\n' >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "Invalid workflow run response for ${commit}" "${stderr_file}"

# An empty array is a valid response that satisfies nothing.
printf '[]\n' >"${fixture}"
expect_failure "${commit}" "${fixture}"
grep -qF "Required workflow .github/workflows/go.yml has no qualifying run" "${stderr_file}"

expect_failure "not-a-commit" "${fixture}"
grep -qF "Invalid release commit" "${stderr_file}"

expect_failure "" "${fixture}"
grep -qF "Invalid release commit: <empty>" "${stderr_file}"

echo "release-commit decision tests passed"
