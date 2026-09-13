#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
cd "${repo_dir}"

fail() {
	echo "Silo rebrand verification failed: $*" >&2
	exit 1
}

require_file() {
	[ -f "$1" ] || fail "missing required file: $1"
}

require_text() {
	local file="$1"
	local text="$2"
	grep -Fq -- "${text}" "${file}" || fail "${file} does not contain: ${text}"
}

reject_text() {
	local file="$1"
	local text="$2"
	if grep -Fq -- "${text}" "${file}"; then
		fail "${file} still contains forbidden delivery text: ${text}"
	fi
}

for file in \
	.github/goreleaser.yml \
	.github/nfpm.yml \
	buildscripts/package/lifecycle_test.sh \
	buildscripts/verify-helm-migration.sh \
	Dockerfile.goreleaser \
	Dockerfile.distroless \
	dockerscripts/build-static-curl.sh \
	dockerscripts/docker-entrypoint.sh \
	helm/silo/Chart.yaml \
	helm/silo/values.yaml \
	silo.service \
	silo.env \
	silo.sysusers; do
	require_file "${file}"
done

for retired_path in \
	CNAME _config.yml index.yaml helm-reindex.sh helm/minio helm-releases \
	Dockerfile Dockerfile.cicd Dockerfile.hotfix Dockerfile.release \
	Dockerfile.release.old_cpu Dockerfile.scratch docker-buildx.sh \
	minio.service cmd/callhome.go buildscripts/upgrade-tests .github/logo.svg \
	docs/federation/lookup/bucket-lookup.png \
	docs/screenshots/Minio_Cloud_Native_Arch.jpg \
	docs/screenshots/Minio_Cloud_Native_Arch.png \
	docs/screenshots/Minio_Cloud_Native_Arch.svg \
	docs/screenshots/Architecture-diagram_distributed_8.jpg \
	docs/screenshots/Architecture-diagram_distributed_8.png \
	docs/screenshots/Architecture-diagram_distributed_8.svg \
	docs/screenshots/Architecture-diagram_distributed_16.jpg \
	docs/screenshots/Architecture-diagram_distributed_16.png \
	docs/screenshots/Architecture-diagram_distributed_16.svg \
	docs/screenshots/Architecture-diagram_distributed_nm.png \
	docs/screenshots/Example-1.jpg docs/screenshots/Example-1.png \
	docs/screenshots/Example-2.jpg docs/screenshots/Example-2.png \
	docs/screenshots/Example-3.jpg docs/screenshots/Example-3.png \
	docs/screenshots/pic1.png docs/screenshots/pic2.png \
	docs/metrics/prometheus/grafana/grafana-minio.png \
	docs/metrics/prometheus/grafana/bucket/grafana-bucket.png \
	docs/metrics/prometheus/grafana/node/grafana-node.png \
	docs/metrics/prometheus/grafana/replication/grafana-replication-cluster.png \
	docs/metrics/prometheus/grafana/replication/grafana-replication-node.png; do
	[ ! -e "${retired_path}" ] || fail "retired upstream delivery path remains: ${retired_path}"
done

require_text .github/goreleaser.yml "binary: silo"
require_text .github/goreleaser.yml 'name_template: "silo_{{ .Env.PKG_VERSION }}_{{ .Os }}_{{ .Arch }}"'
require_text .github/goreleaser.yml "sboms:"
require_text .github/goreleaser.yml "artifacts: archive"
require_text .github/goreleaser.yml "cmd: cosign"
# shellcheck disable=SC2016 # Match the literal GoReleaser template variable.
require_text .github/goreleaser.yml 'signature: "${artifact}.sigstore.json"'
require_text .github/nfpm.yml "name: silo"
require_text .github/nfpm.yml "dst: /usr/bin/silo"
require_text .github/nfpm.yml "dst: /etc/default/silo"
require_text .github/nfpm.yml "dst: /usr/lib/sysusers.d/silo.conf"
require_text buildscripts/package/lifecycle_test.sh "Silo package lifecycle checks passed"
require_text buildscripts/verify-helm-migration.sh "Silo Helm lint, render, legacy-upgrade, and package checks passed"
require_text silo.service "Conflicts=minio.service"
require_text silo.service "EnvironmentFile=-/etc/default/minio"
require_text silo.service "EnvironmentFile=-/etc/default/silo"
# shellcheck disable=SC2016 # Match the literal service environment variables.
require_text silo.service 'ExecStart=/usr/bin/silo server $MINIO_OPTS $MINIO_VOLUMES'
require_text README.md "/etc/systemd/system/silo.service.d/10-legacy-user.conf"
require_text README_ZH.md "/etc/systemd/system/silo.service.d/10-legacy-user.conf"
require_text Dockerfile.goreleaser "COPY silo /usr/bin/silo"
require_text Dockerfile.goreleaser 'CMD ["silo"]'
require_text Dockerfile.goreleaser "MC_AMD64_SHA256="
require_text Dockerfile.goreleaser "Published checksum drift"
require_text Dockerfile.distroless 'COPY --chmod=0755 silo /usr/bin/silo'
require_text Dockerfile.distroless 'ENTRYPOINT ["/usr/bin/silo"]'
require_text Dockerfile.distroless '"/usr/bin/silo", "healthcheck", "ready"'
require_text dockerscripts/build-static-curl.sh "sha256sum -c"
require_text helm/silo/Chart.yaml "name: silo"
require_text helm/silo/values.yaml "repository: pgsty/silo"
require_text helm/silo/templates/deployment.yaml "/usr/bin/docker-entrypoint.sh silo server"
require_text helm/silo/templates/statefulset.yaml "/usr/bin/docker-entrypoint.sh silo server"
require_text docs/orchestration/docker-compose/docker-compose.yaml 'http://silo{1...4}/data{1...2}'
require_text docs/resiliency/docker-compose.yaml 'http://silo{1...4}/data{1...8}'
require_text docs/distributed/DECOMMISSION.md 'systemctl restart silo'
# shellcheck disable=SC2016 # Match the literal shell variable.
require_text docs/resiliency/resiliency-tests.sh 'docker exec resiliency-silo$NODE-1'
require_text .github/workflows/release.yml "Attest downloadable release artifacts"
require_text .github/workflows/release.yml "packages_checksums.txt"
require_text .github/workflows/docker-release.yml "Attest multi-architecture image provenance"
require_text .github/workflows/docker-release.yml "index.docker.io/pgsty/silo"

# Copyright notices credit both parties with fixed terms: upstream MinIO
# development ends at its own last year, and the fork's own term starts when
# the fork did. Deriving the upstream end year from the clock would extend
# MinIO's copyright term every January.
require_text cmd/build-constants.go 'upstreamCopyrightEndYear = "2025"'
require_text cmd/build-constants.go 'forkCopyrightStartYear = "2025"'
require_text cmd/main.go 'upstreamCopyrightEndYear'
reject_text cmd/main.go 'CopyrightYear = strconv.Itoa(time.Now().Year())'
require_text NOTICE 'MinIO Project, (C) 2015-2025 MinIO, Inc.'
require_text NOTICE 'Silo Project modifications, (C) 2025-2026 PGSTY.'

# Contribution policy: no CLA, inbound=outbound, DCO sign-off enforced in CI.
require_file .github/workflows/dco.yml
require_text .github/workflows/dco.yml "Signed-off-by"
require_text CONTRIBUTING.md "developercertificate.org"
require_text CONTRIBUTING.md "No CLA"

for file in .github/nfpm.yml Dockerfile.goreleaser silo.service; do
	reject_text "${file}" "/usr/bin/minio"
	reject_text "${file}" "/usr/local/bin/minio"
done
reject_text Dockerfile.goreleaser "MINIO_UPDATE_MINISIGN_PUBKEY"
reject_text buildscripts/minio-upgrade.sh "docker system prune"
reject_text buildscripts/minio-upgrade.sh "docker volume prune"
reject_text docs/orchestration/docker-compose/docker-compose.yaml 'http://minio{1...4}'
reject_text docs/resiliency/docker-compose.yaml 'http://minio{1...4}'
reject_text docs/distributed/DECOMMISSION.md 'systemctl restart minio'
reject_text docs/resiliency/resiliency-tests.sh 'resiliency-minio'
reject_text docs/resiliency/resiliency-tests.sh 'docker system prune'
reject_text docs/resiliency/resiliency-tests.sh 'docker image prune'
reject_text docs/resiliency/resiliency-tests.sh 'docker ps -q'

if grep -Ev '^[[:space:]]*(#|$)' silo.env | grep -q '='; then
	fail "silo.env must not contain active assignments that shadow /etc/default/minio"
fi

if rg -n 'pgsty/minio:' .github/workflows Dockerfile.goreleaser helm/silo; then
	fail "an active delivery surface still publishes the frozen pgsty/minio image"
fi

# The repository and its default branch are pgsty/silo and main. The invariant
# is that the old name is never a live target, not that it is never spoken: the
# READMEs have to name it to explain the rename and to point at the archived
# artifacts, which is the opposite of stranding a reader on it. CONTRIBUTORS.md
# also quotes historical issue titles.
#
# So two rules. First, no live URL may resolve to the old repository anywhere,
# READMEs and CONTRIBUTORS.md included.
old_repo_pattern='pgsty/minio(\.git)?([^[:alnum:]_.-]|$)'
stale_repo_url="$(rg -n -e "github\.com/${old_repo_pattern}" -e "hub\.docker\.com/r/${old_repo_pattern}" \
	--glob '!.git/**' --glob '!dist/**' \
	--glob '!SILO_REBRANDING_MIGRATION.md' \
	--glob '!buildscripts/rebrand-guard/compat-baseline.json' . |
	sed 's#^\./##' | grep -v '^buildscripts/verify-rebrand\.sh:' || true)"
if [ -n "${stale_repo_url}" ]; then
	printf '%s\n' "${stale_repo_url}" >&2
	fail "a link still resolves to the pre-rename pgsty/minio repository"
fi

# Second, the bare name may only appear where it is deliberate: the pinned
# pre-rebrand image digest in the upgrade test, the two guards that refuse a
# legacy image, the two READMEs that document the rename and the archived
# minio branch, and historical issue titles in CONTRIBUTORS.md.
repo_guard_allowlist='^(buildscripts/minio-upgrade\.sh|buildscripts/verify-rebrand\.sh|buildscripts/helm-migration-guard/main\.go|README\.md|README_ZH\.md|CONTRIBUTORS\.md):'
stale_repo="$(rg -n "${old_repo_pattern}" --glob '!.git/**' --glob '!dist/**' \
	--glob '!SILO_REBRANDING_MIGRATION.md' \
	--glob '!buildscripts/rebrand-guard/compat-baseline.json' . |
	sed 's#^\./##' | grep -Ev "${repo_guard_allowlist}" || true)"
if [ -n "${stale_repo}" ]; then
	printf '%s\n' "${stale_repo}" >&2
	fail "a source reference still names the pre-rename pgsty/minio repository"
fi

stale_branch="$(rg -n 'pgsty/silo/(blob/|tree/|raw/)?master' \
	--glob '!.git/**' --glob '!dist/**' . || true)"
if [ -n "${stale_branch}" ]; then
	printf '%s\n' "${stale_branch}" >&2
	fail "a link still targets the retired master branch; raw and Actions URLs do not follow a branch rename"
fi

for workflow in .github/workflows/go.yml .github/workflows/vulncheck.yml; do
	if rg -q '^\s+- master$' "${workflow}"; then
		fail "${workflow} still filters on master and would go silently dormant on main"
	fi
	require_text "${workflow}" "      - main"
done

network_hits="$(rg -n --glob '*.go' --glob '!**/*_test.go' \
	'https?://[^"`[:space:]]*(dl\.min\.io|subnet\.min\.io|api\.min\.io|slack\.min\.io|play\.min\.io)' \
	cmd internal || true)"
network_hits="$(printf '%s\n' "${network_hits}" | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*//' || true)"
if [ -n "${network_hits}" ]; then
	printf '%s\n' "${network_hits}" >&2
	fail "runtime code still contains an upstream MinIO service endpoint"
fi

require_text cmd/build-constants.go 'MinioReleaseBaseURL = ""'
require_text cmd/globals.go "globalInplaceUpdateDisabled = true"
reject_text cmd/globals.go "subnetAdminPublicKey"
reject_text cmd/admin-handlers.go "getSubnetAdminPublicKey"

echo "Silo delivery and runtime rebrand checks passed"
