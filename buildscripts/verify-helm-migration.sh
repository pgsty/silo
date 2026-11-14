#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
baseline_commit="${HELM_LEGACY_COMMIT:-d88f46cce}"
helm_image="${HELM_IMAGE:-alpine/helm:3.18.6@sha256:c6d8088ddb279625a2e1ca3b08b22c18c946d1f65c8b810f28f1597435a1134c}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/silo-helm.XXXXXX")"

cleanup() {
	rm -rf "${work_dir}"
}
trap cleanup EXIT

cd "${repo_dir}"
git cat-file -e "${baseline_commit}^{commit}"
git archive "${baseline_commit}" helm/minio | tar -x -C "${work_dir}"

if command -v helm >/dev/null 2>&1; then
	new_chart="${repo_dir}/helm/silo"
	old_chart="${work_dir}/helm/minio"
	output_dir="${work_dir}"
	helm_run() {
		helm "$@"
	}
else
	command -v docker >/dev/null 2>&1 || {
		echo "helm or docker is required" >&2
		exit 1
	}
	new_chart=/repo/helm/silo
	old_chart=/check/helm/minio
	output_dir=/check
	helm_run() {
		docker run --rm \
			-v "${repo_dir}:/repo:ro" \
			-v "${work_dir}:/check" \
			"${helm_image}" "$@"
	}
fi

helm_run lint "${new_chart}"
helm_run template silo "${new_chart}" \
	--namespace silo \
	--set rootUser=silo-admin \
	--set rootPassword=test-password-123456 >/dev/null
helm_run template silo "${new_chart}" \
	--namespace silo \
	--set mode=standalone \
	--set replicas=1 \
	--set persistence.enabled=false \
	--set rootUser=silo-admin \
	--set rootPassword=test-password-123456 >/dev/null

# Exercise optional templates that the default render leaves dormant.
helm_run template silo-all "${new_chart}" \
	--namespace silo \
	--set rootUser=silo-admin \
	--set rootPassword=test-password-123456 \
	--set tls.enabled=true \
	--set tls.certSecret=silo-tls \
	--set trustedCertsSecret=silo-trusted-ca \
	--set ingress.enabled=true \
	--set consoleIngress.enabled=true \
	--set networkPolicy.enabled=true \
	--set podDisruptionBudget.enabled=true \
	--set metrics.serviceMonitor.enabled=true \
	--set metrics.serviceMonitor.includeNode=true \
	--set 'buckets[0].name=chart-test' \
	--set 'buckets[0].policy=none' \
	--set 'buckets[0].purge=false' >/dev/null

# Existing values commonly address the historical myminio target. Render the
# custom-command path explicitly so both the new and compatibility aliases are
# protected by the release gate rather than only by a source-text assertion.
custom_render="${work_dir}/custom-command.yaml"
helm_run template silo-custom "${new_chart}" \
	--namespace silo \
	--set rootUser=silo-admin \
	--set rootPassword=test-password-123456 \
	--set-string 'customCommands[0].command=admin info myminio' \
	--show-only templates/configmap.yaml >"${custom_render}"
for expected in \
	'alias set mysilo' \
	'alias set myminio' \
	'runCommand admin info myminio'; do
	grep -F -- "${expected}" "${custom_render}" >/dev/null || {
		echo "rendered custom command is missing: ${expected}" >&2
		exit 1
	}
done

old_render="${work_dir}/legacy.yaml"
new_render="${work_dir}/candidate.yaml"
helm_run template my-release "${old_chart}" \
	--namespace my-namespace \
	--set rootUser=legacy-admin \
	--set rootPassword=legacy-password-123456 >"${old_render}"
helm_run template my-release "${new_chart}" \
	--namespace my-namespace \
	-f "${old_chart}/values.yaml" \
	--set rootUser=legacy-admin \
	--set rootPassword=legacy-password-123456 \
	--set nameOverride=minio \
	--set fullnameOverride=my-release-minio \
	--set serviceAccount.name=minio-sa \
	--set image.repository=pgsty/silo \
	--set mcImage.repository=pgsty/silo \
	--set-string image.tag=RELEASE.2026-08-04T00-00-00Z \
	--set-string mcImage.tag=RELEASE.2026-08-04T00-00-00Z >"${new_render}"

go run ./buildscripts/helm-migration-guard "${old_render}" "${new_render}"

# The templates deploy values.image.tag, not appVersion; a release must move both.
chart_version="$(sed -n 's/^version: *//p' helm/silo/Chart.yaml)"
app_version="$(sed -n 's/^appVersion: *//p' helm/silo/Chart.yaml)"
image_tag="$(sed -n '/^image:/,/^[^ ]/s/^  tag: *//p' helm/silo/values.yaml)"
if [ -z "${app_version}" ] || [ "${image_tag}" != "${app_version}" ]; then
	echo "helm/silo: image.tag '${image_tag}' must equal appVersion '${app_version}'" >&2
	exit 1
fi
if [ -n "${RELEASE_TAG:-}" ] && [ "${image_tag}" != "${RELEASE_TAG}" ]; then
	echo "helm/silo: image.tag '${image_tag}' must equal RELEASE_TAG '${RELEASE_TAG}'" >&2
	exit 1
fi

helm_run package "${new_chart}" --destination "${output_dir}" >/dev/null
test -s "${work_dir}/silo-${chart_version}.tgz"
if find "${work_dir}" -maxdepth 1 -type f -name 'minio-*.tgz' | grep -q .; then
	echo "Helm packaging emitted a legacy MinIO chart name" >&2
	exit 1
fi

echo "Silo Helm lint, render, legacy-upgrade, and package checks passed"
