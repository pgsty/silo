# Silo Helm Chart

This chart installs Silo, an independently maintained, S3-compatible object
storage server, on Kubernetes. It supports standalone and distributed modes.
The chart and server are licensed under AGPL-3.0-or-later.

## Prerequisites

- Kubernetes 1.19 or later
- Helm 3
- A PersistentVolume provisioner unless `persistence.enabled=false`

## Install

From this repository:

```bash
helm install silo ./helm/silo \
  --namespace silo --create-namespace \
  --set rootUser=silo-admin \
  --set rootPassword='replace-with-a-long-random-secret'
```

For a disposable standalone installation:

```bash
helm install silo ./helm/silo \
  --namespace silo --create-namespace \
  --set mode=standalone \
  --set replicas=1 \
  --set persistence.enabled=false \
  --set resources.requests.memory=512Mi \
  --set rootUser=silo-admin \
  --set rootPassword='replace-with-a-long-random-secret'
```

The default server image is `docker.io/pgsty/silo` (which contains the `silo`
server, `mcli`, and an `mc` client compatibility symlink, without a `minio`
server binary). Post-install resource jobs use `mcImage` (`docker.io/pgsty/mc`)
by default.

## Compatibility contract

The product and delivery names are Silo, while established interfaces remain
compatible:

- `MINIO_*` environment variables and existing values keys are unchanged.
- `/minio/*` API and metrics routes are unchanged.
- `minio_*` Prometheus metrics and `x-minio-*` protocol headers are unchanged.
- Existing storage, including `.minio.sys`, is used without conversion.
- `nameOverride`, `fullnameOverride`, and `serviceAccount.name` can pin existing
  Kubernetes resource identities during an upgrade.

New installations default to Silo resource names and the `silo-sa` service
account.

## Upgrade an existing release

Do not upgrade an existing release without first pinning its current resource
names. Export the complete values and render the candidate chart offline:

```bash
helm get values my-release -n my-namespace -a > values.before-silo.yaml
SILO_TAG='<published-silo-release-tag>'
MCLI_TAG='<published-mcli-release-tag>'

helm template my-release ./helm/silo \
  -n my-namespace \
  -f values.before-silo.yaml \
  --set nameOverride=minio \
  --set fullnameOverride=my-existing-fullname \
  --set serviceAccount.name=minio-sa \
  --set image.repository=pgsty/silo \
  --set mcImage.repository=pgsty/mc \
  --set-string image.tag="${SILO_TAG}" \
  --set-string mcImage.tag="${MCLI_TAG}" \
  > rendered.silo.yaml
```

Compare the old and new manifests. Stop if the candidate changes immutable
selectors, StatefulSet or Service identity, PVC names, Secrets, or storage
mounts. After review, upgrade the chart and image together:

```bash
SILO_TAG='<published-silo-release-tag>'
MCLI_TAG='<published-mcli-release-tag>'
helm upgrade my-release ./helm/silo \
  -n my-namespace \
  -f values.before-silo.yaml \
  --set nameOverride=minio \
  --set fullnameOverride=my-existing-fullname \
  --set serviceAccount.name=minio-sa \
  --set image.repository=pgsty/silo \
  --set mcImage.repository=pgsty/mc \
  --set-string image.tag="${SILO_TAG}" \
  --set-string mcImage.tag="${MCLI_TAG}"
```

Rollback is chart-level: use `helm rollback`, not an image-only downgrade. The
new chart invokes `silo server`; an old image does not provide that executable.
The new image accepts a legacy first argv token of `minio` only to support old
chart commands during the forward migration.

When upgrading an existing Silo release to `RELEASE.2026-11-12T00-00-00Z` (chart
`7.0.5`):

- `helm upgrade --reuse-values` keeps the previously saved `image.tag` and
  `mcImage.tag`; pass `--set-string image.tag=RELEASE.2026-11-12T00-00-00Z` and
  `--set-string mcImage.tag=RELEASE.2026-11-12T00-00-00Z` explicitly.
- When upgrading from `20261109`, avoid editing service accounts on un-upgraded
  pods or peer sites until every node runs `20261112`, drain active batch jobs,
  and pause pool decommission or concurrent multi-pool writes during rolling pod
  restarts so lock-ordering and cross-pool `null`-version Object Lock checks
  apply uniformly.
- When upgrading from `20261026` or earlier, drain or cancel active batch jobs
  before upgrading; `20261026` cannot resume submitter-bound batch manifests on
  downgrade, single-pool clusters whose erasure sets do not all share the same
  pods/hosts require a drained stop-all upgrade rather than a rolling pod
  restart, and `POST ?restore` returns `503` while mixed versions are serving.
  See the [20261109 release notes](https://silo.pgsty.com/blog/release/silo-20261109/#upgrade)
  and [server compatibility notes](https://silo.pgsty.com/compatibility/server/).

## Persistence and TLS

The default PersistentVolumeClaim mounts at `/export`. Use an existing claim
with:

```bash
helm install silo ./helm/silo --set persistence.existingClaim=PVC_NAME
```

Create a TLS Secret containing `private.key` and `public.crt`, then set:

```bash
helm upgrade --install silo ./helm/silo \
  --set tls.enabled=true \
  --set tls.certSecret=silo-tls
```

Additional trusted CAs can be supplied through `trustedCertsSecret`.

## Existing Secrets and post-install resources

Set `existingSecret` to a Secret containing `rootUser` and `rootPassword`.
Buckets, users, policies, service accounts, and custom commands can be created
with the existing `buckets`, `users`, `policies`, `svcaccts`, and
`customCommands` values. The post-install job uses `mcli` through its `mc`
compatibility command. New custom commands should target `mysilo`; the legacy
`myminio` target remains registered so existing values continue to work.

## Configuration

See [values.yaml](./values.yaml) for the complete values surface and the
[Silo documentation](https://silo.pgsty.com/) for server operations.

To uninstall the chart:

```bash
helm uninstall silo -n silo
```

PersistentVolumeClaims may remain after uninstall; inspect them before any
manual deletion.
