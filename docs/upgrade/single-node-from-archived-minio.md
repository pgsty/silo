# Upgrading a Single-Node Deployment from the Archived MinIO Community Edition

The MinIO community edition repository was archived on 2026-04-25 and its binary
distribution channels (`dl.min.io`, the Docker Hub tags, quay.io) were withdrawn
afterwards. Operators still running the final community release need a documented,
validated path forward. This guide records a real-world, single-node upgrade from
`RELEASE.2025-10-15T17-29-55Z` (the last community release) to Silo
`RELEASE.2026-09-16T00-00-00Z`, performed in production on 2026-09-26.

The [compatibility audit](https://silo.pgsty.com/compatibility/server/) covers
the server behavior changes but does not specifically address the
single-node/single-drive (FS mode) case. This document fills that gap with
field data.

## Validated environment

- Single node, single drive: `server /data` in FS mode, running under Docker Compose
- Root credentials only — no IAM sub-users, no OIDC, no notification targets, no reverse proxy
- ~5,900 objects / ~34,000 stored chunks accumulated over 15 months on the source version
- Source: `RELEASE.2025-10-15T17-29-55Z` → target: `RELEASE.2026-09-16T00-00-00Z`

## Why this is a low-risk swap for standalone deployments

- **Zero data migration.** `.minio.sys`, erasure metadata, bucket/object layout and
  encryption formats keep their names and schemas; the existing data volume is opened
  in place, with no copy and no metadata rewrite.
- **Single nodes are unaffected by the removed private `ReadMultiple` storage REST
  call** — that only constrains mixed-version multi-node clusters.
- **The IAM/password-policy tightening does not apply** to plain root-credential
  standalone setups (no sub-users, no OIDC, no bucket policies in use).

## Procedure

1. **Back up the data volume first** (tar the volume or snapshot the disk). Even with
   a compatible format, an upgrade window is the worst time to discover your only
   copy is damaged.
2. **Pin the exact target image tag** in your deployment tooling. Floating tags make
   both upgrades and rollbacks ambiguous.
3. **Stop dependent services before swapping the storage container**, so no writes
   race the restart.
4. **Recreate the storage container with the Silo image, keeping the data volume
   unchanged.** Compatibility notes:
   - `minio server …` invocations translate transparently; the official container
     entrypoint handles the rename.
   - Healthchecks that run `curl -f /minio/health/live` inside the container work
     out of the box with the official images (curl is bundled). If you build custom
     images, remember to include curl — the upstream release images shipped a static
     curl, minimal bases may not have one.
5. **Verify in layers**:
   - Startup log: expect zero errors. Watch specifically for hardening rejections —
     Silo refuses malformed historical objects (poisoned metadata, invalid erasure
     geometry) that older code tolerated; such objects need manual remediation
     before they will serve again.
   - `GET /minio/health/live` and `/minio/health/ready` → 200.
   - Application-level S3 smoke: upload → read back → delete, through the real client.

## Observed results (2026-09-26 field run)

- In-place upgrade with zero migration steps; the 15-month-old data volume opened
  with no errors and **no objects were rejected by the new hardening**.
- A full application regression against the storage (multipart upload, object read
  by a parser service, listing, deletion) passed end to end.
- **Rollback path is image-swap only** (same on-disk schema), but note we did not
  exercise a reverse downgrade in production. Our evidence is a staged forward
  migration — the same data volume was opened read-write by three engine builds
  in sequence (`2025-09` → `2025-10` → `2026-09`) with no format intervention —
  plus the documented schema retention. Keep the previous image available locally:
  registry tags you depend on may disappear, as the community tags already have.

## Post-upgrade behavior changes to check

These did not affect the validated standalone setup, but review them against your
own clients before upgrading:

- **TLS defaults changed** across 20260903/20260916 — verify clients if you serve TLS
  directly from the storage node or front it with older proxies/identity providers.
- **`If-Match` on `DeleteObject`** was ignored in 20260903 and is enforced in 20260916.
- **Multipart listing is capped at 1,000 entries** per request in newer releases.
- `MINIO_API_TRUSTED_PROXIES` still defaults to trusting every proxy header; set it
  explicitly if the node sits behind a proxy.
