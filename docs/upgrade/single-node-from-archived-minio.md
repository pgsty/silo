# Single-node migration from MinIO to SILO

The maintained migration procedure and single-node case study belong to the
companion documentation site:

- [English migration guide](https://silo.pgsty.com/compatibility/migration/)
- [中文迁移指南](https://silo.pgsty.com/zh/compatibility/migration/)

Follow the guide's deployment checks, consistent backup procedure, verification
steps and [rollback requirements](https://silo.pgsty.com/compatibility/migration/#rollback).
Modern single-node/single-drive erasure deployments are distinct from the retired
filesystem backend; historical FS installations need the
[filesystem migration procedure](https://silo.pgsty.com/operations/deployments/baremetal-migrate-fs-gateway/).

Paris Y. ([@yupoet](https://github.com/yupoet)) contributed the production report in
[#228](https://github.com/pgsty/silo/pull/228), describing a 2026-09-26 forward
upgrade to SILO 20260916. The
[original report](https://github.com/pgsty/silo/blob/fec1e0804a7493f68ba409345da8e90f0f4d5fbb/docs/upgrade/single-node-from-archived-minio.md)
is retained as historical evidence. Its FS terminology and unconditional
metadata, healthcheck, multipart-listing and rollback claims are superseded by
the maintained guide. The report is not independent verification of a newer
release, a complete historical-object audit, or a reverse downgrade.
