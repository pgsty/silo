# Silo Server Limits Per Tenant

For optimal production setup Silo recommends Linux kernel version 4.x and later.

## Erasure Code (Multiple Drives / Servers)

| Item                                                            | Specification |
|:----------------------------------------------------------------|:--------------|
| Maximum number of servers per cluster                           | no-limit      |
| Minimum number of servers                                       | 02            |
| Minimum number of drives per server when server count is 1      | 02            |
| Minimum number of drives per server when server count is 2 or 3 | 01            |
| Minimum number of drives per server when server count is 4      | 01            |
| Maximum number of drives per server                             | no-limit      |
| Read quorum                                                     | N/2           |
| Write quorum                                                    | N/2+1         |

## Limits of S3 API

| Item                                                                            | Specification                                                                   |
|:--------------------------------------------------------------------------------|:--------------------------------------------------------------------------------|
| Maximum number of buckets                                                       | unlimited (we recommend not beyond 500000 buckets) - see NOTE:                  |
| Maximum number of objects per bucket                                            | no-limit                                                                        |
| Maximum object size                                                             | 50 TiB                                                                          |
| Minimum object size                                                             | 0 B                                                                             |
| Maximum object size per PUT operation                                           | 5 TiB                                                                           |
| Maximum number of parts per upload                                              | 10,000                                                                          |
| Part size range                                                                 | 5 MiB to 5 TiB. Last part can be 0 B to 5 TiB                                   |
| Maximum number of parts returned per list parts request                         | 10000                                                                           |
| Maximum number of objects returned per list objects request                     | 1000                                                                            |
| Maximum number of multipart uploads returned per list multipart uploads request | 1000                                                                            |
| Maximum length for bucket names                                                 | 63                                                                              |
| Maximum length for object names                                                 | 1024                                                                            |
| Maximum length for '/' separated object name segment                            | 255                                                                             |
| Maximum number of versions per object                                           | 10000 (can be configured to higher values but we do not recommend beyond 10000) |

> NOTE: While Silo does not implement an upper boundary on buckets, cluster
> hardware has natural limits that depend on workload and scaling patterns.
> Benchmark the intended workload and size production deployments with
> operational headroom.

## List of Amazon S3 APIs not supported on Silo

We found the following APIs to be redundant or less useful outside of AWS S3. If you have a different view on any of the APIs we missed, please consider opening a [GitHub issue](https://github.com/pgsty/silo/issues) with relevant details on why Silo must implement them.

### List of Amazon S3 Bucket APIs not supported on Silo

- BucketACL (Use [bucket policies](https://silo.pgsty.com/administration/identity-access-management/policy-based-access-control/) instead)
- BucketCORS (CORS enabled by default on all buckets for all HTTP verbs, you can optionally restrict the CORS domains)
- BucketWebsite (Use [`caddy`](https://github.com/caddyserver/caddy) or [`nginx`](https://www.nginx.com/resources/wiki/))
- BucketAnalytics, BucketMetrics, BucketLogging (Use [bucket notification](https://silo.pgsty.com/administration/monitoring/bucket-notifications/) APIs)

### List of Amazon S3 Object APIs not supported on Silo

- ObjectACL (Use [bucket policies](https://silo.pgsty.com/administration/identity-access-management/policy-based-access-control/) instead)

## Object name restrictions on Silo

- Object name restrictions on Silo are governed by OS and filesystem limitations. For example object names that contain characters `^*|\/&";` are unsupported on Windows platform or any other file systems that do not support filenames with special characters.

> **This list is non exhaustive, it depends on the operating system and filesystem under use - please consult your operating system vendor for a more comprehensive list of special characters**.

Silo recommends using Linux operating system for production workloads.

- In the default (safe) object naming mode, objects must not have conflicting objects as parent objects. Applications using this behavior should change their behavior and use non-conflicting unique keys; for example, situations such as the following conflicting key patterns are not supported, and LIST operations at the collision return an empty result set.

```
PUT <bucketname>/a/b/1.txt
PUT <bucketname>/a/b
```

```
PUT <bucketname>/a/b
PUT <bucketname>/a/b/1.txt
```

  A cluster formatted with `--object-naming=extended` (or
  `MINIO_OBJECT_NAMING=extended`) supports these conflicting keys: an object
  and a prefix of the same name (`obj1` and `obj1/obj2`) are stored in
  physically separate directories, so both appear in LIST results and exact-key
  reads, writes and deletes behave independently. Be aware of the following:

  - The mode is chosen when the cluster is formatted for the first time, is
    recorded in every drive's `format.json`, and cannot be changed afterwards.
    Every node must use the same mode; drives or pools that disagree refuse to
    start. Existing safe-mode clusters cannot be migrated in place.
  - Object names on disk are escaped and carry a terminal marker (for example
    `data◊file.txt` is stored as `data␣4file.txt◊`). Tools that read raw drive
    contents, such as `mc admin inspect`, must address the encoded name.
  - Escape sequences make some names slightly longer on disk. The 1024-byte
    object name limit and the 255-byte per-segment limit still apply to the
    encoded form.
  - Replication and data movement between extended and safe mode clusters is
    not supported.
  - Keys ending with `__XLDIR__` remain reserved for directory objects, as in
    safe mode.
