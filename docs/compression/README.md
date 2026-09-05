# Compression Guide

Silo server allows streaming compression to ensure efficient disk space usage.
Compression happens inflight, i.e objects are compressed before being written to disk(s).
Silo uses [`klauspost/compress/s2`](https://github.com/klauspost/compress/tree/master/s2)
streaming compression due to its stability and performance.

This algorithm is specifically optimized for machine generated content.
Write throughput is typically at least 500MB/s per CPU core,
and scales with the number of available CPU cores.
Decompression speed is typically at least 1GB/s.

This means that in cases where raw IO is below these numbers
compression will not only reduce disk usage but also help increase system throughput.
Typically, enabling compression on spinning disk systems
will increase speed when the content can be compressed.

## Get Started

### 1. Prerequisites

Install Silo - [Silo Quickstart Guide](https://silo.pgsty.com/operations/deployments/baremetal-deploy-minio-on-redhat-linux/).

### 2. Run Silo with compression

Compression can be enabled by updating the `compress` config settings for Silo server config.
Config `compress` settings take extensions and mime-types to be compressed.

```bash
~ mc admin config get mysilo compression
compression extensions=".txt,.log,.csv,.json,.tar,.xml,.bin" mime_types="text/*,application/json,application/xml"
```

Default config includes most common highly compressible content extensions and mime-types.

```bash
~ mc admin config set mysilo compression extensions=".pdf" mime_types="application/pdf"
```

To show help on setting compression config values.

```bash
~ mc admin config set mysilo compression
```

To enable compression for all content, no matter the extension and content type
(except for the default excluded types) set BOTH extensions and mime types to empty.

```bash
~ mc admin config set mysilo compression enable="on" extensions="" mime_types=""
```

The compression settings may also be set through environment variables.
When set, environment variables override the defined `compress` config settings in the server config.

```bash
export MINIO_COMPRESSION_ENABLE="on"
export MINIO_COMPRESSION_EXTENSIONS=".txt,.log,.csv,.json,.tar,.xml,.bin"
export MINIO_COMPRESSION_MIME_TYPES="text/*,application/json,application/xml"
```

> [!NOTE]
> To enable compression for all content when using environment variables, set either or both of the extensions and MIME types to `*` instead of an empty string:
> ```bash
> export MINIO_COMPRESSION_ENABLE="on"
> export MINIO_COMPRESSION_EXTENSIONS="*"
> export MINIO_COMPRESSION_MIME_TYPES="*"
> ```

### 3. Compression + Encryption

Combining encryption and compression is not safe in all setups.
This is particularly so if the compression ratio of your content reveals information about it.
See [CRIME TLS](https://en.wikipedia.org/wiki/CRIME) as an example of this.

Therefore, compression is disabled when encrypting by default, and must be enabled separately.

Evaluate the security and resource impact in a staging environment before
deciding whether this feature combination is safe for your setup.

To enable compression+encryption use:

```bash
~ mc admin config set mysilo compression allow_encryption=on
```

Or alternatively through the environment variable `MINIO_COMPRESSION_ALLOW_ENCRYPTION=on`.

SSE-C objects are excluded from compression even with `allow_encryption=on`.
Replication ships an SSE-C object as raw ciphertext, because the server never holds the
customer key, and the compression metadata is not carried over the wire. A compressed
SSE-C object would therefore replicate to a replica that decrypts to a compressed stream.
`allow_encryption` still applies to SSE-S3 and SSE-KMS, where the server owns the key and
decompresses before replicating.

### 4. Excluded Types

- Already compressed objects are not fit for compression since they do not have compressible patterns.
Such objects do not produce efficient [`LZ compression`](https://en.wikipedia.org/wiki/LZ77_and_LZ78)
which is a fitness factor for a lossless data compression.

Pre-compressed input typically compresses in excess of 2GiB/s per core,
so performance impact should be minimal even if precompressed data is re-compressed.
Decompressing incompressible data has no significant performance impact.

Below is a list of common files and content-types which are typically not suitable for compression.

- Extensions

 | `gz`  | (GZIP)      |
 | `bz2` | (BZIP2)     |
 | `rar` | (WinRAR)    |
 | `zip` | (ZIP)       |
 | `7z`  | (7-Zip)     |
 | `xz`  | (LZMA)      |
 | `mp4` | (MP4)       |
 | `mkv` | (MKV media) |
 | `mov` | (MOV)       |

- Content-Types

 | `video/*`                |
 | `audio/*`                |
 | `application/zip`        |
 | `application/x-gzip`     |
 | `application/zip`        |
 | `application/x-bz2`      |
 | `application/x-compress` |
 | `application/x-xz`       |

All files with these extensions and mime types are excluded from compression,
even if compression is enabled for all types.

## To test the setup

To test this setup, practice put calls to the server using `mc` and use `mc ls` on
the data directory to view the size of the object.

## Explore Further

- [Use `mc` with Silo Server](https://silo.pgsty.com/reference/minio-mc/)
- [Use `aws-cli` with Silo Server](https://silo.pgsty.com/integrations/aws-cli-with-minio/)
- [Use `minio-go` SDK with Silo Server](https://silo.pgsty.com/developers/go/minio-go/)
- [The Silo documentation website](https://silo.pgsty.com/docs/)
