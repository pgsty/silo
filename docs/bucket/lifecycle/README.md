# Bucket Lifecycle Configuration Quickstart Guide [![Docker Pulls](https://img.shields.io/docker/pulls/pgsty/silo.svg?maxAge=604800)](https://hub.docker.com/r/pgsty/silo/)

Enable object lifecycle configuration on buckets to setup automatic deletion of objects after a specified number of days or a specified date.

## 1. Prerequisites

- Install Silo - [Silo Quickstart Guide](https://silo.pgsty.com/operations/deployments/baremetal-deploy-minio-on-redhat-linux/).
- Install `mc` - [mc Quickstart Guide](https://silo.pgsty.com/reference/minio-mc/#quickstart)

## 2. Enable bucket lifecycle configuration

- Create a bucket lifecycle configuration which expires the objects under the prefix `old/` on `2020-01-01T00:00:00.000Z` date and the objects under `temp/` after 7 days.
- Enable bucket lifecycle configuration using `mc`:

```sh
$ mc ilm import play/testbucket <<EOF
{
    "Rules": [
        {
            "Expiration": {
                "Date": "2020-01-01T00:00:00.000Z"
            },
            "ID": "OldPictures",
            "Filter": {
                "Prefix": "old/"
            },
            "Status": "Enabled"
        },
        {
            "Expiration": {
                "Days": 7
            },
            "ID": "TempUploads",
            "Filter": {
                "Prefix": "temp/"
            },
            "Status": "Enabled"
        }
    ]
}
EOF
```

```
Lifecycle configuration imported successfully to `play/testbucket`.
```

- List the current settings

```
$ mc ilm ls play/testbucket
     ID     |  Prefix  |  Enabled   | Expiry |  Date/Days   |  Transition  |    Date/Days     |  Storage-Class   |       Tags
------------|----------|------------|--------|--------------|--------------|------------------|------------------|------------------
OldPictures |   old/   |    ✓       |  ✓     |  1 Jan 2020  |     ✗        |                  |                  |
------------|----------|------------|--------|--------------|--------------|------------------|------------------|------------------
TempUploads |  temp/   |    ✓       |  ✓     |   7 day(s)   |     ✗        |                  |                  |
------------|----------|------------|--------|--------------|--------------|------------------|------------------|------------------
```

## 3. Activate ILM versioning features

This will only work with a versioned bucket, take a look at [Bucket Versioning Guide](https://silo.pgsty.com/administration/object-management/object-versioning/) for more understanding.

### 3.1 Automatic removal of non current objects versions

A non-current object version is a version which is not the latest for a given object. It is possible to set up an automatic removal of non-current versions when a version becomes older than a given number of days.

e.g., To scan objects stored under `user-uploads/` prefix and remove versions older than one year.

```
{
    "Rules": [
        {
            "ID": "Removing all old versions",
            "Filter": {
                "Prefix": "users-uploads/"
            },
            "NoncurrentVersionExpiration": {
                "NoncurrentDays": 365
            },
            "Status": "Enabled"
        }
    ]
}
```

This JSON rule is equivalent to the following compatible `mc` command:
```
mc ilm rule add --noncurrent-expire-days 365 --prefix "user-uploads/" mysilo/mydata
```

### 3.2 Automatic removal of noncurrent versions keeping only most recent ones after noncurrent days

It is possible to configure automatic removal of older noncurrent versions keeping only the most recent `N` using `NewerNoncurrentVersions`.

e.g, To remove noncurrent versions of all objects keeping the most recent 5 noncurrent versions under the prefix `user-uploads/` 30 days after they become noncurrent ,

```
{
    "Rules": [
        {
            "ID": "Keep only most recent 5 noncurrent versions",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "users-uploads/"
            },
            "NoncurrentVersionExpiration": {
                "NewerNoncurrentVersions": 5,
                "NoncurrentDays": 30
            }
        }
    ]
}
```

This JSON rule is equivalent to the following compatible `mc` command:
```
mc ilm rule add --noncurrent-expire-days 30 --noncurrent-expire-newer 5 --prefix "user-uploads/" mysilo/mydata
```

#### 3.2.a Automatic removal of noncurrent versions keeping only most recent ones immediately (Silo only extension)

This is available only on Silo as an extension to the NewerNoncurrentVersions feature. The following rule makes it possible to remove older noncurrent versions
of objects under the prefix `user-uploads/` as soon as there are more than `N` noncurrent versions of an object.

```
{
    "Rules": [
        {
            "ID": "Keep only most recent 5 noncurrent versions",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "users-uploads/"
            },
            "NoncurrentVersionExpiration": {
                "NewerNoncurrentVersions": 5
            }
        }
    ]
}
```
Note: This rule has an implicit zero NoncurrentDays, which makes the expiry of those 'extra' noncurrent versions immediate.

#### 3.2.b Automatic removal of all versions (Silo only extension)

This is available only on Silo as an extension to the Expiration feature. The following rule makes it possible to remove all versions of an object under
the prefix `user-uploads/` as soon as the latest object satisfies the expiration criteria. 

> NOTE: If the latest object is a delete marker then filtering based on `Filter.Tags` is ignored and 
> if the DELETE marker modTime satisfies the `Expiration.Days` then all versions of the object are 
> immediately purged.

```
{
    "Rules": [
        {
            "ID": "Purge all versions of an expired object",
            "Status": "Enabled",
            "Filter": {
                "Prefix": "users-uploads/"
            },
            "Expiration": {
                "Days": 7,
                "ExpiredObjectAllVersions": true
            }
        }
    ]
}
```

### 3.3 Automatic removal of delete markers with no other versions

When an object has only one version as a delete marker, the latter can be automatically removed after a certain number of days using the following configuration:

```
{
    "Rules": [
        {
            "ID": "Removing all delete markers",
            "Expiration": {
                "ExpiredObjectDeleteMarker": true
            },
            "Status": "Enabled"
        }
    ]
}
```

## 4. Enable ILM transition feature

In Erasure mode, Silo supports tiering to public cloud providers such as GCS, AWS and Azure as well as to other Silo clusters via the ILM transition feature. This will allow transitioning of older objects to a different cluster or the public cloud by setting up transition rules in the bucket lifecycle configuration. This feature enables applications to optimize storage costs by moving less frequently accessed data to a cheaper storage without compromising accessibility of data.

To transition objects in a bucket to a destination bucket on a different cluster, applications need to specify a transition tier defined on Silo instead of storage class while setting up the ILM lifecycle rule.

> To create a transition tier for transitioning objects to a prefix `testprefix` in `azurebucket` on Azure blob using `mc`:

```
 mc admin tier add azure source AZURETIER --endpoint https://blob.core.windows.net --access-key AZURE_ACCOUNT_NAME --secret-key AZURE_ACCOUNT_KEY  --bucket azurebucket --prefix testprefix1/
```

> The admin user running this command needs the "admin:SetTier" and "admin:ListTier" permissions if not running as root.

Using above tier, set up a lifecycle rule with transition:

```
 mc ilm add --expiry-days 365 --transition-days 45 --storage-class "AZURETIER" mysilo/srcbucket
```

Note: In the case of S3, it is possible to create a tier from Silo running in EC2 to S3 using AWS role attached to EC2 as credentials instead of accesskey/secretkey:

```
mc admin tier add s3 source S3TIER --bucket s3bucket --prefix testprefix/ --use-aws-role
```

Once transitioned, GET or HEAD on the object will stream the content from the transitioned tier. In the event that the object needs to be restored temporarily to the local cluster, the AWS [RestoreObject API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html) can be utilized.

```
aws s3api restore-object --bucket srcbucket \
--key object \
--restore-request Days=3
```

### 4.1 Monitoring transition events

`s3:ObjectTransition:Complete` and `s3:ObjectTransition:Failed` events can be used to monitor transition events between the source cluster and transition tier. To watch lifecycle events, you can enable bucket notification on the source bucket with `mc event add`  and specify `--event ilm` flag.

Note that transition event notification is a Silo extension.

## 5. Access-based tiering between server pools

Silo can move frequently read objects to a faster server pool and return them
to a slower pool after they become idle. This is different from remote ILM
transition: the object remains a native local object and all versions move
together.

Access tiering requires at least two server pools. Pool indices follow the
order on the server command line:

~~~sh
silo server /srv/nvme{1...4} /srv/hdd{1...8}
#             pool 0 (fast)   pool 1 (slow)
~~~

Server pools are erasure-coding expansion units, not individual drives. Each
pool should consist of internally homogeneous media.

The feature is disabled by default. Configure the topology and safety limits
with `mc admin config set`; ILM is a dynamic subsystem, so this applies without
a restart. Environment variables (`MINIO_ILM_ACCESS_TIERING`,
`MINIO_ILM_ACCESS_POOLS`, `MINIO_ILM_ACCESS_MAX_SIZE`,
`MINIO_ILM_ACCESS_PROMOTE_WATERMARK`, `MINIO_ILM_ACCESS_BIN_WIDTH`,
`MINIO_ILM_ACCESS_BINS`, `MINIO_ILM_ACCESS_FLUSH`,
`MINIO_ILM_ACCESS_MIN_RESIDENCY`, `MINIO_ILM_ACCESS_WORKERS`,
`MINIO_ILM_ACCESS_MAX_TRACKED`) are read at process start and override the
stored config.

~~~sh
mc admin config set local ilm \
  access_tiering=on \
  access_pools="0,1" \
  access_max_size="2TiB" \
  access_promote_watermark=85 \
  access_bin_width=1m \
  access_bins=12 \
  access_flush=1m \
  access_min_residency=24h \
  access_workers=10 \
  access_max_tracked=1000000
~~~

The pool list is ordered hottest to coldest. With three or more pools,
promotion always targets the first index and demotion always targets the last;
intermediate pools are not hop targets. An access_max_size value of zero means
no cluster-wide logical-byte cap. Promotion also stops when the hottest pool
reaches access_promote_watermark.

New PUTs still land via the usual free-space pool picker; they are not steered
onto the cold pool. Size the capacity pool larger than the hot pool so new
objects tend to land there.

Add an AccessTransition to the bucket lifecycle XML:

~~~xml
<LifecycleConfiguration>
  <AccessTierQuota>500GiB</AccessTierQuota>
  <Rule>
    <ID>hot-logs</ID>
    <Status>Enabled</Status>
    <Filter>
      <And>
        <Prefix>logs/</Prefix>
        <ObjectSizeGreaterThan>65536</ObjectSizeGreaterThan>
      </And>
    </Filter>
    <AccessTransition>
      <Window>10m</Window>
      <PromoteAfterAccesses>100</PromoteAfterAccesses>
      <DemoteAfterAccesses>5</DemoteAfterAccesses>
      <DemoteAfterIdle>24h</DemoteAfterIdle>
    </AccessTransition>
  </Rule>
</LifecycleConfiguration>
~~~

This promotes a matching object after 100 successful GETs in 10 minutes. An
object becomes eligible to return to the coldest configured pool only after
access tiering has already moved it (the `x-minio-internal-ilm-atier` stamp),
it has stayed put for the server-wide minimum residency, it has been idle at
least 24 hours, and it has no more than 5 GETs in the window. Objects that
landed on the hot pool via a normal PUT never demote. Prefix, tag, and
object-size lifecycle filters are honored.

Access-based moves are a parallel path: they are not lifecycle `Eval` actions
and do not appear in S3 prediction headers. If the same object is also due
for age-based remote `Transition` or expiry, that scanner action wins and
demotion discovery is skipped for that pass; promotions still run from the
GET tracker. Site replication copies expiry rules only, same as remote
Transition, so AccessTransition stays local to the cluster.

AccessTierQuota is an optional bucket-wide cap. Promotion checks, in order:

1. hot-pool used percentage;
2. cluster-wide access_max_size;
3. bucket AccessTierQuota.

Demotion is not blocked by these caps and is processed before promotion.
Access moves pause during rebalance or decommission, never target a suspended
pool, skip remotely transitioned objects and objects with excessive version
counts, and recheck eligibility while holding the object namespace lock.

The hit counter is intentionally best effort. Only successfully served GET
requests count; HEAD requests do not. Counters are merged across nodes and
bounded by access_max_tracked. A rule window longer than
access_bin_width multiplied by access_bins is clamped to retained history.

AccessTransition and AccessTierQuota are Silo lifecycle extensions. A stock
AWS SDK that reads and rewrites the lifecycle configuration may discard
unknown fields. Use a raw signed S3 PUT lifecycle request, such as
[setup_ilm_access_tiering.sh](setup_ilm_access_tiering.sh), when installing
the rule. Save the XML above as `rule.xml`, then run:

~~~sh
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  ./setup_ilm_access_tiering.sh http://127.0.0.1:9000 testbucket us-east-1 rule.xml
~~~

Access-tier activity is exposed under /minio/metrics/v3/ilm, including move
counts, moved bytes, queue depth, hot bytes per bucket, failed moves, dropped
GET samples, and separate skip counters for each capacity limit.

## Explore Further

- [MinIO Go client API reference (S3-compatible SDK)](https://pkg.go.dev/github.com/minio/minio-go/v7)
- [Object Lifecycle Management](https://docs.aws.amazon.com/AmazonS3/latest/dev/object-lifecycle-mgmt.html)
