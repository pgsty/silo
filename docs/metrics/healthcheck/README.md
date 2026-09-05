# Silo Healthcheck

Silo server exposes three un-authenticated, healthcheck endpoints liveness probe and a cluster probe at `/minio/health/live` and `/minio/health/cluster` respectively.

## Native CLI probe

The `silo` binary can probe those endpoints itself, which makes health checking possible in containers that ship no shell, `curl`, or `mc`:

```
silo healthcheck [FLAGS] [live|ready|cluster|cluster-read]
```

The check name maps 1:1 onto `/minio/health/<path>`; `live` is the default. The exit code is `0` when healthy and `1` otherwise, and one diagnostic line (including the `x-minio-server-status` and quorum headers on failure) is printed for `docker inspect` to capture. The probe target is derived the same way the server derives its own listen address — `--address` / `MINIO_ADDRESS`, with HTTPS auto-detected from `public.crt` and `private.key` in `--certs-dir` — or overridden wholesale with `--url` / `MINIO_HEALTHCHECK_URL`. The environment form exists for containers with a baked-in `HEALTHCHECK`: a probe process cannot see the server's command line, so when the server's address or TLS setup comes from CLI arguments rather than the environment, set `MINIO_HEALTHCHECK_URL` (e.g. `https://127.0.0.1:9010`) to point the built-in probe at it. Certificate verification is skipped, matching the kubelet's behavior for HTTPS probes.

Use it as an image `HEALTHCHECK` (exec form, since there may be no shell; keep the outer timeout above the probe's own 5s deadline so its diagnostic line survives):

```
HEALTHCHECK --interval=30s --timeout=10s --start-period=2m --start-interval=2s --retries=3 \
  CMD ["/usr/bin/silo", "healthcheck", "ready"]
```

or as a Docker Compose healthcheck:

```
healthcheck:
  test: ["CMD", "/usr/bin/silo", "healthcheck", "ready"]
  interval: 5s
  timeout: 10s
  retries: 5
```

`silo healthcheck --maintenance cluster` answers the pre-drain question documented below: exit `0` when the node can be taken down safely, exit `1` (HTTP 412) when doing so would lose HA. Keep the `cluster` checks out of per-container liveness probes — they reflect cluster-wide quorum, not this process.

## Liveness probe

This probe always responds with '200 OK'. Only fails if 'etcd' is configured and unreachable. When liveness probe fails, Kubernetes like platforms restart the container.

```
livenessProbe:
  httpGet:
    path: /minio/health/live
    port: 9000
    scheme: HTTP
  initialDelaySeconds: 120
  periodSeconds: 30
  timeoutSeconds: 10
  successThreshold: 1
  failureThreshold: 3
```

## Readiness probe

This probe responds with '200 OK' once the server process is up: it fails only while the request queue is overloaded, or when the health operation against the configured KMS or 'etcd' fails. When readiness probe fails, Kubernetes like platforms turn-off routing to the container.

```
readinessProbe:
  httpGet:
    path: /minio/health/ready
    port: 9000
    scheme: HTTP
  initialDelaySeconds: 120
  periodSeconds: 15
  timeoutSeconds: 10
  successThreshold: 1
  failureThreshold: 3
```

## Cluster probe

### Cluster-writeable probe

The reply is '200 OK' if cluster has write quorum if not it returns '503 Service Unavailable'.

```
curl http://silo1:9001/minio/health/cluster
HTTP/1.1 503 Service Unavailable
Accept-Ranges: bytes
Content-Length: 0
Server: Silo
Vary: Origin
X-Amz-Bucket-Region: us-east-1
X-Minio-Write-Quorum: 3
X-Amz-Request-Id: 16239D6AB80EBECF
X-Xss-Protection: 1; mode=block
Date: Tue, 21 Jul 2020 00:36:14 GMT
```

### Cluster-readable probe

The reply is '200 OK' if cluster has read quorum if not it returns '503 Service Unavailable'.

```
curl http://silo1:9001/minio/health/cluster/read
HTTP/1.1 503 Service Unavailable
Accept-Ranges: bytes
Content-Length: 0
Server: Silo
Vary: Origin
X-Amz-Bucket-Region: us-east-1
X-Minio-Write-Quorum: 3
X-Amz-Request-Id: 16239D6AB80EBECF
X-Xss-Protection: 1; mode=block
Date: Tue, 21 Jul 2020 00:36:14 GMT
```

### Checking cluster health for maintenance

You may query the cluster probe endpoint to check if the node which received the request can be taken down for maintenance, if the server replies back '412 Precondition Failed' this means you will lose HA. '200 OK' means you are okay to proceed.

```
curl http://silo1:9001/minio/health/cluster?maintenance=true
HTTP/1.1 412 Precondition Failed
Accept-Ranges: bytes
Content-Length: 0
Server: Silo
Vary: Origin
X-Amz-Bucket-Region: us-east-1
X-Amz-Request-Id: 16239D63820C6E76
X-Xss-Protection: 1; mode=block
X-Minio-Write-Quorum: 3
Date: Tue, 21 Jul 2020 00:35:43 GMT
```

## Startup readiness window

None of the probes above, and no `admin info` view, proves that the node which received the request can already serve the data path after a restart. Each node connects its erasure drives to its peers in a monitor loop: a remote drive that could not be connected during startup stays uninstalled on that node until a later pass, and the monitor waits 15 seconds after each completed pass, so that interval is a floor between attempts, not a bound on recovery. While a drive is uninstalled, the node's own liveness and readiness probes answer '200 OK', the cluster probes can report healthy as well, because they aggregate every peer's report of its own local drives rather than the drives this node has installed, and `mcli ready` inherits the same blind spot. Yet a PUT through that node can fail with '503 SlowDownWrite' for lack of write quorum, and a GET through it of an object that another node just wrote can answer '404 NoSuchKey'. In the review runs that established this, sampled I/O began succeeding roughly 13 to 15 seconds after the administrative views became healthy on a four-node loopback cluster, consistent with the reconnect interval, and every object acknowledged by other nodes during the window was readable afterwards; these are observations, not guarantees, since reconnection can keep failing.

Automation that restarts a cluster and then immediately writes to it, such as an upgrade or failover runbook, should therefore gate on a bounded data-path check rather than on these probes: one small PUT through each node followed by a read of each object through every node, repeated until every request returns the correct bytes and the acknowledged version within one fixed deadline, with each request budgeted from the remaining deadline and SDK retries disabled, and with the acknowledged objects re-read afterwards. Record the time to first usable I/O separately from the probe result. Such a check proves sampled I/O at that moment for the erasure sets those keys hash to; it proves neither that every set is complete nor that there is headroom for a further node loss, since a set can admit writes with fewer than all of its drives installed. The probes remain the right signal for their stated purpose, process liveness and quorum membership, and are unchanged.
