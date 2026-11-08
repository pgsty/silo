package cmd

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	polplugin "github.com/minio/minio/internal/config/policy/plugin"
	xnet "github.com/pgsty/silo-pkg/v3/net"
	"github.com/pgsty/silo-pkg/v3/policy"
)

type batchReplicationWriteObserver struct {
	ObjectLayer
	written func(string, string)
}

type batchReplicationWalkFailure struct {
	ObjectLayer
	streamed bool
}

func (failure batchReplicationWalkFailure) Walk(ctx context.Context, _, _ string, results chan<- itemOrErr[ObjectInfo], _ WalkOptions) error {
	if !failure.streamed {
		return errErasureReadQuorum
	}
	go func() {
		defer close(results)
		select {
		case results <- itemOrErr[ObjectInfo]{Err: errErasureReadQuorum}:
		case <-ctx.Done():
		}
	}()
	return nil
}

func TestBatchReplicationListingUnavailable(t *testing.T) {
	for _, snowball := range []bool{false, true} {
		for _, streamed := range []bool{false, true} {
			t.Run(fmt.Sprintf("snowball=%t/streamed=%t", snowball, streamed), func(t *testing.T) {
				fixture := newBatchAuthzFixture(t)
				job := BatchJobRequest{
					ID: "replicate-listing" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
					Replicate: &BatchJobReplicateV1{
						Source: BatchJobReplicateSource{
							Type: BatchJobReplicateResourceMinIO, Bucket: fixture.bucket,
							Snowball: BatchJobSnowball{
								Disable: ptr(!snowball), InMemory: ptr(true), Compress: ptr(false), SkipErrs: ptr(false),
								Batch: ptr(1), SmallerThan: ptr("1MiB"),
							},
						},
						Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: "remote", Endpoint: "https://target.invalid"},
					},
				}
				api := batchReplicationWalkFailure{ObjectLayer: fixture.obj, streamed: streamed}
				if err := job.Replicate.Start(fixture.ctx, api, job); !isBatchJobUnavailable(err) {
					t.Fatalf("listing failure did not pause: %v", err)
				}
				report := fixture.jobInfo(t, &job)
				if report.PausedReason == "" || report.Failed || report.Complete || report.Object != "" || report.ObjectsFailed != 0 {
					t.Fatalf("listing failure saved an invalid outcome: %+v", report)
				}
			})
		}
	}
}

func (observer batchReplicationWriteObserver) PutObject(ctx context.Context, bucket, object string, reader *PutObjReader, opts ObjectOptions) (ObjectInfo, error) {
	info, err := observer.ObjectLayer.PutObject(ctx, bucket, object, reader, opts)
	if err == nil {
		observer.written(bucket, object)
	}
	return info, err
}

func TestBatchReplicationRemoteListingDenied(t *testing.T) {
	fixture := newBatchAuthzFixture(t)
	previousTransport := remoteInstanceTransport
	remoteInstanceTransport = atomic.Value{}
	setRemoteInstanceTransport(batchLockTransport(func(request *http.Request) (*http.Response, error) {
		status := http.StatusForbidden
		body := `<Error><Code>AccessDenied</Code><Message>source listing denied</Message></Error>`
		if request.URL.Query().Has("location") {
			status = http.StatusOK
			body = `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
		}
		return &http.Response{
			StatusCode: status, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request,
		}, nil
	}))
	defer func() { remoteInstanceTransport = previousTransport }()
	job := BatchJobRequest{
		ID: "replicate-listing-denied" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
		Replicate: &BatchJobReplicateV1{
			Source: BatchJobReplicateSource{
				Type: BatchJobReplicateResourceMinIO, Bucket: "remote", Endpoint: "https://source.invalid",
				Creds: BatchJobReplicateCredentials{AccessKey: "test-access", SecretKey: "test-secret"},
			},
			Target: BatchJobReplicateTarget{Type: BatchJobReplicateResourceMinIO, Bucket: fixture.bucket},
		},
	}
	if err := job.Replicate.StartFromSource(fixture.ctx, fixture.obj, job); err != nil {
		t.Fatalf("explicit remote denial was not terminal: %v", err)
	}
	report := fixture.jobInfo(t, &job)
	if !report.Failed || report.Complete || report.FailureReason == "" || report.PausedReason != "" {
		t.Fatalf("remote denial saved an invalid outcome: %+v", report)
	}
}

func TestBatchReplicationDependencyRecovery(t *testing.T) {
	for _, mode := range []string{"push", "pull", "snowball"} {
		for _, denied := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/denied=%t", mode, denied), func(t *testing.T) {
				t.Setenv("_MINIO_BATCH_REPLICATION_WORKERS", "2")
				fixture := newBatchAuthzFixture(t)
				keys := []string{"a-done", "b-pending", "c-later"}
				versions := make(map[string]string)
				for _, key := range keys {
					versions[key] = mustGetUUID()
					if mode != "pull" {
						versions[key] = batchPutVersion(t, fixture.obj, fixture.bucket, key, nil).VersionID
					}
				}
				laterDone := make(chan struct{})
				signalLater := sync.OnceFunc(func() { close(laterDone) })
				var writtenMu sync.Mutex
				written := make(map[string]bool)
				recordWrite := func(bucket, key string) {
					if bucket != fixture.bucket && bucket != "remote" {
						return
					}
					writtenMu.Lock()
					written[key] = true
					writtenMu.Unlock()
					if key == "c-later" {
						signalLater()
					}
				}
				var outage atomic.Bool
				outage.Store(true)
				var decisions atomic.Int32
				pluginServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					var input struct {
						Input policy.Args `json:"input"`
					}
					if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
						t.Error(err)
						writer.WriteHeader(http.StatusBadRequest)
						return
					}
					action := policy.Action(policy.GetObjectAction)
					if mode == "pull" {
						action = policy.PutObjectAction
					}
					if outage.Load() && input.Input.Action == action && input.Input.ObjectName == "b-pending" {
						decisions.Add(1)
						if mode != "snowball" {
							select {
							case <-laterDone:
							case <-request.Context().Done():
								return
							}
						}
						if denied {
							io.WriteString(writer, `{"result":false}`)
							return
						}
						writer.WriteHeader(http.StatusServiceUnavailable)
					}
					io.WriteString(writer, `{"result":true}`)
				}))
				defer pluginServer.Close()
				pluginURL, err := xnet.ParseHTTPURL(pluginServer.URL)
				mustIAM(t, err)
				previousPlugin := newGlobalAuthZPluginFn()
				setGlobalAuthZPlugin(polplugin.New(polplugin.Args{
					URL: pluginURL, CloseRespFn: func(reader io.ReadCloser) { reader.Close() },
				}))
				defer setGlobalAuthZPlugin(previousPlugin)
				previousTransport := remoteInstanceTransport
				remoteInstanceTransport = atomic.Value{}
				setRemoteInstanceTransport(batchLockTransport(func(request *http.Request) (*http.Response, error) {
					if err := request.Context().Err(); err != nil {
						return nil, err
					}
					body := ""
					header := make(http.Header)
					query := request.URL.Query()
					switch {
					case query.Has("location"):
						body = `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`
					case query.Has("versions"):
						body = `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>remote</Name><IsTruncated>false</IsTruncated>`
						for _, key := range keys {
							body += fmt.Sprintf(`<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><LastModified>2026-11-01T00:00:00.000Z</LastModified><ETag>"etag"</ETag><Size>7</Size><StorageClass>STANDARD</StorageClass></Version>`, key, versions[key])
						}
						body += `</ListVersionsResult>`
					case request.Method == http.MethodGet:
						body = "payload"
						header.Set("Etag", `"etag"`)
						header.Set("Last-Modified", UTCNow().Format(http.TimeFormat))
						header.Set("X-Amz-Version-Id", query.Get("versionId"))
					case request.Method == http.MethodPut:
						if mode == "snowball" && request.Body != nil {
							archive := tar.NewReader(request.Body)
							for {
								entry, readErr := archive.Next()
								if readErr == io.EOF {
									break
								}
								if readErr != nil {
									return nil, readErr
								}
								recordWrite("remote", entry.Name)
							}
						} else if mode != "snowball" {
							if _, err := io.Copy(io.Discard, request.Body); err != nil {
								return nil, err
							}
							recordWrite("remote", strings.TrimPrefix(request.URL.Path, "/remote/"))
						}
						header.Set("Etag", `"etag"`)
					default:
						return nil, fmt.Errorf("unexpected replication request: %s %s", request.Method, request.URL)
					}
					header.Set("Content-Length", strconv.Itoa(len(body)))
					return &http.Response{
						StatusCode: http.StatusOK, Header: header,
						Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: request,
					}, nil
				}))
				defer func() { remoteInstanceTransport = previousTransport }()
				job := &BatchJobRequest{
					ID: "replicate-retry" + getKeySeparator() + "0", Started: UTCNow(), Submitter: batchRootSubmitter(t),
					Replicate: &BatchJobReplicateV1{
						Source: BatchJobReplicateSource{Type: BatchJobReplicateResourceMinIO, Bucket: fixture.bucket},
						Target: BatchJobReplicateTarget{
							Type: BatchJobReplicateResourceMinIO, Bucket: "remote", Endpoint: "https://target.invalid",
							Creds: BatchJobReplicateCredentials{AccessKey: "test-access", SecretKey: "test-secret"},
						},
					},
				}
				if mode == "pull" {
					job.Replicate.Source.Endpoint = job.Replicate.Target.Endpoint
					job.Replicate.Source.Creds = job.Replicate.Target.Creds
					job.Replicate.Source.Bucket = "remote"
					job.Replicate.Target.Endpoint = ""
					job.Replicate.Target.Bucket = fixture.bucket
				}
				if mode == "snowball" {
					job.Replicate.Source.Snowball = BatchJobSnowball{
						Disable: ptr(false), InMemory: ptr(true), Compress: ptr(false), SkipErrs: ptr(false),
						Batch: ptr(1), SmallerThan: ptr("1MiB"),
					}
				}
				job.Replicate.Flags.Retry.Attempts = 1
				job.Replicate.Flags.Retry.Delay = time.Millisecond
				interrupted := &batchJobInfo{
					JobID: job.ID, JobType: string(job.Type()), StartTime: job.Started,
					Object: "c-later", Objects: 2,
				}
				mustIAM(t, interrupted.updateAfter(fixture.ctx, fixture.obj, 0, *job))
				pool := globalBatchJobPool
				pool.objLayer = batchReplicationWriteObserver{ObjectLayer: fixture.obj, written: recordWrite}
				ctx, cancel := context.WithCancel(fixture.ctx)
				pool.ctx = ctx
				mustIAM(t, pool.queueJob(job))
				done := make(chan struct{})
				go func() { defer close(done); pool.AddWorker() }()
				defer func() {
					cancel()
					<-done
					if t.Failed() {
						t.Logf("last report: %+v", fixture.jobInfo(t, job))
					}
				}()
				state := "paused"
				if denied {
					state = "terminal"
				}
				waitBatchState(t, pool, job.ID, state)
				report := fixture.jobInfo(t, job)
				if decisions.Load() == 0 {
					t.Fatal("test did not reach per-object authorization")
				}
				if denied {
					if !report.Failed || report.Complete || report.FailureReason == "" || report.PausedReason != "" {
						t.Fatalf("denial was not terminal: %+v", report)
					}
					pool.retryDue(time.Now().Add(time.Hour))
					if len(pool.jobCh) != 0 {
						t.Fatal("denied job was retried")
					}
					return
				}
				if report.Failed || report.Complete || report.FailureReason != "" || report.PausedReason == "" ||
					report.Object != "" || report.Objects != 0 || report.ObjectsFailed != 0 {
					t.Fatalf("outage was not saved with a safe restart point: %+v", report)
				}
				pool.jmu.Lock()
				owner := pool.jobOwners[job.ID]
				sameOwner := owner.req == job && owner.retries == 1
				pool.jmu.Unlock()
				if !sameOwner {
					t.Fatal("pause lost the job owner")
				}
				outage.Store(false)
				pool.retryDue(time.Now().Add(time.Hour))
				waitBatchState(t, pool, job.ID, "terminal")
				report = fixture.jobInfo(t, job)
				if !report.Complete || report.Failed || report.PausedReason != "" || report.Objects != int64(len(keys)) || report.ObjectsFailed != 0 {
					t.Fatalf("retry did not finish with consistent counts: %+v", report)
				}
				writtenMu.Lock()
				for _, key := range keys {
					if !written[key] {
						t.Errorf("retry skipped %s", key)
					}
				}
				writtenMu.Unlock()
				if mode == "pull" {
					for _, key := range keys {
						if !batchVersionExists(t, fixture.obj, fixture.bucket, key, versions[key]) {
							t.Errorf("retry lost remote version of %s", key)
						}
					}
				}
			})
		}
	}
}
