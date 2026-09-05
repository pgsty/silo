package cmd

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio/internal/auth"
	"github.com/minio/mux"
)

func corsAdminRequest(t *testing.T, cred auth.Credentials, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	router := mux.NewRouter()
	registerAdminRouter(router, true)
	req, err := newTestSignedRequestV4(method, adminPathPrefix+adminAPIVersionPrefix+path,
		int64(len(body)), bytes.NewReader(body), cred.AccessKey, cred.SecretKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin %s: %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec
}

func corsImportReport(t *testing.T, rec *httptest.ResponseRecorder) madmin.BucketMetaImportErrs {
	t.Helper()
	var rpt madmin.BucketMetaImportErrs
	if err := json.Unmarshal(rec.Body.Bytes(), &rpt); err != nil {
		t.Fatalf("import report %q: %v", rec.Body.String(), err)
	}
	return rpt
}

func corsZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// corsCorruptedZip builds an archive holding a stored (uncompressed) cors.xml
// whose payload is altered after the checksum is computed, plus the given
// companion entries. The altered document stays well formed, so only the zip
// checksum tells the two apart.
func corsCorruptedZip(t *testing.T, name string, doc []byte, others map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(doc); err != nil {
		t.Fatal(err)
	}
	for other, data := range others {
		ow, err := zw.Create(other)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ow.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	at := bytes.Index(raw, []byte("app.example.com"))
	if at < 0 {
		t.Fatalf("stored CORS payload not found in archive")
	}
	raw[at] = 'A'
	return raw
}

// TestAdminBucketMetadataCORSRoundTrip covers the export/import round trip for
// per-bucket CORS, per-file error reporting for an invalid document, and that
// an archive without cors.xml leaves an existing configuration alone.
func TestAdminBucketMetadataCORSRoundTrip(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		corsXML := []byte(testSiteReplicationCORSDoc)
		if _, err := updateLocalBucketCORSMetadata(t.Context(), obj, bucket, corsXML); err != nil {
			t.Fatal(err)
		}

		// Export must carry the stored document verbatim.
		rec := corsAdminRequest(t, cred, http.MethodGet, "/export-bucket-metadata?bucket="+bucket, nil)
		archive := rec.Body.Bytes()
		zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			t.Fatal(err)
		}
		var exported []byte
		for _, f := range zr.File {
			if f.Name != bucket+"/"+bucketCorsConfig {
				continue
			}
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			exported, err = io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(exported, corsXML) {
			t.Fatalf("%s: exported CORS = %q, want %q", instanceType, exported, corsXML)
		}

		// Drop the configuration: the archive must then omit the entry.
		if _, err = updateLocalBucketCORSMetadata(t.Context(), obj, bucket, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, err = globalBucketMetadataSys.GetCorsConfigXML(bucket); err == nil {
			t.Fatalf("%s: CORS still present before restore", instanceType)
		}
		rec = corsAdminRequest(t, cred, http.MethodGet, "/export-bucket-metadata?bucket="+bucket, nil)
		empty := rec.Body.Bytes()
		zr, err = zip.NewReader(bytes.NewReader(empty), int64(len(empty)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range zr.File {
			if f.Name == bucket+"/"+bucketCorsConfig {
				t.Fatalf("%s: export emitted %s for a bucket without CORS", instanceType, f.Name)
			}
		}

		rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata", archive)
		if st := corsImportReport(t, rec).Buckets[bucket]; !st.Cors.IsSet || st.Cors.Err != "" {
			t.Fatalf("%s: import report cors = %+v", instanceType, st.Cors)
		}
		stored, storedAt, err := globalBucketMetadataSys.GetCorsConfigXML(bucket)
		if err != nil || !bytes.Equal(stored, corsXML) {
			t.Fatalf("%s: restored CORS = %q, err = %v", instanceType, stored, err)
		}
		created, err := globalBucketMetadataSys.CreatedAt(bucket)
		if err != nil {
			t.Fatal(err)
		}
		if !storedAt.After(created) {
			t.Fatalf("%s: restored CORS timestamp %v is not after bucket creation %v", instanceType, storedAt, created)
		}

		// An archive without cors.xml must not remove the configuration.
		corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata",
			corsZip(t, map[string][]byte{bucket + "/quota.json": []byte(`{"quota":0}`)}))
		if stored, _, err = globalBucketMetadataSys.GetCorsConfigXML(bucket); err != nil || !bytes.Equal(stored, corsXML) {
			t.Fatalf("%s: import without cors.xml changed CORS: %q, err = %v", instanceType, stored, err)
		}

		// A bucket the import itself creates must still land above its own
		// creation time, otherwise CORS replication would drop the restore.
		fresh := "cors-import-created-bucket"
		rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata",
			corsZip(t, map[string][]byte{fresh + "/" + bucketCorsConfig: corsXML}))
		if st := corsImportReport(t, rec).Buckets[fresh]; !st.Cors.IsSet || st.Cors.Err != "" {
			t.Fatalf("%s: fresh bucket import report cors = %+v", instanceType, st.Cors)
		}
		freshStored, freshAt, err := globalBucketMetadataSys.GetCorsConfigXML(fresh)
		if err != nil || !bytes.Equal(freshStored, corsXML) {
			t.Fatalf("%s: fresh bucket CORS = %q, err = %v", instanceType, freshStored, err)
		}
		freshCreated, err := globalBucketMetadataSys.CreatedAt(fresh)
		if err != nil {
			t.Fatal(err)
		}
		if !freshAt.After(freshCreated) {
			t.Fatalf("%s: fresh bucket CORS timestamp %v is not after creation %v", instanceType, freshAt, freshCreated)
		}

		// An invalid document must fail loudly for that bucket and change nothing.
		rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata",
			corsZip(t, map[string][]byte{bucket + "/" + bucketCorsConfig: []byte("<CORSConfiguration><CORSRule>")}))
		if st := corsImportReport(t, rec).Buckets[bucket]; st.Cors.Err == "" {
			t.Fatalf("%s: invalid CORS import reported no error: %+v", instanceType, st)
		}
		if stored, _, err = globalBucketMetadataSys.GetCorsConfigXML(bucket); err != nil || !bytes.Equal(stored, corsXML) {
			t.Fatalf("%s: invalid CORS import changed stored config: %q, err = %v", instanceType, stored, err)
		}

		// A well formed document carried by a corrupt zip entry must be
		// rejected too, leaving the stored document and its timestamp alone
		// while the other configs in the same archive still apply.
		_, corsAt, err := globalBucketMetadataSys.GetCorsConfigXML(bucket)
		if err != nil {
			t.Fatal(err)
		}
		rec = corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata",
			corsCorruptedZip(t, bucket+"/"+bucketCorsConfig, corsXML,
				map[string][]byte{bucket + "/quota.json": []byte(`{"quota":4096,"quotatype":"hard"}`)}))
		st := corsImportReport(t, rec).Buckets[bucket]
		if st.Cors.Err == "" {
			t.Fatalf("%s: corrupt CORS entry reported no error: %+v", instanceType, st)
		}
		if !st.Quota.IsSet || st.Quota.Err != "" {
			t.Fatalf("%s: corrupt CORS entry blocked the neighboring quota: %+v", instanceType, st.Quota)
		}
		stored, storedAt, err = globalBucketMetadataSys.GetCorsConfigXML(bucket)
		if err != nil || !bytes.Equal(stored, corsXML) || !storedAt.Equal(corsAt) {
			t.Fatalf("%s: corrupt CORS entry changed stored config: %q at %v (was %v), err = %v", instanceType, stored, storedAt, corsAt, err)
		}
		quota, _, err := globalBucketMetadataSys.GetQuotaConfig(t.Context(), bucket)
		if err != nil || quota == nil || quota.Quota != 4096 {
			t.Fatalf("%s: neighboring quota not applied: %+v, err = %v", instanceType, quota, err)
		}
	}})
}

// corsPeerStub is a stand-in site-replication peer. It records every
// SRBucketMeta it is asked to apply and answers with status.
func corsPeerStub(t *testing.T, applied chan<- madmin.SRBucketMeta, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && applied != nil {
			var item madmin.SRBucketMeta
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				t.Errorf("decode peer apply: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			applied <- item
		}
		w.WriteHeader(status)
	}))
}

// TestAdminBucketMetadataCORSImportReplicatesPastPeerFailure pins that an
// imported CORS document reaches the reachable peers even when the shared
// bucket metadata hook failed against an unreachable one, and that both
// failures are still reported for the bucket.
func TestAdminBucketMetadataCORSImportReplicatesPastPeerFailure(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, _ http.Handler, cred auth.Credentials, t *testing.T) {
		ctx := t.Context()
		corsXML := []byte(testSiteReplicationCORSDoc)

		healthyApplies := make(chan madmin.SRBucketMeta, 4)
		healthy := corsPeerStub(t, healthyApplies, http.StatusOK)
		defer healthy.Close()
		broken := corsPeerStub(t, nil, http.StatusBadRequest)
		defer broken.Close()

		// With site replication on, admin requests resolve their token signing
		// key through the site replicator account, so it has to exist.
		serviceCred, err := auth.CreateCredentials(siteReplicatorSvcAcc, "cors-import-service-secret")
		if err != nil {
			t.Fatal(err)
		}
		serviceCred.ParentUser = cred.AccessKey
		if _, err = globalIAMSys.store.AddServiceAccount(ctx, serviceCred); err != nil {
			t.Fatal(err)
		}
		defer globalIAMSys.DeleteServiceAccount(ctx, serviceCred.AccessKey, false)
		globalSiteReplicatorCred.Set(serviceCred.SecretKey)
		defer globalSiteReplicatorCred.Set("")

		globalSiteReplicationSys.Lock()
		oldEnabled, oldState := globalSiteReplicationSys.enabled, globalSiteReplicationSys.state
		globalSiteReplicationSys.enabled = true
		globalSiteReplicationSys.state = srState{
			Name:                    "cors-import-test",
			ServiceAccountAccessKey: serviceCred.AccessKey,
			Peers: map[string]madmin.PeerInfo{
				globalDeploymentID(): {Name: "local", DeploymentID: globalDeploymentID()},
				"peer-healthy":       {Name: "healthy", DeploymentID: "peer-healthy", Endpoint: healthy.URL},
				"peer-broken":        {Name: "broken", DeploymentID: "peer-broken", Endpoint: broken.URL},
			},
		}
		globalSiteReplicationSys.Unlock()
		defer func() {
			globalSiteReplicationSys.Lock()
			globalSiteReplicationSys.enabled, globalSiteReplicationSys.state = oldEnabled, oldState
			globalSiteReplicationSys.Unlock()
		}()

		rec := corsAdminRequest(t, cred, http.MethodPut, "/import-bucket-metadata",
			corsZip(t, map[string][]byte{
				bucket + "/" + bucketCorsConfig: corsXML,
				bucket + "/quota.json":          []byte(`{"quota":8192,"quotatype":"hard"}`),
			}))
		st := corsImportReport(t, rec).Buckets[bucket]
		if !st.Cors.IsSet || st.Cors.Err != "" {
			t.Fatalf("%s: import report cors = %+v", instanceType, st.Cors)
		}
		stored, storedAt, err := globalBucketMetadataSys.GetCorsConfigXML(bucket)
		if err != nil || !bytes.Equal(stored, corsXML) {
			t.Fatalf("%s: stored CORS = %q, err = %v", instanceType, stored, err)
		}

		// The reachable peer must have been told about the CORS document,
		// carrying exactly the timestamp that was saved locally.
		var corsSeen, sharedSeen bool
		for range 2 {
			select {
			case item := <-healthyApplies:
				if item.Type != madmin.SRBucketMetaTypeCorsConfig {
					sharedSeen = item.Bucket == bucket && item.Quota != nil
					continue
				}
				if item.Bucket != bucket || item.Cors == nil || !item.UpdatedAt.Equal(storedAt) {
					t.Fatalf("%s: peer CORS event = %#v, want %s at %v", instanceType, item, bucket, storedAt)
				}
				payload, decErr := base64.StdEncoding.Strict().DecodeString(*item.Cors)
				if decErr != nil || !bytes.Equal(payload, corsXML) {
					t.Fatalf("%s: peer CORS payload = %q, err = %v", instanceType, payload, decErr)
				}
				corsSeen = true
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: healthy peer received no further events (shared=%v cors=%v)", instanceType, sharedSeen, corsSeen)
			}
		}
		if !sharedSeen || !corsSeen {
			t.Fatalf("%s: healthy peer events shared=%v cors=%v, want both", instanceType, sharedSeen, corsSeen)
		}

		// Both hook failures against the unreachable peer stay reported.
		if got := strings.Count(st.Err, "->broken:"); got != 2 {
			t.Fatalf("%s: bucket error mentions the broken peer %d times, want 2: %q", instanceType, got, st.Err)
		}
	}})
}
