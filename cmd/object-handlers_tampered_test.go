package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
)

// tamperedObjectLayer returns a fixed error from the read paths so the handler
// response can be tested without reproducing the storage defect that produces
// an unreadable object. No object bytes are sent to the caller.
type tamperedObjectLayer struct {
	ObjectLayer
	err error
}

func (o *tamperedObjectLayer) GetObjectNInfo(context.Context, string, string, *HTTPRangeSpec, http.Header, ObjectOptions) (*GetObjectReader, error) {
	return nil, o.err
}

func (o *tamperedObjectLayer) GetObjectInfo(context.Context, string, string, ObjectOptions) (ObjectInfo, error) {
	return ObjectInfo{}, o.err
}

// TestObjectTamperedGETHEADStatus asserts that an object the server cannot
// decode is reported with a 5xx status, not a success status. Returning
// http.StatusPartialContent here let SDKs accept the XML error document as
// object content. See pgsty/silo#110.
func TestObjectTamperedGETHEADStatus(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{t: t, objAPITest: func(obj ObjectLayer, instanceType, bucket string, router http.Handler, credentials auth.Credentials, t *testing.T) {
		// An encrypted stream shorter than one complete encryption package is
		// a real size-validation origin of errObjectTampered.
		damaged := ObjectInfo{Size: 31, UserDefined: map[string]string{crypto.MetaAlgorithm: crypto.InsecureSealAlgorithm}}
		_, err := damaged.DecryptedSize()
		if err != errObjectTampered {
			t.Fatalf("damaged-size error = %v, want errObjectTampered", err)
		}
		previous := newObjectLayerFn()
		setObjectLayer(&tamperedObjectLayer{ObjectLayer: obj, err: err})
		defer setObjectLayer(previous)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req, err := newTestSignedRequestV4(method, getGetObjectURL("", bucket, "damaged-object"), 0, nil, credentials.AccessKey, credentials.SecretKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if method == http.MethodGet && !strings.Contains(rec.Body.String(), "<Code>XMinioObjectTampered</Code>") {
				t.Fatalf("%s: GET did not reach the damaged-object response: %d %s", instanceType, rec.Code, rec.Body.String())
			}
			if method == http.MethodHead && rec.Header().Get(xMinIOErrCodeHeader) != "XMinioObjectTampered" {
				t.Fatalf("%s: HEAD did not reach the damaged-object response: %d %v", instanceType, rec.Code, rec.Header())
			}
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("%s: %s of a damaged object returned HTTP %d, want %d", instanceType, method, rec.Code, http.StatusInternalServerError)
			}
		}
	}})
}
