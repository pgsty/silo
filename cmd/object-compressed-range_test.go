// Copyright (c) 2026 Feng Ruohang
//
// This file is part of Silo Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/minio/internal/auth"
	"github.com/minio/minio/internal/crypto"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/kms"
)

// Indexed reads may skip into the first decrypted block while both the disk
// offset and the remaining decompressed skip are zero. The reader must still
// accept a compression block without the original stream identifier.
func TestAPICompressedEncryptedRange(t *testing.T) {
	ExecObjectLayerAPITest(ExecObjectLayerAPITestArgs{
		t: t,
		objAPITest: func(obj ObjectLayer, backend, bucket string, router http.Handler, cred auth.Credentials, t *testing.T) {
			previousKMS, previousTLS := GlobalKMS, globalIsTLS
			var err error
			GlobalKMS, err = kms.NewBuiltin("range-key", bytes.Repeat([]byte{0x42}, 32))
			if err != nil {
				t.Fatal(err)
			}
			globalIsTLS = true
			defer func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS }()
			restore := setCopyChecksumCompression(true)
			defer restore()
			part := bytes.Repeat([]byte("compressible-A"), 1<<20)
			for _, mode := range []string{"compressed", "sse-s3", "sse-kms"} {
				for _, multipart := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/multipart=%t", backend, mode, multipart), func(t *testing.T) {
						key := fmt.Sprintf("range-%s-%t.txt", mode, multipart)
						headers := map[string]string{}
						switch mode {
						case "sse-s3":
							headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionAES
						case "sse-kms":
							headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
							headers[xhttp.AmzServerSideEncryptionKmsID] = "range-key"
						}
						data := part
						if multipart {
							data = attributesPartsUpload(t, router, cred, bucket, key, headers,
								[][]byte{part, bytes.Repeat([]byte("compressible-B"), 1<<20)}, []int{1, 2})
						} else {
							putCopyChecksumSource(t, router, cred, bucket, key, data, headers)
						}
						oi, err := obj.GetObjectInfo(t.Context(), bucket, key, ObjectOptions{})
						if err != nil {
							t.Fatal(err)
						}
						_, encrypted := crypto.IsEncrypted(oi.UserDefined)
						if !oi.IsCompressed() || encrypted != (mode != "compressed") || len(oi.Parts) == 0 || len(oi.Parts[0].Index) == 0 {
							t.Fatal("fixture must have indexed compression and the requested encryption")
						}
						if encrypted {
							off, decOff, _, skip, _ := getCompressedOffsets(oi, 1<<20, func(b []byte) ([]byte, error) { return oi.compressionIndexDecrypt(b, nil) })
							if off != 0 || decOff != 0 || skip <= 0 {
								t.Fatalf("fixture misses boundary: off=%d decOff=%d decryptSkip=%d", off, decOff, skip)
							}
						}
						offsets := []int{0, 100, 1 << 20, 1<<20 + 1, len(data) - 1000}
						if multipart {
							offsets = append(offsets, len(part)-500, len(part), len(part)+1<<20)
						}
						for _, start := range offsets {
							rec := attributesPartsSignedRequest(t, router, cred, http.MethodGet, getGetObjectURL("", bucket, key), nil,
								map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", start, start+999)})
							if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), data[start:start+1000]) {
								t.Errorf("range at %d: status=%d bytes=%d, want 206 and exact slice", start, rec.Code, rec.Body.Len())
							}
						}
						rec := attributesPartsSignedRequest(t, router, cred, http.MethodGet, getGetObjectURL("", bucket, key), nil, nil)
						if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), data) {
							t.Fatal("full read changed after ranged reads")
						}
					})
				}
			}
		},
	})
}

func TestAPICompressedEncryptedRangeCorruptBlockRejected(t *testing.T) {
	resetTestGlobals()
	ctx := GlobalContext
	obj, fsDir, err := prepareFSWithDisks(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer removeAll(fsDir)
	defer obj.Shutdown(ctx)

	bucket, router, err := initAPIHandlerTest(ctx, obj, nil, MakeBucketOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := newTestConfig(globalMinioDefaultRegion, obj); err != nil {
		t.Fatal(err)
	}
	previousKMS, previousTLS := GlobalKMS, globalIsTLS
	GlobalKMS, err = kms.NewBuiltin("range-key", bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	globalIsTLS = true
	defer func() { GlobalKMS, globalIsTLS = previousKMS, previousTLS }()
	restore := setCopyChecksumCompression(true)
	defer restore()

	cred := globalActiveCred
	payload := bytes.Repeat([]byte("compressible-A"), 1<<20)

	for _, mode := range []string{"compressed", "sse-kms"} {
		key := "corrupt-" + mode + ".txt"
		headers := map[string]string{}
		if mode == "sse-kms" {
			headers[xhttp.AmzServerSideEncryption] = xhttp.AmzEncryptionKMS
			headers[xhttp.AmzServerSideEncryptionKmsID] = "range-key"
		}
		putCopyChecksumSource(t, router, cred, bucket, key, payload, headers)

		rec := attributesPartsSignedRequest(t, router, cred, http.MethodGet, getGetObjectURL("", bucket, key), nil,
			map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", 1<<20, (1<<20)+999)})
		if rec.Code != http.StatusPartialContent || !bytes.Equal(rec.Body.Bytes(), payload[1<<20:(1<<20)+1000]) {
			t.Fatalf("%s pre-corrupt range failed: code=%d", mode, rec.Code)
		}

		corruptedAny := false
		_ = filepath.Walk(fsDir, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.IsDir() || !strings.Contains(path, key) {
				return nil
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			if strings.HasSuffix(path, "part.1") {
				raw[len(raw)/2] ^= 0xff
				_ = os.WriteFile(path, raw, info.Mode())
				corruptedAny = true
			} else if strings.HasSuffix(path, xlStorageFormatFile) && len(raw) > 256 {
				raw[len(raw)-64] ^= 0xff
				_ = os.WriteFile(path, raw, info.Mode())
				corruptedAny = true
			}
			return nil
		})
		if !corruptedAny {
			t.Fatalf("%s: failed to locate backing storage file to corrupt", mode)
		}

		recAfter := attributesPartsSignedRequest(t, router, cred, http.MethodGet, getGetObjectURL("", bucket, key), nil,
			map[string]string{"Range": fmt.Sprintf("bytes=%d-%d", 1<<20, (1<<20)+999)})
		if recAfter.Code == http.StatusPartialContent && recAfter.Body.Len() == 1000 {
			t.Fatalf("%s: corrupted range unexpectedly returned 206 with 1000 bytes", mode)
		}
	}
}
