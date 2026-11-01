// Copyright (c) 2026 Denis Babchuk
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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"maps"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio/internal/hash"
	xhttp "github.com/minio/minio/internal/http"
)

// checksumTestObject builds the xl.meta checksum of an object the way
// PutObject and CompleteMultipartUpload store it.
func checksumTestObject(t *testing.T, alg hash.ChecksumType, full bool, parts ...[]byte) FileInfo {
	t.Helper()
	fi := FileInfo{Volume: "bucket", Name: "object"}
	if len(parts) == 1 {
		fi.Size = int64(len(parts[0]))
		fi.Checksum = hash.NewChecksumFromData(alg, parts[0]).AppendTo(nil, nil)
		return fi
	}
	var combined, all []byte
	for i, p := range parts {
		combined = append(combined, hash.NewChecksumFromData(alg, p).Raw...)
		all = append(all, p...)
		fi.Parts = append(fi.Parts, ObjectPartInfo{Number: i + 1, Size: int64(len(p)), ActualSize: int64(len(p))})
		fi.Size += int64(len(p))
	}
	typ := alg | hash.ChecksumMultipart | hash.ChecksumIncludesMultipart
	if full {
		typ |= hash.ChecksumFullObject
	}
	cs := hash.NewChecksumFromData(typ, combined)
	if typ.FullObjectRequested() {
		// Full object CRC, as merged from the parts on completion.
		whole := hash.NewChecksumFromData(alg, all)
		cs = &hash.Checksum{Type: typ, Raw: whole.Raw, Encoded: whole.Encoded}
	}
	fi.Checksum = cs.AppendTo(nil, combined)
	return fi
}

// TestGetCRCMetaChecksumType checks the checksum headers that replication
// sends for an object: a FULL_OBJECT checksum type only for multipart full
// object CRCs, where the target needs it to create a matching upload.
func TestGetCRCMetaChecksumType(t *testing.T) {
	p1, p2 := []byte("first part"), []byte("second part")
	enc := func(alg hash.ChecksumType, b []byte) string { return hash.NewChecksumFromData(alg, b).Encoded }
	whole := append(append([]byte{}, p1...), p2...)
	composite := func(alg hash.ChecksumType) string {
		var combined []byte
		combined = append(combined, hash.NewChecksumFromData(alg, p1).Raw...)
		combined = append(combined, hash.NewChecksumFromData(alg, p2).Raw...)
		return enc(alg, combined) + "-2"
	}
	full := map[string]string{xhttp.AmzChecksumType: xhttp.AmzChecksumTypeFullObject}
	tests := []struct {
		name  string
		fi    FileInfo
		alg   hash.ChecksumType
		isMP  bool
		value string
		extra map[string]string
	}{
		{"single-part SHA256", checksumTestObject(t, hash.ChecksumSHA256, false, p1), hash.ChecksumSHA256, false, enc(hash.ChecksumSHA256, p1), nil},
		{"single-part CRC32", checksumTestObject(t, hash.ChecksumCRC32, false, p1), hash.ChecksumCRC32, false, enc(hash.ChecksumCRC32, p1), nil},
		{"single-part CRC64NVME", checksumTestObject(t, hash.ChecksumCRC64NVME, false, p1), hash.ChecksumCRC64NVME, false, enc(hash.ChecksumCRC64NVME, p1), nil},
		{"multipart COMPOSITE CRC32C", checksumTestObject(t, hash.ChecksumCRC32C, false, p1, p2), hash.ChecksumCRC32C, true, composite(hash.ChecksumCRC32C), nil},
		{"multipart COMPOSITE SHA256", checksumTestObject(t, hash.ChecksumSHA256, false, p1, p2), hash.ChecksumSHA256, true, composite(hash.ChecksumSHA256), nil},
		{"multipart FULL_OBJECT CRC32", checksumTestObject(t, hash.ChecksumCRC32, true, p1, p2), hash.ChecksumCRC32, true, enc(hash.ChecksumCRC32, whole), full},
		{"multipart FULL_OBJECT CRC32C", checksumTestObject(t, hash.ChecksumCRC32C, true, p1, p2), hash.ChecksumCRC32C, true, enc(hash.ChecksumCRC32C, whole), full},
		{"multipart CRC64NVME", checksumTestObject(t, hash.ChecksumCRC64NVME, false, p1, p2), hash.ChecksumCRC64NVME, true, enc(hash.ChecksumCRC64NVME, whole), full},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oi := tt.fi.ToObjectInfo("bucket", "object", true)
			want := map[string]string{tt.alg.Key(): tt.value, xhttp.AmzChecksumAlgo: tt.alg.String()}
			maps.Copy(want, tt.extra)
			got, isMP := getCRCMeta(oi, 0, nil)
			if isMP != tt.isMP {
				t.Errorf("isMP: got %t, want %t", isMP, tt.isMP)
			}
			if !maps.Equal(got, want) {
				t.Errorf("object headers: got %v, want %v", got, want)
			}
			if !tt.isMP {
				return
			}
			// Part headers carry the part checksum and never a type.
			want = map[string]string{tt.alg.Key(): enc(tt.alg, p2), xhttp.AmzChecksumAlgo: tt.alg.String()}
			if got, _ := getCRCMeta(oi, 2, nil); !maps.Equal(got, want) {
				t.Errorf("part 2 headers: got %v, want %v", got, want)
			}
		})
	}
}

// TestReplicateObjectChecksumTypes replicates objects with checksums through
// the S3 API of a test server, and checks that the replica gets the same
// checksum as the source.
func TestReplicateObjectChecksumTypes(t *testing.T) {
	ctx := context.Background()
	// Leave no object layer behind: unit tests that run later in the package
	// rely on newObjectLayerFn() returning nil.
	defer resetTestGlobals()
	ts := StartTestServer(t, ErasureSDStr)
	defer ts.Stop()

	clnt, err := minio.New(strings.TrimPrefix(ts.Server.URL, "http://"), &minio.Options{
		Creds: credentials.NewStaticV4(ts.AccessKey, ts.SecretKey, ""),
	})
	if err != nil {
		t.Fatal(err)
	}
	core := &minio.Core{Client: clnt}
	for _, bucket := range []string{"src", "dst"} {
		if err := clnt.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := clnt.EnableVersioning(ctx, bucket); err != nil {
			t.Fatal(err)
		}
	}

	small := []byte("single part object")
	p1 := bytes.Repeat([]byte("a"), 5<<20)
	p2 := []byte("last part")
	tests := []struct {
		name      string
		alg       hash.ChecksumType
		multipart bool
		full      bool
		copyOf    string // server-side copy of an object created above
	}{
		{"put-SHA256", hash.ChecksumSHA256, false, false, ""},
		{"put-CRC32", hash.ChecksumCRC32, false, false, ""},
		{"mp-COMPOSITE-CRC32C", hash.ChecksumCRC32C, true, false, ""},
		{"mp-COMPOSITE-SHA256", hash.ChecksumSHA256, true, false, ""},
		{"mp-FULL_OBJECT-CRC32", hash.ChecksumCRC32, true, true, ""},
		{"mp-FULL_OBJECT-CRC32C", hash.ChecksumCRC32C, true, true, ""},
		{"mp-CRC64NVME", hash.ChecksumCRC64NVME, true, false, ""},
		// The copy keeps the multipart FULL_OBJECT checksum of its source
		// but is not multipart, so it replicates with a single PUT.
		{"copy-FULL_OBJECT-CRC32", hash.ChecksumCRC32, false, true, "mp-FULL_OBJECT-CRC32"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			object := tt.name
			// Upload the source object like an S3 client does.
			switch {
			case tt.copyOf != "":
				_, err := core.CopyObject(ctx, "src", tt.copyOf, "src", object, nil, minio.CopySrcOptions{}, minio.PutObjectOptions{})
				if err != nil {
					t.Fatal(err)
				}
			case !tt.multipart:
				_, err := core.PutObject(ctx, "src", object, bytes.NewReader(small), int64(len(small)), "", "", minio.PutObjectOptions{
					UserMetadata: map[string]string{tt.alg.Key(): hash.NewChecksumFromData(tt.alg, small).Encoded},
				})
				if err != nil {
					t.Fatal(err)
				}
			default:
				meta := map[string]string{xhttp.AmzChecksumAlgo: tt.alg.String()}
				if tt.full {
					meta[xhttp.AmzChecksumType] = xhttp.AmzChecksumTypeFullObject
				}
				uploadID, err := core.NewMultipartUpload(ctx, "src", object, minio.PutObjectOptions{UserMetadata: meta})
				if err != nil {
					t.Fatal(err)
				}
				var parts []minio.CompletePart
				for i, p := range [][]byte{p1, p2} {
					h := http.Header{}
					h.Set(tt.alg.Key(), hash.NewChecksumFromData(tt.alg, p).Encoded)
					pi, err := core.PutObjectPart(ctx, "src", object, uploadID, i+1, bytes.NewReader(p), int64(len(p)), minio.PutObjectPartOptions{CustomHeader: h})
					if err != nil {
						t.Fatal(err)
					}
					parts = append(parts, minio.CompletePart{
						PartNumber: pi.PartNumber, ETag: pi.ETag,
						ChecksumCRC32: pi.ChecksumCRC32, ChecksumCRC32C: pi.ChecksumCRC32C,
						ChecksumSHA1: pi.ChecksumSHA1, ChecksumSHA256: pi.ChecksumSHA256,
						ChecksumCRC64NVME: pi.ChecksumCRC64NVME,
					})
				}
				if _, err := core.CompleteMultipartUpload(ctx, "src", object, uploadID, parts, minio.PutObjectOptions{}); err != nil {
					t.Fatal(err)
				}
			}

			// Replicate it the way replicateObject does.
			gr, err := ts.Obj.GetObjectNInfo(ctx, "src", object, nil, http.Header{}, ObjectOptions{Versioned: true, ReplicationRequest: true})
			if err != nil {
				t.Fatal(err)
			}
			defer gr.Close()
			objInfo := gr.ObjInfo
			putOpts, isMP, err := putReplicationOpts(ctx, "", objInfo)
			if err != nil {
				t.Fatal(err)
			}
			if isMP != tt.multipart {
				t.Fatalf("multipart replication: got %t, want %t", isMP, tt.multipart)
			}
			if isMP {
				err = replicateObjectWithMultipart(ctx, core, "dst", object, gr, objInfo, putOpts)
			} else {
				size, serr := objInfo.GetActualSize()
				if serr != nil {
					t.Fatal(serr)
				}
				_, err = core.PutObject(ctx, "dst", object, gr, size, "", "", putOpts)
			}
			if err != nil {
				t.Fatalf("replication failed: %v", err)
			}

			src, err := clnt.StatObject(ctx, "src", object, minio.StatObjectOptions{Checksum: true})
			if err != nil {
				t.Fatal(err)
			}
			dst, err := clnt.StatObject(ctx, "dst", object, minio.StatObjectOptions{Checksum: true})
			if err != nil {
				t.Fatal(err)
			}
			checksums := func(oi minio.ObjectInfo) string {
				return strings.Join([]string{oi.ChecksumMode, oi.ChecksumCRC32, oi.ChecksumCRC32C, oi.ChecksumSHA1, oi.ChecksumSHA256, oi.ChecksumCRC64NVME}, "|")
			}
			if checksums(src) == "|||||" || checksums(dst) != checksums(src) {
				t.Errorf("replica checksum %q, source %q", checksums(dst), checksums(src))
			}
		})
	}
}
