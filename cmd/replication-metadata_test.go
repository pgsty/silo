// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"maps"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"
	"testing"

	xhttp "github.com/minio/minio/internal/http"
)

func TestExtractReplicationMetadataPreservesNormalizedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire []string
		want string
	}{
		{name: "absent"},
		{name: "transport-only", wire: []string{"aws-chunked"}},
		{name: "mixed", wire: []string{"aws-chunked,gzip"}, want: "gzip"},
		{name: "gzip", wire: []string{"gzip"}, want: "gzip"},
		{name: "transport-last", wire: []string{"gzip,aws-chunked"}, want: "gzip"},
		{name: "multiple-values", wire: []string{"aws-chunked", "gzip"}, want: "gzip"},
		{name: "space-before-gzip", wire: []string{"aws-chunked, gzip"}, want: "gzip"},
		{name: "space-before-transport", wire: []string{"gzip, aws-chunked"}, want: "gzip"},
	} {
		for _, lowercase := range []bool{false, true} {
			name := tc.name + "/canonical"
			if lowercase {
				name = tc.name + "/lowercase"
			}
			t.Run(name, func(t *testing.T) {
				header := http.Header{
					"Content-Type":      []string{"application/octet-stream"},
					"X-Amz-Meta-Source": []string{"raw"},
					"X-Minio-Replication-Server-Side-Encryption-Sealed-Key":     []string{"sealed-key"},
					"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm": []string{"DAREv2-HMAC-SHA256"},
					"X-Minio-Replication-Server-Side-Encryption-Iv":             []string{"iv"},
					"X-Minio-Replication-Encrypted-Multipart":                   []string{""},
					"X-Minio-Replication-Actual-Object-Size":                    []string{"1"},
					ReplicationSsecChecksumHeader:                               []string{"checksum"},
					xhttp.AmzMetaUnencryptedContentLength:                       []string{"injected-length"},
					xhttp.AmzMetaUnencryptedContentMD5:                          []string{"injected-md5"},
				}
				if tc.wire != nil {
					header[xhttp.ContentEncoding] = tc.wire
				}
				if lowercase {
					h := make(http.Header, len(header))
					for k, v := range header {
						h[strings.ToLower(k)] = v
					}
					header = h
				}
				metadata, err := extractMetadata(t.Context(), textproto.MIMEHeader(header))
				if err != nil {
					t.Fatal(err)
				}
				if metadata["content-encoding"] != tc.want {
					t.Fatalf("ordinary encoding=%q want=%q", metadata["content-encoding"], tc.want)
				}
				for _, internal := range replicationToInternalHeaders {
					if _, ok := metadata[internal]; ok {
						t.Fatalf("ordinary request accepted internal field %s", internal)
					}
				}
				// Callers own ordinary metadata and may transform it after extraction.
				metadata["content-type"] = "application/wasm"
				for k := range metadata {
					if strings.EqualFold(k, "x-amz-meta-source") {
						metadata[k] = "caller"
					}
				}
				want := maps.Clone(metadata)
				maps.Copy(want, map[string]string{
					"X-Minio-Internal-Server-Side-Encryption-Sealed-Key":     "sealed-key",
					"X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm": "DAREv2-HMAC-SHA256",
					"X-Minio-Internal-Server-Side-Encryption-Iv":             "iv",
					"X-Minio-Internal-Encrypted-Multipart":                   "",
					"X-Minio-Internal-Actual-Object-Size":                    "1",
					ReplicationSsecChecksumHeader:                            "checksum",
				})
				for range 2 {
					if err := extractReplicationMetadataFromMime(t.Context(), textproto.MIMEHeader(header), metadata); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(metadata, want) {
						t.Errorf("restoration changed normalized metadata: got %#v want %#v", metadata, want)
					}
				}
				if tc.want == "" {
					if _, present := metadata["content-encoding"]; present {
						t.Error("transport-only content-encoding key restored")
					}
				}
				for _, key := range []string{xhttp.AmzMetaUnencryptedContentLength, xhttp.AmzMetaUnencryptedContentMD5} {
					if _, present := caseInsensitiveMap(metadata).Lookup(key); present {
						t.Errorf("redacted metadata restored: %s", key)
					}
				}
			})
		}
	}
}

func TestExtractReplicationMetadataNilHeader(t *testing.T) {
	metadata := map[string]string{"content-type": "application/wasm"}
	want := maps.Clone(metadata)
	if err := extractReplicationMetadataFromMime(t.Context(), nil, metadata); err != errInvalidArgument {
		t.Fatalf("nil header: got %v want %v", err, errInvalidArgument)
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("nil input changed metadata: %#v", metadata)
	}
}
