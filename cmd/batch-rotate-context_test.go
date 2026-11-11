// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/kms"
)

func TestBatchRotationContextValidation(t *testing.T) {
	previous := GlobalKMS
	GlobalKMS = nil
	t.Cleanup(func() { GlobalKMS = previous })
	for _, encoded := range []string{"not-base64!", base64.StdEncoding.EncodeToString([]byte(`{`)), base64.StdEncoding.EncodeToString([]byte(`{"tenant":1}`)), base64.StdEncoding.EncodeToString([]byte(`[]`))} {
		enc := BatchJobKeyRotateEncryption{Type: ssekms, Key: "key", Context: encoded}
		if err := enc.Validate(); err == nil {
			t.Fatalf("accepted invalid context %q", encoded)
		}
	}
	for _, raw := range []string{"", `{}`, `null`, `{"tenant":"acme"}`} {
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		if raw == "" {
			encoded = ""
		}
		if err := (BatchJobKeyRotateEncryption{Type: ssekms, Key: "key", Context: encoded}).Validate(); err != nil {
			t.Fatalf("context %q: %v", raw, err)
		}
	}
}

func TestBatchRotationContextInitialRetryAndReload(t *testing.T) {
	for _, mode := range []string{"initial", "retry", "reload"} {
		t.Run(mode, func(t *testing.T) {
			f := newBatchAuthzFixture(t)
			previous := GlobalKMS
			t.Cleanup(func() { GlobalKMS = previous })
			configured, err := kms.NewBuiltin("context-key", bytes.Repeat([]byte{0x42}, 32))
			mustIAM(t, err)
			GlobalKMS = configured
			const object = "rotation/context"
			const payload = "a context-bound encryption key keeps this readable"
			metadata := map[string]string{}
			key, err := newEncryptMetadata(f.ctx, crypto.S3KMS, "context-key", nil, f.bucket, object, metadata, kms.Context{"tenant": "old"})
			mustIAM(t, err)
			ciphertext, err := io.ReadAll(crypto.EncryptSinglePart(strings.NewReader(payload), key))
			mustIAM(t, err)
			original, err := f.obj.PutObject(f.ctx, f.bucket, object, mustGetPutObjReader(t, bytes.NewReader(ciphertext), int64(len(ciphertext)), "", ""), ObjectOptions{Versioned: true, UserDefined: metadata})
			mustIAM(t, err)
			contextJSON := `{"tenant":"acme","purpose":"batch-rotation"}`
			encoded := base64.StdEncoding.EncodeToString([]byte(contextJSON))
			rec, job := f.submit(t, globalActiveCred, fmt.Sprintf("keyrotate:\n  apiVersion: v1\n  bucket: %s\n  prefix: rotation/\n  encryption:\n    type: sse-kms\n    key: context-key\n    context: %s\n", f.bucket, encoded))
			if job == nil {
				t.Fatalf("submit: %d %s", rec.Code, rec.Body.String())
			}
			if mode == "retry" {
				GlobalKMS = nil
				err := job.KeyRotate.KeyRotate(f.ctx, f.obj, original, job.Submitter)
				GlobalKMS = configured
				if err == nil {
					t.Fatal("rotation succeeded while KMS was unavailable")
				}
				before, err := f.obj.GetObjectInfo(f.ctx, f.bucket, object, ObjectOptions{VersionID: original.VersionID})
				mustIAM(t, err)
				if before.UserDefined[crypto.MetaContext] != metadata[crypto.MetaContext] {
					t.Fatal("failed attempt changed context")
				}
			}
			if mode == "reload" {
				loaded := &BatchJobRequest{}
				mustIAM(t, loaded.load(f.ctx, f.obj, getJobPath(*job)))
				job = loaded
			}
			mustIAM(t, job.KeyRotate.Start(f.ctx, f.obj, *job))
			progress := f.jobInfo(t, job)
			if !progress.Complete || progress.Failed || progress.Objects != 1 {
				t.Fatalf("rotation incomplete: %+v", progress)
			}
			after, err := f.obj.GetObjectInfo(f.ctx, f.bucket, object, ObjectOptions{VersionID: original.VersionID})
			mustIAM(t, err)
			raw, err := base64.StdEncoding.DecodeString(after.UserDefined[crypto.MetaContext])
			mustIAM(t, err)
			var got kms.Context
			mustIAM(t, json.Unmarshal(raw, &got))
			if !maps.Equal(got, kms.Context{"tenant": "acme", "purpose": "batch-rotation"}) {
				t.Fatalf("stored context %v", got)
			}
			actual, err := crypto.S3KMS.UnsealObjectKey(configured, after.UserDefined, f.bucket, object)
			mustIAM(t, err)
			if actual != key {
				t.Fatal("rotation changed the plaintext data key")
			}
			if got := readCopyChecksumObject(t, f.obj, f.bucket, object, ObjectOptions{VersionID: original.VersionID}); string(got) != payload {
				t.Fatal("rotated object is unreadable")
			}
		})
	}
}
