// Copyright (c) 2026 Feng Ruohang
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/kms-go/kes"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/crypto"
	"github.com/minio/minio/internal/kms"
)

// Use the configured KES client over TLS, rather than a mocked KMS interface:
// cancellation must survive every layer, including the HTTP request context.
func connectCancellationKES(t *testing.T, handler http.Handler) *kms.KMS {
	t.Helper()
	for _, key := range []string{kms.EnvKMSEndpoint, kms.EnvKMSSecretKey, kms.EnvKMSSecretKeyFile} {
		t.Setenv(key, "")
		mustIAM(t, os.Unsetenv(key))
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	mustIAM(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	key, err := kes.GenerateAPIKey(nil)
	mustIAM(t, err)
	t.Setenv(kms.EnvKESEndpoint, server.URL)
	t.Setenv(kms.EnvKESAPIKey, key.String())
	t.Setenv(kms.EnvKESDefaultKey, "cancellation-key")
	t.Setenv(kms.EnvKESServerCA, ca)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	k, err := kms.Connect(ctx, nil)
	mustIAM(t, err)
	return k
}

func cancellationDecryptHandler(t *testing.T, k *kms.KMS, before func(*http.Request)) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// KMS Connect periodically describes the default key to keep it cached.
		// This maintenance request is independent of the decrypt under test.
		if r.Method == http.MethodGet && r.URL.Path == "/v1/key/describe/cancellation-key" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"name": "cancellation-key"})
			return
		}
		if r.URL.Path != "/v1/key/decrypt/cancellation-key" {
			t.Errorf("unexpected KES path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var request struct {
			Ciphertext []byte `json:"ciphertext"`
			Context    []byte `json:"context"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		// Drain the HTTP/1 body so net/http can observe a peer disconnect while
		// the handler is blocked in the simulated KES operation.
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		before(r)
		if r.Context().Err() != nil {
			return
		}
		var aad kms.Context
		if err := json.Unmarshal(request.Context, &aad); err != nil {
			t.Error(err)
			return
		}
		plain, err := k.Decrypt(r.Context(), &kms.DecryptRequest{Name: "cancellation-key", Ciphertext: request.Ciphertext, AssociatedData: aad})
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": kes.ErrDecrypt.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string][]byte{"plaintext": plain})
	})
}

func TestKMSRequestCancellation(t *testing.T) {
	for _, operation := range []string{"iam", "sse-list"} {
		for _, expiry := range []string{"cancel", "deadline"} {
			t.Run(operation+"/"+expiry, func(t *testing.T) {
				builtin, err := kms.NewBuiltin("cancellation-key", bytes.Repeat([]byte{42}, 32))
				mustIAM(t, err)
				entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var calls atomic.Int32
				var enteredOnce, canceledOnce sync.Once
				unblock := sync.OnceFunc(func() { close(release) })
				client := connectCancellationKES(t, cancellationDecryptHandler(t, builtin, func(r *http.Request) {
					calls.Add(1)
					enteredOnce.Do(func() { close(entered) })
					select {
					case <-r.Context().Done():
						canceledOnce.Do(func() { close(canceled) })
					case <-release:
					}
				}))
				t.Cleanup(unblock)
				prior := GlobalKMS
				GlobalKMS = client
				t.Cleanup(func() { GlobalKMS = prior })
				var run func(context.Context) error
				if operation == "iam" {
					const name = "config/iam/policies/cancel/policy.json"
					plaintext := []byte(`{"Version":1}`)
					ciphertext, err := config.EncryptBytes(builtin, plaintext, kms.Context{minioMetaBucket: minioMetaBucket + "/" + name})
					mustIAM(t, err)
					run = func(ctx context.Context) error {
						got, err := decryptData(ctx, ciphertext, name)
						if err == nil && !bytes.Equal(got, plaintext) {
							return errors.New("config plaintext changed")
						}
						return err
					}
				} else {
					var metadata []map[string]string
					var buckets, names []string
					var expected []crypto.ObjectKey
					for i := range 3 {
						name := fmt.Sprintf("object-%d", i)
						dek, err := builtin.GenerateKey(context.Background(), &kms.GenerateKeyRequest{AssociatedData: kms.Context{"bucket": "bucket/" + name}})
						mustIAM(t, err)
						key := crypto.GenerateKey(dek.Plaintext, nil)
						sealed := key.Seal(dek.Plaintext, crypto.GenerateIV(nil), crypto.S3.String(), "bucket", name)
						metadata = append(metadata, crypto.S3.CreateMetadata(nil, dek.KeyID, dek.Ciphertext, sealed))
						buckets, names = append(buckets, "bucket"), append(names, name)
						expected = append(expected, key)
					}
					run = func(ctx context.Context) error {
						keys, err := crypto.S3.UnsealObjectKeys(ctx, client, metadata, buckets, names)
						if err != nil {
							return err
						}
						if len(keys) != len(expected) {
							return errors.New("partial key list returned as success")
						}
						for i := range keys {
							if keys[i] != expected[i] {
								return errors.New("object key or ordering changed")
							}
						}
						return nil
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				if expiry == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 300*time.Millisecond)
				}
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- run(ctx) }()
				select {
				case <-entered:
				case err := <-done:
					t.Fatalf("decrypt returned before reaching KES: %v (type=%v)", err, client.Type)
				case <-time.After(5 * time.Second):
					t.Fatal("decrypt did not reach KES")
				}
				want := context.DeadlineExceeded
				if expiry == "cancel" {
					cancel()
					want = context.Canceled
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
				// The current KES SDK may sleep twice for up to 999ms after a
				// deadline error. Include that existing backoff plus the 300ms
				// request deadline; cancellation must still stop new decrypts.
				case <-time.After(3 * time.Second):
					unblock()
					<-done
					t.Fatal("request exceeded the cancellation and KES retry budget")
				}
				awaitIAMPolicyReload(t, canceled)
				if n := calls.Load(); n != 1 {
					t.Fatalf("cancellation launched a fallback or more object decryptions: %d calls", n)
				}
				unblock()
				mustIAM(t, run(context.Background()))
				before := calls.Load()
				cctx, ccancel := context.WithCancel(context.Background())
				ccancel()
				if err := run(cctx); !errors.Is(err, context.Canceled) || calls.Load() != before {
					t.Fatal("already-canceled request still issued decryption work")
				}
			})
		}
	}
}

func TestIAMDecryptAssociatedDataCompatibility(t *testing.T) {
	builtin, err := kms.NewBuiltin("cancellation-key", bytes.Repeat([]byte{42}, 32))
	mustIAM(t, err)
	var calls atomic.Int32
	client := connectCancellationKES(t, cancellationDecryptHandler(t, builtin, func(*http.Request) { calls.Add(1) }))
	prior := GlobalKMS
	GlobalKMS = client
	t.Cleanup(func() { GlobalKMS = prior })
	const name = "config/iam/policies/compat/policy.json"
	plaintext := []byte(`{"Version":1}`)
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			aad, wantCalls := minioMetaBucket+"/"+name, int32(1)
			if legacy {
				aad, wantCalls = name, 2
			}
			ciphertext, err := config.EncryptBytes(builtin, plaintext, kms.Context{minioMetaBucket: aad})
			mustIAM(t, err)
			before := calls.Load()
			got, err := decryptData(context.Background(), ciphertext, name)
			mustIAM(t, err)
			if !bytes.Equal(got, plaintext) || calls.Load()-before != wantCalls {
				t.Fatal("current/legacy encrypted IAM records no longer decrypt correctly")
			}
		})
	}
}
