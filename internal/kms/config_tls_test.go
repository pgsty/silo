// Copyright (c) 2026 Ruohang Feng
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

package kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"aead.dev/mtls"
)

// Exercise the configured MinKMS transport, including the API-key certificate.
// A KES integration test does not cover this separate client implementation.
func TestConnectMinKMSTLSIdentity(t *testing.T) {
	for _, key := range []string{EnvKESEndpoint, EnvKMSSecretKey, EnvKMSSecretKeyFile} {
		t.Setenv(key, "") // Restore the original value after testing absence.
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	key, err := mtls.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var connections []tls.ConnectionState
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/version" {
			t.Errorf("unexpected KMS request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		identity, err := mtls.PeerIdentity(r.TLS)
		if err != nil || identity != key.Identity() {
			t.Errorf("API key identity: got %s, error %v", identity, err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		mu.Lock()
		connections = append(connections, *r.TLS)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// Force a new TLS connection so the second request checks session reuse.
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, `{"version":"2026-10-22T00-00-00Z","api_version":"v1"}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	caDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(caDir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvKMSEndpoint, server.URL)
	t.Setenv(EnvKMSAPIKey, key.String())
	t.Setenv(EnvKMSDefaultKey, "silo-test-key")
	t.Setenv(EnvKMSEnclave, "silo-test-enclave")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Connect(ctx, &ConnectionOptions{CADir: caDir})
	if err != nil {
		t.Fatal(err)
	}
	if client.Type != MinKMS || client.DefaultKey != "silo-test-key" || client.conn.(*kmsConn).enclave != "silo-test-enclave" {
		t.Fatal("MinKMS connection lost its configured identity or key scope")
	}
	for range 2 {
		version, err := client.Version(ctx)
		if err != nil || version != "2026-10-22T00-00-00Z" {
			t.Fatalf("trusted MinKMS: version %q, error %v", version, err)
		}
	}
	mu.Lock()
	if len(connections) != 2 || connections[0].DidResume || !connections[1].DidResume || connections[1].Version != tls.VersionTLS12 {
		t.Errorf("TLS 1.2 client session cache was not preserved: %+v", connections)
	}
	mu.Unlock()

	// An empty CA directory cannot authenticate this private server. The client
	// must reject it instead of silently falling back to insecure TLS.
	untrusted, err := Connect(ctx, &ConnectionOptions{CADir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = untrusted.Version(ctx)
	var unknownCA x509.UnknownAuthorityError
	if !errors.As(err, &unknownCA) {
		t.Fatalf("untrusted KMS server: got %v, want unknown certificate authority", err)
	}
}
