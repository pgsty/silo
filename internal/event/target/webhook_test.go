// Copyright (c) 2026 mr javad seydi
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

package target

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/store"
	xnet "github.com/pgsty/silo-pkg/v3/net"
)

func webhookClientCertificate(t *testing.T, name string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestWebhookConcurrentTLSInitializationAndClose(t *testing.T) {
	cert, key := webhookClientCertificate(t, "concurrent")
	for range 100 {
		client := newWebhookClient(t.Context(), WebhookArgs{ClientCert: cert, ClientKey: key}, &http.Transport{DialContext: (&net.Dialer{}).DialContext})
		var wg sync.WaitGroup
		wg.Go(func() {
			if err := client.init(); err != nil {
				t.Error(err)
			}
		})
		wg.Go(client.close)
		wg.Wait()
	}
}

func TestWebhookReloadClientCertificate(t *testing.T) {
	received := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		received <- r.TLS.PeerCertificates[0].Subject.CommonName
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	endpoint, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	args := WebhookArgs{Enable: true, Endpoint: *endpoint}
	args.ClientCert, args.ClientKey = webhookClientCertificate(t, "first")
	transport := server.Client().Transport.(*http.Transport)
	target, err := NewWebhookTarget(t.Context(), "tls", args, nil, transport)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.Save(event.Event{}); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "first" {
		t.Fatalf("client certificate = %q", got)
	}
	args.ClientCert, args.ClientKey = webhookClientCertificate(t, "second")
	target.Update(args, transport)
	if err := target.Save(event.Event{}); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "second" {
		t.Fatalf("client certificate after reload = %q", got)
	}
}

func TestWebhookUpdateRetiresClientAfterInFlightPOST(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-release }))
	defer server.Close()
	endpoint, err := xnet.ParseHTTPURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	args := WebhookArgs{Enable: true, Endpoint: *endpoint}
	cert, key := webhookClientCertificate(t, "in-flight")
	dir := t.TempDir()
	args.ClientCert, args.ClientKey = filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if err := os.Symlink(cert, args.ClientCert); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, args.ClientKey); err != nil {
		t.Fatal(err)
	}
	target, err := NewWebhookTarget(t.Context(), "test", args, nil, http.DefaultTransport.(*http.Transport))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	old := target.currentClient()
	done := make(chan error, 1)
	go func() { done <- target.Save(event.Event{}) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("POST did not start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("POST did not start")
	}
	target.Update(args, http.DefaultTransport.(*http.Transport))
	if old.ctx.Err() != nil {
		close(release)
		<-done
		t.Fatal("old client retired before POST finished")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if old.ctx.Err() == nil {
		t.Fatal("old client was not retired after POST")
	}
}

type blockingWebhookStore struct {
	store.Store[event.Event]
	started, release chan struct{}
}

func (s *blockingWebhookStore) Put(event.Event) (store.Key, error) {
	close(s.started)
	<-s.release
	return store.Key{}, nil
}

func TestWebhookCloseCancelsWhilePutIsBlocked(t *testing.T) {
	target, err := NewWebhookTarget(t.Context(), "test", WebhookArgs{}, nil, http.DefaultTransport.(*http.Transport))
	if err != nil {
		t.Fatal(err)
	}
	s := &blockingWebhookStore{started: make(chan struct{}), release: make(chan struct{})}
	target.store = s
	putDone := make(chan struct{})
	go func() { defer close(putDone); target.Save(event.Event{}) }()
	<-s.started
	closed := make(chan struct{})
	go func() { target.Close(); close(closed) }()
	select {
	case <-target.ctx.Done():
	case <-time.After(time.Second):
		close(s.release)
		<-putDone
		<-closed
		t.Fatal("Close did not cancel while Put was blocked")
	}
	select {
	case <-closed:
		t.Fatal("Close did not wait for the pending write")
	default:
	}
	close(s.release)
	<-putDone
	<-closed
}
