// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Exercise the production RequestServer driver against a real S3 backend.
// The library's filesystem Server and its ReadOnly option are a different path.
func TestSFTPRequestServerObjectOperations(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("TLS=%t", secure), func(t *testing.T) {
			c := &check{t, "ErasureSD"}
			suite := newTestSuiteIAM(TestSuiteCommon{serverType: "ErasureSD", signer: signerV4, secure: secure}, false)
			suite.SetUpSuite(c)
			t.Cleanup(func() { suite.TearDownSuite(c) })
			previousTLS, previousTransport := globalIsTLS, globalRemoteFTPClientTransport
			globalIsTLS = secure
			globalRemoteFTPClientTransport = suite.TestSuiteCommon.client.Transport.(*http.Transport)
			t.Cleanup(func() {
				globalIsTLS, globalRemoteFTPClientTransport = previousTLS, previousTransport
			})

			ctx, cancel := context.WithTimeout(context.Background(), testDefaultTimeout)
			defer cancel()
			connect := func(policy string) *sftp.Client {
				t.Helper()
				accessKey, secretKey := mustGenerateCredentials(c)
				if err := suite.adm.SetUser(ctx, accessKey, secretKey, madmin.AccountEnabled); err != nil {
					t.Fatal(err)
				}
				if _, err := suite.adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{policy}, User: accessKey}); err != nil {
					t.Fatal(err)
				}
				perms, err := sshPasswordAuth(newSSHConnMock(accessKey), []byte(secretKey))
				if err != nil {
					t.Fatal(err)
				}
				return newSFTPRequestTestClient(t, perms)
			}
			client := connect("readwrite")
			bucket := "/" + getRandomBucketName()
			if err := client.Mkdir(bucket); err != nil {
				t.Fatal(err)
			}
			read := func(client *sftp.Client, name string) []byte {
				t.Helper()
				f, err := client.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				data, err := io.ReadAll(f)
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			for _, size := range []int{0, 32767, 32768, 65537} {
				name := fmt.Sprintf("%s/中文-café-%d", bucket, size)
				data := bytes.Repeat([]byte{byte(size)}, size)
				f, err := client.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				if n, err := f.ReadFrom(bytes.NewReader(data)); err != nil || n != int64(size) {
					f.Close()
					t.Fatalf("upload %s: n=%d, err=%v", name, n, err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
				if got := read(client, name); !bytes.Equal(got, data) {
					t.Fatalf("download %s: byte mismatch", name)
				}
				info, err := client.Stat(name)
				if err != nil || info.Size() != int64(size) {
					t.Fatalf("stat %s: info=%v, err=%v", name, info, err)
				}
			}
			entries, err := client.ReadDir(bucket)
			if err != nil || len(entries) != 4 {
				t.Fatalf("list: %d entries, err=%v", len(entries), err)
			}
			name := bucket + "/中文-café-65537"
			original := read(client, name)
			// Include list permission because Client.Remove also tries Rmdir;
			// both requests must observe the denied delete, not a failed listing.
			readonly := connect("consolereadonly")
			if !bytes.Equal(read(readonly, name), original) {
				t.Fatal("readonly download changed content")
			}
			if f, err := readonly.OpenFile(name, os.O_WRONLY|os.O_TRUNC); err == nil {
				_, writeErr := f.Write([]byte("forbidden"))
				closeErr := f.Close()
				// The streaming driver can acknowledge buffered bytes before S3
				// rejects the PUT. Verify the object, not just the write status.
				t.Logf("readonly write: write=%v close=%v", writeErr, closeErr)
			}
			if !bytes.Equal(read(client, name), original) {
				t.Fatal("readonly upload modified content")
			}
			if err := readonly.Remove(name); err == nil {
				t.Fatal("readonly delete succeeded")
			}
			if !bytes.Equal(read(client, name), original) {
				t.Fatal("denied operation modified content")
			}
			// Remove retries Rmdir, which can mask a listing error for a user
			// without ListBucket. Check the stored object even if it returns nil.
			withoutList := connect("readonly")
			withoutList.Remove(name)
			if !bytes.Equal(read(client, name), original) {
				t.Fatal("readonly user without listing permission deleted content")
			}
			for operation, err := range map[string]error{
				"hardlink": client.Link(name, bucket+"/hardlink"),
				"symlink":  client.Symlink(name, bucket+"/symlink"),
				"rename":   client.Rename(name, bucket+"/renamed"),
			} {
				if status, ok := err.(*sftp.StatusError); !ok || status.Code != uint32(sftp.ErrSSHFxOpUnsupported) {
					t.Fatalf("%s: expected unsupported operation, got %v", operation, err)
				}
			}
			for _, entry := range entries {
				if err := client.Remove(bucket + "/" + entry.Name()); err != nil {
					t.Fatal(err)
				}
			}
			entries, err = client.ReadDir(bucket)
			if err != nil || len(entries) != 0 {
				t.Fatalf("list after deletion: %d entries, err=%v", len(entries), err)
			}
			// SILO exposes a missing object as a directory for stat-then-list
			// clients. Keep that existing virtual-directory behavior.
			if info, err := client.Stat(name); err != nil || !info.IsDir() {
				t.Fatalf("stat virtual directory: info=%v, err=%v", info, err)
			}
			if err := client.RemoveDirectory(bucket); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func newSFTPRequestTestClient(t *testing.T, perms *ssh.Permissions) *sftp.Client {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	deadline := time.Now().Add(time.Minute)
	serverConn.SetDeadline(deadline)
	clientConn.SetDeadline(deadline)
	server := sftp.NewRequestServer(serverConn, NewSFTPDriver(perms, "127.0.0.1"), sftp.WithRSAllocator())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.Serve()
	}()
	t.Cleanup(func() {
		clientConn.Close()
		server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SFTP request server did not stop")
		}
	})
	client, err := sftp.NewClientPipe(clientConn, clientConn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}
