// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/logger"
	httpTarget "github.com/minio/minio/internal/logger/target/http"
	types "github.com/minio/minio/internal/logger/target/loggertypes"
)

type webhookConfigObjectLayer struct {
	ObjectLayer
}

func (webhookConfigObjectLayer) SetDriveCounts() []int { return []int{1} }

// TestDynamicWebhookOutlivesConfigContext applies logger targets the way a
// peer reload does: under a bounded context that ends when the handler returns.
func TestDynamicWebhookOutlivesConfigContext(t *testing.T) {
	for _, subSys := range []string{config.AuditWebhookSubSys, config.LoggerWebhookSubSys, config.AuditKafkaSubSys} {
		for _, queue := range []struct {
			name     string
			disk     bool
			failInit bool
		}{
			{name: "disk=false"},
			{name: "disk=true", disk: true},
			{name: "disk=unavailable", disk: true, failInit: true},
		} {
			if subSys == config.AuditKafkaSubSys && queue.failInit {
				// An unopenable Kafka queue starts no goroutine.
				continue
			}
			t.Run(subSys+"/"+queue.name, func(t *testing.T) {
				// Isolate global target registries and wait for all workers to exit
				// before the parent removes the disk queue.
				if os.Getenv("_SILO_WEBHOOK_CONTEXT_TEST") != t.Name() {
					executable, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					queueDir := ""
					if queue.disk {
						queueDir = t.TempDir()
					}
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					child := exec.CommandContext(ctx, executable,
						"-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$",
						"-test.v", "-test.timeout=25s")
					// Logger targets from the environment would join the registries.
					for _, kv := range os.Environ() {
						if !strings.HasPrefix(kv, "MINIO_AUDIT_") && !strings.HasPrefix(kv, "MINIO_LOGGER_") {
							child.Env = append(child.Env, kv)
						}
					}
					child.Env = append(child.Env,
						"_SILO_WEBHOOK_CONTEXT_TEST="+t.Name(),
						"_SILO_WEBHOOK_QUEUE_DIR="+queueDir)
					output, err := child.CombinedOutput()
					if err != nil {
						t.Fatalf("isolated webhook test: %v\n%s", err, output)
					}
					t.Logf("%s", output)
					return
				}

				if subSys == config.AuditKafkaSubSys {
					testDynamicKafkaOutlivesConfigContext(t, os.Getenv("_SILO_WEBHOOK_QUEUE_DIR"))
					return
				}

				targets := logger.AuditTargets
				if subSys == config.LoggerWebhookSubSys {
					targets = logger.SystemTargets
				}
				received := make(chan string, 8)
				receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var entry struct{ Marker string }
					if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
						t.Errorf("decode webhook: %v", err)
					}
					received <- entry.Marker
					w.WriteHeader(http.StatusOK)
				}))
				t.Cleanup(receiver.Close)

				queueDir := os.Getenv("_SILO_WEBHOOK_QUEUE_DIR")
				if queue.failInit {
					queueDir = filepath.Join(queueDir, "queue")
					if err := os.WriteFile(queueDir, []byte("not a directory"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				cfg := newServerConfig()
				_, err := cfg.SetKVS(fmt.Sprintf("%s:context-test enable=on endpoint=%s queue_size=16 batch_size=1 queue_dir=%s http_timeout=1s retry_interval=100ms",
					subSys, receiver.URL, queueDir), config.DefaultKVS)
				if err != nil {
					t.Fatal(err)
				}
				// A reload cancels the target it replaces; clean up only the last one.
				var current *httpTarget.Target
				t.Cleanup(func() {
					if current != nil {
						current.Cancel()
					}
				})
				// reload applies the subsystem the way a peer does and returns the
				// registered target once the bounded reload context has ended.
				reload := func() *httpTarget.Target {
					t.Helper()
					ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancel()
					if err := applyDynamicConfigForSubSys(ctx, webhookConfigObjectLayer{}, cfg, subSys); err != nil {
						t.Fatal(err)
					}
					var target *httpTarget.Target
					for _, candidate := range targets() {
						if candidate.Endpoint() == receiver.URL {
							if target != nil {
								t.Fatal("configured webhook was registered twice")
							}
							target = candidate.(*httpTarget.Target)
						}
					}
					if target == nil {
						t.Fatal("configured webhook was not registered")
					}
					current = target
					return target
				}

				target := reload()
				if err := target.Send(t.Context(), struct{ Marker string }{"after-reload"}); err != nil {
					t.Fatal(err)
				}
				if queue.failInit {
					// A failed initialization starts no worker: the record stays queued.
					select {
					case got := <-received:
						t.Fatalf("received %q before the queue was initialized", got)
					case <-time.After(250 * time.Millisecond):
					}
					if got := target.Stats().QueueLength; got != 1 {
						t.Fatalf("failed queue consumed an event: queue length %d", got)
					}
					// After the operator repairs queue_dir, applying the configuration
					// again replaces the target, which must take over the record.
					if err := os.Remove(queueDir); err != nil {
						t.Fatal(err)
					}
					target = reload()
				}
				select {
				case got := <-received:
					if got != "after-reload" {
						t.Fatalf("received marker %q, want after-reload", got)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("webhook stopped after reload returned; stats: %+v", target.Stats())
				}
			})
		}
	}
}

// testDynamicKafkaOutlivesConfigContext runs in the isolated child process.
// With a queue_dir, Kafka records reach the broker only through the disk
// replay, which polls the queue every few seconds.
func testDynamicKafkaOutlivesConfigContext(t *testing.T, queueDir string) {
	const topic = "audit-context-test"
	broker := sarama.NewMockBroker(t, 1)
	t.Cleanup(broker.Close)
	broker.SetHandlerByMap(map[string]sarama.MockResponse{
		"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
			{ApiKey: 0, MinVersion: 0, MaxVersion: 8},  // Produce
			{ApiKey: 3, MinVersion: 0, MaxVersion: 11}, // Metadata
			{ApiKey: 18, MinVersion: 0, MaxVersion: 3}, // ApiVersions
		}),
		"MetadataRequest": sarama.NewMockMetadataResponse(t).
			SetBroker(broker.Addr(), broker.BrokerID()).
			SetLeader(topic, 0, broker.BrokerID()),
		"ProduceRequest": sarama.NewMockProduceResponse(t),
	})
	produced := func() (n int) {
		for _, exchange := range broker.History() {
			if _, ok := exchange.Request.(*sarama.ProduceRequest); ok {
				n++
			}
		}
		return n
	}

	cfg := newServerConfig()
	_, err := cfg.SetKVS(fmt.Sprintf("%s:context-test enable=on brokers=%s topic=%s queue_size=16 queue_dir=%s",
		config.AuditKafkaSubSys, broker.Addr(), topic, queueDir), config.DefaultKVS)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err := applyDynamicConfigForSubSys(ctx, webhookConfigObjectLayer{}, cfg, config.AuditKafkaSubSys); err != nil {
		t.Fatal(err)
	}
	var target logger.Target
	for _, candidate := range logger.AuditTargets() {
		if candidate.Type() == types.TargetKafka {
			if target != nil {
				t.Fatal("more than one Kafka target was registered")
			}
			target = candidate
		}
	}
	if target == nil {
		t.Fatal("configured Kafka target was not registered")
	}
	t.Cleanup(target.Cancel)
	// Returning from the peer reload cancels its bounded context.
	cancel()

	before := produced()
	if err := target.Send(t.Context(), struct{ Marker string }{"after-reload"}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); produced() == before; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("Kafka target stopped after reload returned; stats: %+v", target.Stats())
		}
	}
}

func TestServerConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	objLayer, fsDir, err := prepareFS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(fsDir)

	if err = newTestConfig(globalMinioDefaultRegion, objLayer); err != nil {
		t.Fatalf("Init Test config failed")
	}

	if globalSite.Region() != globalMinioDefaultRegion {
		t.Errorf("Expecting region `us-east-1` found %s", globalSite.Region())
	}

	// Set new region and verify.
	config.SetRegion(globalServerConfig, "us-west-1")
	site, err := config.LookupSite(
		globalServerConfig[config.SiteSubSys][config.Default],
		globalServerConfig[config.RegionSubSys][config.Default],
	)
	if err != nil {
		t.Fatal(err)
	}
	if site.Region() != "us-west-1" {
		t.Errorf("Expecting region `us-west-1` found %s", globalSite.Region())
	}

	if err := saveServerConfig(t.Context(), objLayer, globalServerConfig); err != nil {
		t.Fatalf("Unable to save updated config file %s", err)
	}

	// Initialize server config.
	if err := loadConfig(objLayer, nil); err != nil {
		t.Fatalf("Unable to initialize from updated config file %s", err)
	}
}
