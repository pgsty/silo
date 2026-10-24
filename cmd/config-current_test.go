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
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/config/notify"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/event/target"
	"github.com/pgsty/silo-pkg/v3/env"
)

type webhookConfigObjectLayer struct{ ObjectLayer }

func (webhookConfigObjectLayer) SetDriveCounts() []int { return nil }

func TestNotifyWebhookDynamicConfig(t *testing.T) {
	previous := globalEventNotifier
	previousConfig := globalServerConfig
	globalServerConfig = config.New()
	globalEventNotifier = NewEventNotifier(t.Context())
	globalEventNotifier.targetsInitialized = true
	t.Cleanup(func() {
		globalEventNotifier.RemoveAllBucketTargets()
		globalEventNotifier = previous
		globalServerConfig = previousConfig
	})

	received := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("Authorization")
	}))
	defer server.Close()
	cfg := config.New()
	kvs := notify.DefaultWebhookKVS.Clone()
	kvs.Set(config.Enable, config.EnableOn)
	kvs.Set(target.WebhookEndpoint, server.URL)
	kvs.Set(target.WebhookAuthToken, "first")
	cfg[config.NotifyWebhookSubSys]["live"] = kvs
	id := event.TargetID{ID: "live", Name: "webhook"}
	globalEventNotifier.AddRulesMap("bucket", event.NewRulesMap([]event.Name{event.ObjectCreatedPut}, "*", id))

	apply := func() {
		t.Helper()
		if err := applyDynamicConfigForSubSys(t.Context(), webhookConfigObjectLayer{}, cfg, config.NotifyWebhookSubSys); err != nil {
			t.Fatal(err)
		}
	}
	receive := func() string {
		t.Helper()
		select {
		case auth := <-received:
			return auth
		case <-time.After(5 * time.Second):
			t.Fatal("webhook did not receive an event")
			return ""
		}
	}
	apply()
	if !globalEventNotifier.targetList.Exists(id) {
		t.Fatal("new webhook is unavailable until server restart")
	}
	if !config.SubSystemsDynamic.Contains(config.NotifyWebhookSubSys) {
		t.Fatal("webhook config updates still require a restart")
	}
	if !slices.Contains(globalEventNotifier.GetARNList(), id.ToARN(globalSite.Region()).String()) {
		t.Fatal("new webhook ARN is not visible")
	}
	globalEventNotifier.targetList.Send(event.Event{}, event.NewTargetIDSet(id), true)
	if got := receive(); got != "Bearer first" {
		t.Fatalf("authorization = %q", got)
	}

	kvs.Set(target.WebhookAuthToken, "second")
	apply()
	globalEventNotifier.targetList.Send(event.Event{}, event.NewTargetIDSet(id), true)
	if got := receive(); got != "Bearer second" {
		t.Fatalf("authorization after reload = %q", got)
	}
	kvs.Set(target.WebhookQueueDir, t.TempDir())
	if err := validateConfig(t.Context(), cfg, config.NotifyWebhookSubSys); err == nil {
		t.Fatal("admin validation accepted a queue move before config persistence")
	}
	kvs.Set(target.WebhookQueueDir, "")

	kvs.Set(target.WebhookEndpoint, "://invalid")
	if err := applyDynamicConfigForSubSys(t.Context(), webhookConfigObjectLayer{}, cfg, config.NotifyWebhookSubSys); err == nil {
		t.Fatal("invalid webhook configuration was accepted")
	}
	globalEventNotifier.targetList.Send(event.Event{}, event.NewTargetIDSet(id), true)
	if got := receive(); got != "Bearer second" {
		t.Fatalf("invalid reload changed the active webhook: %q", got)
	}

	delete(cfg[config.NotifyWebhookSubSys], "live")
	apply()
	if globalEventNotifier.targetList.Exists(id) {
		t.Fatal("deleted webhook is still active")
	}
}

func TestDynamicConfigAttemptsEverySubsystemAfterFailure(t *testing.T) {
	previousNotifier, previousConfig := globalEventNotifier, globalServerConfig
	previousDynamic := config.SubSystemsDynamic
	globalEventNotifier = NewEventNotifier(t.Context())
	globalEventNotifier.targetsInitialized = true
	globalServerConfig = config.New()
	config.SubSystemsDynamic = map[string]struct{}{config.NotifyWebhookSubSys: {}, config.CompressionSubSys: {}}
	t.Cleanup(func() {
		globalEventNotifier.RemoveAllBucketTargets()
		globalEventNotifier, globalServerConfig = previousNotifier, previousConfig
		config.SubSystemsDynamic = previousDynamic
	})
	cfg := config.New()
	webhook := notify.DefaultWebhookKVS.Clone()
	webhook.Set(config.Enable, config.EnableOn)
	webhook.Set(target.WebhookEndpoint, "://invalid")
	cfg[config.NotifyWebhookSubSys]["broken"] = webhook
	compression := cfg[config.CompressionSubSys][config.Default]
	compression.Set(config.Enable, "invalid")
	cfg[config.CompressionSubSys][config.Default] = compression
	err := applyDynamicConfig(t.Context(), webhookConfigObjectLayer{}, cfg)
	if err == nil || !strings.Contains(err.Error(), "Compression") || !strings.Contains(err.Error(), "webhook notification") {
		t.Fatalf("did not attempt both subsystems: %v", err)
	}
}

func TestWebhookValidationWithEnvironmentQueue(t *testing.T) {
	previous := globalEventNotifier
	globalEventNotifier = NewEventNotifier(t.Context())
	globalEventNotifier.targetsInitialized = true
	t.Cleanup(func() {
		globalEventNotifier.RemoveAllBucketTargets()
		globalEventNotifier = previous
	})
	t.Setenv(target.EnvWebhookQueueDir+"_live", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cfg := config.New()
	kvs := notify.DefaultWebhookKVS.Clone()
	kvs.Set(config.Enable, config.EnableOn)
	kvs.Set(target.WebhookEndpoint, server.URL)
	cfg[config.NotifyWebhookSubSys]["live"] = kvs
	if err := globalEventNotifier.reloadWebhookTargets(cfg); err != nil {
		t.Fatal(err)
	}
	kvs.Set(target.WebhookAuthToken, "updated")
	if err := validateConfig(t.Context(), cfg, config.NotifyWebhookSubSys); err != nil {
		t.Fatalf("effective queue directory did not change: %v", err)
	}
	// Environment overrides must not hide invalid persisted configuration.
	kvs.Set(target.WebhookQueueDir, "relative/path")
	if err := validateConfig(t.Context(), cfg, config.NotifyWebhookSubSys); err == nil {
		t.Fatal("invalid persisted queue directory was accepted")
	}
	kvs.Set(target.WebhookQueueDir, "")
	// Other config validators temporarily disable environment merging. A peer
	// reload must wait for them rather than installing the stored fallback.
	unlock := env.LockSetEnv()
	env.SetEnvOff()
	done := make(chan error, 1)
	go func() { done <- globalEventNotifier.reloadWebhookTargets(cfg) }()
	var early bool
	select {
	case <-done:
		early = true
	case <-time.After(100 * time.Millisecond):
	}
	env.SetEnvOn()
	unlock()
	if early {
		t.Fatal("reload parsed configuration while environment merging was disabled")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not resume after configuration validation")
	}
}

func TestWebhookReloadBeforeWorkerInitialization(t *testing.T) {
	notifier := NewEventNotifier(t.Context())
	t.Cleanup(notifier.RemoveAllBucketTargets)
	cfg := config.New()
	if err := notifier.loadTargets(t.Context(), cfg, NewHTTPTransport()); err != nil {
		t.Fatal(err)
	}
	kvs := notify.DefaultWebhookKVS.Clone()
	kvs.Set(config.Enable, config.EnableOn)
	kvs.Set(target.WebhookEndpoint, "http://127.0.0.1:1")
	cfg[config.NotifyWebhookSubSys]["early"] = kvs
	if err := notifier.reloadWebhookTargets(cfg); err != nil {
		t.Fatal(err)
	}
	if err := notifier.InitBucketTargets(t.Context(), webhookConfigObjectLayer{}); err != nil {
		t.Fatal(err)
	}
	if !notifier.targetList.Exists(event.TargetID{ID: "early", Name: "webhook"}) {
		t.Fatal("acknowledged reload was lost during notification worker initialization")
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
