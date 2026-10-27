// Copyright (c) 2015-2026 MinIO, Inc.
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

package notify

import (
	"context"
	"crypto/tls"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/event"
	"github.com/minio/minio/internal/event/target"
)

func TestWebhookReloadDoesNotWaitForPOST(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(strconv.FormatBool(queued), func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/slow" {
					started <- struct{}{}
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
			}))
			defer server.Close()
			defer finish()
			queueDir := ""
			if queued {
				queueDir = t.TempDir()
			}
			cfg := webhookReloadConfig(server.URL+"/slow", queueDir)
			list := event.NewTargetList(t.Context())
			transport := http.DefaultTransport.(*http.Transport)
			if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
				t.Fatal(err)
			}
			id := event.TargetID{ID: "live", Name: "webhook"}
			defer func() { finish(); list.Remove(event.NewTargetIDSet(id)) }()
			go list.Send(event.Event{EventName: event.ObjectCreatedPut}, event.NewTargetIDSet(id), true)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("slow delivery did not start")
			}
			kvs := cfg[config.NotifyWebhookSubSys]["live"]
			kvs.Set(target.WebhookEndpoint, server.URL+"/new")
			done := make(chan error, 1)
			go func() { done <- UpdateWebhookTargets(t.Context(), cfg, list, transport) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Error("reload blocked behind an in-flight POST")
			}
		})
	}
}

func TestWebhookStartupDefersCertificateErrors(t *testing.T) {
	cfg := webhookReloadConfig("http://127.0.0.1:1", "")
	kvs := cfg[config.NotifyWebhookSubSys]["live"]
	cfg[config.NotifyWebhookSubSys]["other"] = kvs.Clone()
	kvs.Set(target.WebhookClientCert, filepath.Join(t.TempDir(), "missing.crt"))
	kvs.Set(target.WebhookClientKey, filepath.Join(t.TempDir(), "missing.key"))
	list, err := FetchEnabledTargets(t.Context(), cfg, &http.Transport{TLSClientConfig: &tls.Config{}})
	if err != nil {
		t.Fatalf("one unreadable client certificate disabled all notification targets: %v", err)
	}
	defer list.Remove(event.NewTargetIDSet(list.List()...))
	if len(list.List()) != 2 {
		t.Fatal("unreadable client certificate prevented other targets from registering")
	}
}

func TestWebhookReloadSkipsUnchangedQueue(t *testing.T) {
	queueDir := filepath.Join(t.TempDir(), "queue")
	cfg := webhookReloadConfig("http://127.0.0.1:1", queueDir)
	list := event.NewTargetList(t.Context())
	transport := http.DefaultTransport.(*http.Transport)
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatal(err)
	}
	defer list.Remove(event.NewTargetIDSet(list.List()...))
	if err := os.Rename(queueDir, queueDir+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queueDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatalf("unchanged webhook reopened its queue directory: %v", err)
	}
	if err := TestWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatalf("validation reopened an unchanged webhook queue: %v", err)
	}
}

func TestWebhookReloadRejectsQueueDirectoryChange(t *testing.T) {
	cfg := webhookReloadConfig("http://127.0.0.1:1", t.TempDir())
	list := event.NewTargetList(t.Context())
	transport := http.DefaultTransport.(*http.Transport)
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatal(err)
	}
	defer list.Remove(event.NewTargetIDSet(list.List()...))
	live := list.Targets()[0]
	if err := live.Save(event.Event{EventName: event.ObjectCreatedPut}); err != nil {
		t.Fatal(err)
	}
	queue := live.Store()
	kvs := cfg[config.NotifyWebhookSubSys]["live"]
	kvs.Set(target.WebhookQueueDir, t.TempDir())
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err == nil {
		t.Error("queue_dir change accepted with pending events in the old directory")
	}
	if live.Store() != queue || queue.Len() != 1 {
		t.Error("reload abandoned the pending queue")
	}
}

type conflictingWebhookTarget struct {
	event.Target
	id event.TargetID
}

func (t conflictingWebhookTarget) ID() event.TargetID { return t.id }

func TestWebhookReloadRegistrationFailureKeepsPreviousConfig(t *testing.T) {
	transport := http.DefaultTransport.(*http.Transport)
	cfg := webhookReloadConfig("http://127.0.0.1:1", "")
	kvs := cfg[config.NotifyWebhookSubSys]["live"]
	kvs.Set(target.WebhookAuthToken, "first")
	cfg[config.NotifyWebhookSubSys]["obsolete"] = kvs.Clone()
	list := event.NewTargetList(t.Context())
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatal(err)
	}
	live := list.TargetMap()[event.TargetID{ID: "live", Name: "webhook"}].(*target.WebhookTarget)
	conflict := conflictingWebhookTarget{Target: live, id: event.TargetID{ID: "extra", Name: "webhook"}}
	if err := list.Add(conflict); err != nil {
		t.Fatal(err)
	}
	defer list.Remove(event.NewTargetIDSet(list.List()...))
	delete(cfg[config.NotifyWebhookSubSys], "obsolete")
	kvs.Set(target.WebhookAuthToken, "second")
	cfg[config.NotifyWebhookSubSys]["extra"] = kvs.Clone()
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err == nil {
		t.Fatal("duplicate target accepted")
	}
	if live.Args().AuthToken != "first" {
		t.Fatal("failed reload committed an in-place update")
	}
	if !list.Exists(event.TargetID{ID: "obsolete", Name: "webhook"}) {
		t.Fatal("failed reload removed a previous target")
	}
}

func TestWebhookCloseCancelsSlowPOST(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(strconv.FormatBool(queued), func(t *testing.T) {
			started, release := make(chan struct{}, 1), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				started <- struct{}{}
				<-release
			}))
			defer server.Close()
			defer close(release)
			queueDir := ""
			if queued {
				queueDir = t.TempDir()
			}
			cfg := webhookReloadConfig(server.URL, queueDir)
			list := event.NewTargetList(t.Context())
			if err := UpdateWebhookTargets(t.Context(), cfg, list, http.DefaultTransport.(*http.Transport)); err != nil {
				t.Fatal(err)
			}
			id := event.TargetID{ID: "live", Name: "webhook"}
			go list.Send(event.Event{EventName: event.ObjectCreatedPut}, event.NewTargetIDSet(id), true)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("slow delivery did not start")
			}
			done := make(chan struct{})
			go func() { list.Remove(event.NewTargetIDSet(id)); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("shutdown waited for the slow POST timeout")
			}
		})
	}
}

func webhookReloadConfig(endpoint, queueDir string) config.Config {
	cfg := make(config.Config)
	for subSys, defaults := range DefaultNotificationKVS {
		cfg[subSys] = map[string]config.KVS{config.Default: defaults.Clone()}
	}
	kvs := DefaultWebhookKVS.Clone()
	kvs.Set(config.Enable, config.EnableOn)
	kvs.Set(target.WebhookEndpoint, endpoint)
	kvs.Set(target.WebhookQueueDir, queueDir)
	kvs.Set(target.WebhookQueueLimit, "2")
	cfg[config.NotifyWebhookSubSys] = map[string]config.KVS{"live": kvs}
	return cfg
}

func TestWebhookValidationDoesNotReplay(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport)
	cfg := webhookReloadConfig(server.URL, t.TempDir())
	targets, err := fetchSubSysTargets(t.Context(), cfg, config.NotifyWebhookSubSys, transport)
	if err != nil {
		t.Fatal(err)
	}
	if err := targets[0].Save(event.Event{EventName: event.ObjectCreatedPut}); err != nil {
		t.Fatal(err)
	}
	if err := targets[0].Close(); err != nil {
		t.Fatal(err)
	}
	if err := TestSubSysNotificationTargets(t.Context(), cfg, config.NotifyWebhookSubSys, transport); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
		t.Fatal("config validation replayed an event from the live queue")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUpdateWebhookTargetsPreservesQueue(t *testing.T) {
	inFlight := make(chan struct{}, 1)
	received := make(chan string, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	defer finish()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old" {
			inFlight <- struct{}{}
			<-release
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		received <- r.URL.Path
	}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{}
	cfg := webhookReloadConfig(server.URL+"/old", t.TempDir())
	list, err := FetchEnabledTargets(t.Context(), cfg, transport)
	if err != nil {
		t.Fatal(err)
	}
	id := event.TargetID{ID: "live", Name: "webhook"}
	defer func() {
		finish()
		list.Remove(event.NewTargetIDSet(id))
	}()
	live := list.TargetMap()[id]
	queue := live.Store()
	if err := live.Save(event.Event{EventName: event.ObjectCreatedPut}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-inFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("queued delivery did not start")
	}
	// An event queued after the replacement's queue snapshot must survive too.
	kvs := cfg[config.NotifyWebhookSubSys]["live"]
	kvs.Set(target.WebhookEndpoint, server.URL+"/new")
	kvs.Set(target.WebhookQueueLimit, "3")
	updated := make(chan error, 1)
	go func() { updated <- UpdateWebhookTargets(t.Context(), cfg, list, transport) }()
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reload waited for an in-flight delivery")
	}
	if err := live.Save(event.Event{EventName: event.ObjectCreatedPut}); err != nil {
		t.Fatal(err)
	}
	finish()
	if list.TargetMap()[id] != live || live.Store() != queue {
		t.Fatal("reload replaced the target identity or its live queue")
	}
	for range 2 {
		select {
		case path := <-received:
			if path != "/new" {
				t.Fatalf("event sent to %q after reload", path)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("pending event was lost during reload")
		}
	}
	// Reapplying the same config must keep the working sender and queue.
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
		t.Fatal("reload duplicated a pending event")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestUpdateWebhookTargetsRejectsInvalidReplacement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	transport := http.DefaultTransport.(*http.Transport)
	cfg := webhookReloadConfig(server.URL, "")
	list := event.NewTargetList(t.Context())
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err != nil {
		t.Fatal(err)
	}
	id := event.TargetID{ID: "live", Name: "webhook"}
	defer list.Remove(event.NewTargetIDSet(id))
	live := list.TargetMap()[id]
	kvs := cfg[config.NotifyWebhookSubSys]["live"]
	kvs.Set(target.WebhookClientCert, filepath.Join(t.TempDir(), "missing.crt"))
	kvs.Set(target.WebhookClientKey, filepath.Join(t.TempDir(), "missing.key"))
	if err := UpdateWebhookTargets(t.Context(), cfg, list, transport); err == nil {
		t.Fatal("invalid TLS files were accepted")
	}
	if list.TargetMap()[id] != live {
		t.Fatal("invalid replacement changed the active target")
	}
	if err := live.Save(event.Event{EventName: event.ObjectCreatedPut}); err != nil {
		t.Fatalf("invalid replacement interrupted the working webhook: %v", err)
	}
}

// Test fixtures. Every value here is deliberately non-functional: the paths do
// not exist and the credentials are placeholders, so a leaked fixture is inert.
const (
	testCredsPath  = "/nonexistent/test.creds"
	testNKeyPath   = "/nonexistent/test.nk"
	testNATSAddr   = "127.0.0.1:4222"
	testNATSSubj   = "test-subject"
	testAMQPURL    = "amqp://guest:guest@127.0.0.1:5672"
	testTargetName = "FITCHECK" // named target from issue #39

	// The config key an operator types into `mc admin config set`. Spelled as a
	// literal so these tests pin the on-disk schema rather than tracking
	// whatever the Go constant happens to say.
	natsCredsKey = "user_credentials"
	// The env var name that the pre-fix migration wrote into the config store
	// as if it were a config key.
	legacyNATSCredsKey = "MINIO_NOTIFY_NATS_USER_CREDENTIALS"
)

// natsKVSFor builds a stored (on-disk) NATS target KVS carrying the three keys
// that issue #39 reported as rejected. config.Merge passes a stored target
// through verbatim rather than layering it over the defaults, so the numeric
// keys the parser reads must be present here too.
func natsKVSFor(credsKey string) config.KVS {
	return config.KVS{
		config.KV{Key: config.Enable, Value: config.EnableOn},
		config.KV{Key: target.NATSAddress, Value: testNATSAddr},
		config.KV{Key: target.NATSSubject, Value: testNATSSubj},
		config.KV{Key: credsKey, Value: testCredsPath},
		config.KV{Key: target.NATSNKeySeed, Value: testNKeyPath},
		config.KV{Key: target.NATSTLSHandshakeFirst, Value: config.EnableOn},
		config.KV{Key: target.NATSPingInterval, Value: "0"},
		config.KV{Key: target.NATSQueueLimit, Value: "0"},
	}
}

// T1: an enable=on NATS target carrying user_credentials / nkey_seed /
// tls_handshake_first must pass key validation. This is the exact shape from
// issue #39 (`mc admin config set us notify_nats:FITCHECK ...`).
func TestCheckValidNotificationKeysNATSJWTKeys(t *testing.T) {
	for _, tgtName := range []string{config.Default, testTargetName} {
		t.Run(tgtName, func(t *testing.T) {
			tgt := map[string]config.KVS{
				tgtName: natsKVSFor(natsCredsKey),
			}
			if err := checkValidNotificationKeysForSubSys(config.NotifyNATSSubSys, tgt); err != nil {
				t.Fatalf("expected NATS JWT/nkey/handshake keys to validate, got: %v", err)
			}
		})
	}
}

// T2: the parser must surface the three values from stored config (no env).
func TestGetNotifyNATSFromStoredKVS(t *testing.T) {
	for _, tgtName := range []string{config.Default, testTargetName} {
		t.Run(tgtName, func(t *testing.T) {
			natsKVS := map[string]config.KVS{
				tgtName: natsKVSFor(natsCredsKey),
			}
			targets, err := GetNotifyNATS(natsKVS, nil)
			if err != nil {
				t.Fatalf("GetNotifyNATS: %v", err)
			}
			args, ok := targets[tgtName]
			if !ok {
				t.Fatalf("target %q missing from result %v", tgtName, targets)
			}
			if args.UserCredentials != testCredsPath {
				t.Errorf("UserCredentials = %q, want %q", args.UserCredentials, testCredsPath)
			}
			if args.NKeySeed != testNKeyPath {
				t.Errorf("NKeySeed = %q, want %q", args.NKeySeed, testNKeyPath)
			}
			if !args.TLSHandshakeFirst {
				t.Errorf("TLSHandshakeFirst = false, want true")
			}
		})
	}
}

// T3: AMQP `immediate` must validate and parse.
func TestNotifyAMQPImmediate(t *testing.T) {
	amqpKVS := map[string]config.KVS{
		config.Default: {
			config.KV{Key: config.Enable, Value: config.EnableOn},
			config.KV{Key: target.AmqpURL, Value: testAMQPURL},
			config.KV{Key: target.AmqpImmediate, Value: config.EnableOn},
			config.KV{Key: target.AmqpDeliveryMode, Value: "0"},
			config.KV{Key: target.AmqpQueueLimit, Value: "0"},
		},
	}
	if err := checkValidNotificationKeysForSubSys(config.NotifyAMQPSubSys, amqpKVS); err != nil {
		t.Fatalf("expected amqp immediate key to validate, got: %v", err)
	}
	targets, err := GetNotifyAMQP(amqpKVS)
	if err != nil {
		t.Fatalf("GetNotifyAMQP: %v", err)
	}
	args, ok := targets[config.Default]
	if !ok {
		t.Fatalf("default target missing from result %v", targets)
	}
	if !args.Immediate {
		t.Errorf("Immediate = false, want true")
	}
	if args.Internal {
		t.Errorf("Internal = true, want false (immediate must not bleed into internal)")
	}
}

// T4 (guard, must hold before and after the fix): environment variables win
// over stored config, for both the default and the `_<TARGET>` suffixed form.
// Env var names are asserted as raw literals so that a rename of the Go
// constant cannot silently change the public interface.
func TestNotifyEnvOverridesStoredKVS(t *testing.T) {
	const (
		envCreds            = "MINIO_NOTIFY_NATS_USER_CREDENTIALS"
		envNKeySeed         = "MINIO_NOTIFY_NATS_NKEY_SEED"
		envHandshakeFirst   = "MINIO_NOTIFY_NATS_TLS_HANDSHAKE_FIRST"
		envAMQPImmediate    = "MINIO_NOTIFY_AMQP_IMMEDIATE"
		envCredsOverride    = "/nonexistent/env-override.creds"
		envNKeySeedOverride = "/nonexistent/env-override.nk"
	)

	t.Run("nats-default", func(t *testing.T) {
		t.Setenv(envCreds, envCredsOverride)
		t.Setenv(envNKeySeed, envNKeySeedOverride)
		t.Setenv(envHandshakeFirst, config.EnableOff)

		natsKVS := map[string]config.KVS{config.Default: natsKVSFor(natsCredsKey)}
		targets, err := GetNotifyNATS(natsKVS, nil)
		if err != nil {
			t.Fatalf("GetNotifyNATS: %v", err)
		}
		args := targets[config.Default]
		if args.UserCredentials != envCredsOverride {
			t.Errorf("UserCredentials = %q, want env value %q", args.UserCredentials, envCredsOverride)
		}
		if args.NKeySeed != envNKeySeedOverride {
			t.Errorf("NKeySeed = %q, want env value %q", args.NKeySeed, envNKeySeedOverride)
		}
		if args.TLSHandshakeFirst {
			t.Errorf("TLSHandshakeFirst = true, want env value false")
		}
	})

	t.Run("nats-named-target", func(t *testing.T) {
		t.Setenv(envCreds+config.Default+testTargetName, envCredsOverride)
		t.Setenv(envNKeySeed+config.Default+testTargetName, envNKeySeedOverride)
		t.Setenv(envHandshakeFirst+config.Default+testTargetName, config.EnableOff)

		natsKVS := map[string]config.KVS{testTargetName: natsKVSFor(natsCredsKey)}
		targets, err := GetNotifyNATS(natsKVS, nil)
		if err != nil {
			t.Fatalf("GetNotifyNATS: %v", err)
		}
		args := targets[testTargetName]
		if args.UserCredentials != envCredsOverride {
			t.Errorf("UserCredentials = %q, want env value %q", args.UserCredentials, envCredsOverride)
		}
		if args.NKeySeed != envNKeySeedOverride {
			t.Errorf("NKeySeed = %q, want env value %q", args.NKeySeed, envNKeySeedOverride)
		}
		if args.TLSHandshakeFirst {
			t.Errorf("TLSHandshakeFirst = true, want env value false")
		}
	})

	t.Run("amqp-immediate", func(t *testing.T) {
		t.Setenv(envAMQPImmediate, config.EnableOn)
		amqpKVS := map[string]config.KVS{
			config.Default: {
				config.KV{Key: config.Enable, Value: config.EnableOn},
				config.KV{Key: target.AmqpURL, Value: testAMQPURL},
				config.KV{Key: target.AmqpDeliveryMode, Value: "0"},
				config.KV{Key: target.AmqpQueueLimit, Value: "0"},
			},
		}
		targets, err := GetNotifyAMQP(amqpKVS)
		if err != nil {
			t.Fatalf("GetNotifyAMQP: %v", err)
		}
		if !targets[config.Default].Immediate {
			t.Errorf("Immediate = false, want env value true")
		}
	})

	// Pin the env var names that the constants must keep producing. These are
	// public interface: renaming one silently breaks every deployment that
	// sets it.
	t.Run("env-names-are-stable", func(t *testing.T) {
		for _, tc := range []struct{ got, want string }{
			{target.EnvNATSUserCredentials, envCreds},
			{target.EnvNATSNKeySeed, envNKeySeed},
			{target.EnvNatsTLSHandshakeFirst, envHandshakeFirst},
			{target.EnvAMQPImmediate, envAMQPImmediate},
		} {
			if tc.got != tc.want {
				t.Errorf("env var name = %q, want %q", tc.got, tc.want)
			}
		}
	})

	// The config key must be the snake_case name, not the env var name.
	t.Run("config-key-names-are-snake-case", func(t *testing.T) {
		for _, tc := range []struct{ got, want string }{
			{target.NATSUserCredentials, natsCredsKey},
			{target.NATSNKeySeed, "nkey_seed"},
			{target.NATSTLSHandshakeFirst, "tls_handshake_first"},
			{target.AmqpImmediate, "immediate"},
		} {
			if tc.got != tc.want {
				t.Errorf("config key = %q, want %q", tc.got, tc.want)
			}
		}
	})
}

// T6: a store written by the pre-fix migration carries the literal env-var name
// as a config key. Such a store must keep loading, and the value must still
// reach the parser. When both the legacy and the current key are present, the
// current key wins.
func TestNotifyNATSLegacyUserCredentialsKey(t *testing.T) {
	const legacyKey = legacyNATSCredsKey
	const newValue = "/nonexistent/new-key.creds"

	t.Run("legacy-key-alone-validates-and-is-read", func(t *testing.T) {
		natsKVS := map[string]config.KVS{
			config.Default: natsKVSFor(legacyKey),
		}
		if err := checkValidNotificationKeysForSubSys(config.NotifyNATSSubSys, natsKVS); err != nil {
			t.Fatalf("legacy-migrated store must keep validating, got: %v", err)
		}
		targets, err := GetNotifyNATS(natsKVS, nil)
		if err != nil {
			t.Fatalf("GetNotifyNATS: %v", err)
		}
		if got := targets[config.Default].UserCredentials; got != testCredsPath {
			t.Errorf("UserCredentials = %q, want fallback to legacy key value %q", got, testCredsPath)
		}
	})

	t.Run("new-key-wins-over-legacy", func(t *testing.T) {
		kvs := natsKVSFor(legacyKey)
		kvs = append(kvs, config.KV{Key: natsCredsKey, Value: newValue})
		natsKVS := map[string]config.KVS{config.Default: kvs}

		if err := checkValidNotificationKeysForSubSys(config.NotifyNATSSubSys, natsKVS); err != nil {
			t.Fatalf("mixed old/new store must validate, got: %v", err)
		}
		targets, err := GetNotifyNATS(natsKVS, nil)
		if err != nil {
			t.Fatalf("GetNotifyNATS: %v", err)
		}
		if got := targets[config.Default].UserCredentials; got != newValue {
			t.Errorf("UserCredentials = %q, want new key value %q", got, newValue)
		}
	})

	t.Run("env-wins-over-legacy-key", func(t *testing.T) {
		const envOverride = "/nonexistent/env-wins.creds"
		t.Setenv(legacyNATSCredsKey, envOverride)

		natsKVS := map[string]config.KVS{config.Default: natsKVSFor(legacyKey)}
		targets, err := GetNotifyNATS(natsKVS, nil)
		if err != nil {
			t.Fatalf("GetNotifyNATS: %v", err)
		}
		if got := targets[config.Default].UserCredentials; got != envOverride {
			t.Errorf("UserCredentials = %q, want env value %q", got, envOverride)
		}
	})

	t.Run("legacy-key-rejected-for-other-subsystems", func(t *testing.T) {
		// The tolerance is NATS-scoped; it must not become a global escape hatch.
		amqpKVS := map[string]config.KVS{
			config.Default: {
				config.KV{Key: config.Enable, Value: config.EnableOn},
				config.KV{Key: target.AmqpURL, Value: testAMQPURL},
				config.KV{Key: legacyKey, Value: testCredsPath},
			},
		}
		if err := checkValidNotificationKeysForSubSys(config.NotifyAMQPSubSys, amqpKVS); err == nil {
			t.Fatal("expected the NATS legacy key to be rejected for the AMQP sub-system")
		}
	})
}

// T9 (characterization, not an endorsement): FetchEnabledTargets fails fast.
// A single sub-system with an invalid key aborts the whole target list, which
// is why one bad notify config disables every other notification target. This
// test pins the current behavior so that a future change to it is deliberate.
func TestFetchEnabledTargetsFailsFastAcrossSubSystems(t *testing.T) {
	cfg := config.Config{
		config.NotifyNATSSubSys: map[string]config.KVS{
			config.Default: {
				config.KV{Key: config.Enable, Value: config.EnableOn},
				config.KV{Key: target.NATSAddress, Value: testNATSAddr},
				config.KV{Key: target.NATSSubject, Value: testNATSSubj},
				config.KV{Key: target.NATSPingInterval, Value: "0"},
				config.KV{Key: target.NATSQueueLimit, Value: "0"},
				config.KV{Key: "this_key_does_not_exist", Value: "junk"},
			},
		},
		// A healthy sub-system that would yield a working target if the call
		// got that far. NotifySubSystems.ToSlice() is sorted, so notify_nats
		// is reached before notify_webhook and the error aborts the loop
		// before this target is ever constructed -- the healthy config is lost
		// without anything being built or dialed.
		config.NotifyWebhookSubSys: map[string]config.KVS{
			config.Default: {
				config.KV{Key: config.Enable, Value: config.EnableOn},
				config.KV{Key: target.WebhookEndpoint, Value: "http://127.0.0.1:65535/"},
				config.KV{Key: target.WebhookQueueLimit, Value: "0"},
			},
		},
	}

	// FetchEnabledTargets dereferences transport.TLSClientConfig unconditionally
	// for some sub-systems, so a real transport is required even though no
	// target here performs I/O.
	transport := &http.Transport{TLSClientConfig: &tls.Config{}}

	targetList, err := FetchEnabledTargets(context.Background(), cfg, transport)
	if err == nil {
		t.Fatal("expected FetchEnabledTargets to fail fast on the invalid sub-system")
	}
	if targetList != nil {
		t.Errorf("target list = %v, want nil (fail-fast discards healthy targets)", targetList)
	}
}

// ---------------------------------------------------------------------------
// T7: source-level consistency guard.
//
// Every config key the parser reads or the legacy migration writes must be
// registered in the sub-system's default KVS, otherwise config.CheckValidKeys
// rejects a config that the parser would happily consume (issue #39).
// ---------------------------------------------------------------------------

// notifySubSysAudit enumerates the notify sub-systems and the symbols that make
// up their config surface. Keep in sync with DefaultNotificationKVS; the audit
// itself asserts that every registered sub-system appears here.
// tolerated lists keys that are not registered but are still accepted by
// checkValidNotificationKeysForSubSys as deprecated keys. The parser may read
// them; the migration must never write them and they stay undocumented.
var notifySubSysAudit = []struct {
	subSys    string
	getFn     string
	setFn     string
	help      config.HelpKVS
	tolerated []string
}{
	{config.NotifyAMQPSubSys, "GetNotifyAMQP", "SetNotifyAMQP", HelpAMQP, nil},
	{config.NotifyESSubSys, "GetNotifyES", "SetNotifyES", HelpES, nil},
	{config.NotifyKafkaSubSys, "GetNotifyKafka", "SetNotifyKafka", HelpKafka, nil},
	{config.NotifyMQTTSubSys, "GetNotifyMQTT", "SetNotifyMQTT", HelpMQTT, nil},
	{config.NotifyMySQLSubSys, "GetNotifyMySQL", "SetNotifyMySQL", HelpMySQL, nil},
	{config.NotifyNATSSubSys, "GetNotifyNATS", "SetNotifyNATS", HelpNATS, []string{legacyNATSUserCredentialsKey}},
	{config.NotifyNSQSubSys, "GetNotifyNSQ", "SetNotifyNSQ", HelpNSQ, nil},
	{config.NotifyPostgresSubSys, "GetNotifyPostgres", "SetNotifyPostgres", HelpPostgres, nil},
	{config.NotifyRedisSubSys, "GetNotifyRedis", "SetNotifyRedis", HelpRedis, nil},
	{config.NotifyWebhookSubSys, "GetNotifyWebhook", "SetNotifyWebhook", HelpWebhook, nil},
}

// notifyPkgConsts resolves bare identifiers used as config keys in this
// package. Compiler-resolved, so they cannot drift.
var notifyPkgConsts = map[string]string{
	"legacyNATSUserCredentialsKey": legacyNATSUserCredentialsKey,
}

// configPkgConsts resolves the `config.X` selectors that appear as config keys
// in parse.go / legacy.go. These are compiler-resolved, so they cannot drift.
var configPkgConsts = map[string]string{
	"Enable":  config.Enable,
	"Comment": config.Comment,
}

// knownUnregisteredWrites is a shrink-only ratchet for inherited migration
// gaps. Do not add entries to silence a new mismatch.
var knownUnregisteredWrites = map[string][]string{}

func TestNotifyConfigKeysAreRegistered(t *testing.T) {
	targetConsts, err := parseTargetPkgStringConsts("../../event/target")
	if err != nil {
		t.Fatalf("resolving internal/event/target constants: %v", err)
	}

	fset := token.NewFileSet()
	readKeys := map[string]map[string]token.Position{}    // fn name -> key -> pos
	writtenKeys := map[string]map[string]token.Position{} // fn name -> key -> pos

	for _, src := range []string{"parse.go", "legacy.go"} {
		f, err := parser.ParseFile(fset, src, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", src, err)
		}
		resolve := func(e ast.Expr) (string, bool) {
			return resolveKeyExpr(t, fset, src, e, targetConsts)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			switch {
			case strings.HasPrefix(name, "GetNotify"):
				readKeys[name] = collectKVGetKeys(fset, fn, resolve)
			case strings.HasPrefix(name, "SetNotify"):
				writtenKeys[name] = collectKVWriteKeys(fset, fn, resolve)
			}
		}
	}

	// Guard against a new sub-system slipping past the audit table.
	audited := map[string]bool{}
	for _, a := range notifySubSysAudit {
		audited[a.subSys] = true
	}
	for subSys := range DefaultNotificationKVS {
		if !audited[subSys] {
			t.Errorf("sub-system %q is registered in DefaultNotificationKVS but missing from notifySubSysAudit", subSys)
		}
	}

	for _, a := range notifySubSysAudit {
		t.Run(a.subSys, func(t *testing.T) {
			defaults := DefaultNotificationKVS[a.subSys]
			registered := map[string]bool{}
			for _, kv := range defaults {
				registered[kv.Key] = true
			}

			read, ok := readKeys[a.getFn]
			if !ok {
				t.Fatalf("%s not found in parse.go/legacy.go", a.getFn)
			}
			for _, key := range sortedKeys(read) {
				if !registered[key] && !slices.Contains(a.tolerated, key) {
					t.Errorf("%s reads key %q (%s) which is not registered in the default KVS for %s",
						a.getFn, key, read[key], a.subSys)
				}
			}
			// Floor assertion, in the opposite direction. Every registered key
			// is in fact read by every GetNotifyX today, so this holds. Its
			// real job is to fail loudly if the read collector ever stops
			// matching the source — a collector that silently returns nothing
			// would otherwise make the check above pass vacuously.
			for _, kv := range defaults {
				if _, ok := read[kv.Key]; !ok {
					t.Errorf("registered key %q for %s is never read by %s; either the key is dead or this audit has gone blind",
						kv.Key, a.subSys, a.getFn)
				}
			}
			// A tolerated key must genuinely be accepted by validation,
			// otherwise reading it is pointless.
			for _, key := range a.tolerated {
				kvs := map[string]config.KVS{config.Default: {
					config.KV{Key: config.Enable, Value: config.EnableOn},
					config.KV{Key: key, Value: "x"},
				}}
				if err := checkValidNotificationKeysForSubSys(a.subSys, kvs); err != nil {
					t.Errorf("tolerated key %q is still rejected for %s: %v", key, a.subSys, err)
				}
			}

			written, ok := writtenKeys[a.setFn]
			if !ok {
				t.Fatalf("%s not found in parse.go/legacy.go", a.setFn)
			}
			allowed := knownUnregisteredWrites[a.setFn]
			for _, key := range sortedKeys(written) {
				if !registered[key] && !slices.Contains(allowed, key) {
					t.Errorf("%s writes key %q (%s) which is not registered in the default KVS for %s",
						a.setFn, key, written[key], a.subSys)
				}
			}
			// Keep the allowlist honest: an entry that no longer corresponds to
			// a real gap must be deleted, not left to rot.
			for _, key := range allowed {
				if registered[key] {
					t.Errorf("%s: %q is registered now; remove it from knownUnregisteredWrites", a.setFn, key)
				} else if _, ok := written[key]; !ok {
					t.Errorf("%s no longer writes %q; remove it from knownUnregisteredWrites", a.setFn, key)
				}
			}

			// Help entries must describe registered keys only. `comment` is
			// accepted for every sub-system by CheckValidKeys and is therefore
			// documented without being registered.
			for _, hkv := range a.help {
				if hkv.Key == config.Comment {
					continue
				}
				if !registered[hkv.Key] {
					t.Errorf("Help entry %q for %s is not registered in the default KVS", hkv.Key, a.subSys)
				}
			}

			// Conversely: every registered key a user can set should be
			// documented, so `mc admin config get` explains it. `enable` is
			// implicit for every target and HiddenIfEmpty keys are deprecated
			// leftovers that are deliberately undocumented.
			for _, kv := range defaults {
				if kv.Key == config.Enable || kv.HiddenIfEmpty {
					continue
				}
				if _, ok := a.help.Lookup(kv.Key); !ok {
					t.Errorf("registered key %q for %s has no Help entry", kv.Key, a.subSys)
				}
			}
		})
	}
}

func sortedKeys(m map[string]token.Position) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// resolveKeyExpr turns a config-key expression into its string value. Only the
// shapes actually used in this package are supported; anything else fails the
// test loudly rather than being skipped, so the audit cannot silently go blind.
func resolveKeyExpr(t *testing.T, fset *token.FileSet, src string, e ast.Expr, targetConsts map[string]string) (string, bool) {
	t.Helper()
	switch v := e.(type) {
	case *ast.Ident:
		val, ok := notifyPkgConsts[v.Name]
		if !ok {
			t.Errorf("%s: %s used as a config key but not listed in notifyPkgConsts; add it",
				fset.Position(v.Pos()), v.Name)
			return "", false
		}
		return val, true
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			if err != nil {
				t.Errorf("%s: unquoting %s: %v", fset.Position(v.Pos()), v.Value, err)
				return "", false
			}
			return s, true
		}
	case *ast.SelectorExpr:
		pkg, ok := v.X.(*ast.Ident)
		if !ok {
			break
		}
		switch pkg.Name {
		case "target":
			val, ok := targetConsts[v.Sel.Name]
			if !ok {
				t.Errorf("%s: cannot resolve target.%s to a string constant", fset.Position(v.Pos()), v.Sel.Name)
				return "", false
			}
			return val, true
		case "config":
			val, ok := configPkgConsts[v.Sel.Name]
			if !ok {
				t.Errorf("%s: config.%s used as a config key but not listed in configPkgConsts; add it",
					fset.Position(v.Pos()), v.Sel.Name)
				return "", false
			}
			return val, true
		}
	}
	t.Errorf("%s: unsupported config-key expression %T in %s; extend resolveKeyExpr", fset.Position(e.Pos()), e, src)
	return "", false
}

// collectKVGetKeys finds every `<x>.Get(<key>)` call inside fn. This is how
// GetNotifyX reads a stored config value.
func collectKVGetKeys(fset *token.FileSet, fn *ast.FuncDecl, resolve func(ast.Expr) (string, bool)) map[string]token.Position {
	keys := map[string]token.Position{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Get" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok || recv.Name != "kv" {
			return true
		}
		if key, ok := resolve(call.Args[0]); ok {
			keys[key] = fset.Position(call.Pos())
		}
		return true
	})
	return keys
}

// collectKVWriteKeys finds every `{Key: <key>, ...}` composite literal inside
// fn. This is how SetNotifyX writes a migrated config.
//
// Both the explicit `config.KV{...}` form and the elided `{...}` form that Go
// permits inside a `config.KVS{...}` literal must be matched: the elided form
// is idiomatic and would otherwise slip past this audit silently.
func collectKVWriteKeys(fset *token.FileSet, fn *ast.FuncDecl, resolve func(ast.Expr) (string, bool)) map[string]token.Position {
	keys := map[string]token.Position{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		// A typed literal that is neither config.KV nor config.KVS cannot hold
		// or contain a config key. An untyped (elided) literal has no type to
		// check, so it must be inspected rather than skipped.
		if sel, ok := lit.Type.(*ast.SelectorExpr); ok && sel.Sel.Name != "KV" && sel.Sel.Name != "KVS" {
			return true
		}
		for _, elt := range lit.Elts {
			kve, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			ident, ok := kve.Key.(*ast.Ident)
			if !ok || ident.Name != "Key" {
				continue
			}
			if key, ok := resolve(kve.Value); ok {
				keys[key] = fset.Position(lit.Pos())
			}
		}
		return true
	})
	return keys
}

// parseTargetPkgStringConsts reads every `Name = "literal"` constant from the
// internal/event/target sources. Those constants are the single source of truth
// for both config keys and env var names.
func parseTargetPkgStringConsts(dir string) (map[string]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Clean(dir), func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					lit, ok := vs.Values[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					out[vs.Names[0].Name] = s
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, errNoTargetConsts
	}
	return out, nil
}

var errNoTargetConsts = errConst("no string constants found in internal/event/target; the audit would be vacuous")

type errConst string

func (e errConst) Error() string { return string(e) }

// Sanity check for the resolver itself: if this ever stops finding known
// constants the audit above would pass vacuously.
func TestParseTargetPkgStringConsts(t *testing.T) {
	consts, err := parseTargetPkgStringConsts("../../event/target")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"NATSAddress":      "address",
		"NATSNKeySeed":     "nkey_seed",
		"AmqpImmediate":    "immediate",
		"EnvAMQPImmediate": "MINIO_NOTIFY_AMQP_IMMEDIATE",
	} {
		if got := consts[name]; got != want {
			t.Errorf("target.%s = %q, want %q", name, got, want)
		}
	}
	if slices.Contains([]string{""}, consts["NATSSubject"]) {
		t.Error("target.NATSSubject resolved to empty string")
	}
}
