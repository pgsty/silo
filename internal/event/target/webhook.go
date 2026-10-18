// Copyright (c) 2015-2023 MinIO, Inc.
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

package target

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/minio/minio/internal/event"
	xhttp "github.com/minio/minio/internal/http"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/internal/once"
	"github.com/minio/minio/internal/store"
	"github.com/pgsty/silo-pkg/v3/certs"
	xnet "github.com/pgsty/silo-pkg/v3/net"
)

// Webhook constants
const (
	WebhookEndpoint   = "endpoint"
	WebhookAuthToken  = "auth_token"
	WebhookQueueDir   = "queue_dir"
	WebhookQueueLimit = "queue_limit"
	WebhookClientCert = "client_cert"
	WebhookClientKey  = "client_key"

	EnvWebhookEnable     = "MINIO_NOTIFY_WEBHOOK_ENABLE"
	EnvWebhookEndpoint   = "MINIO_NOTIFY_WEBHOOK_ENDPOINT"
	EnvWebhookAuthToken  = "MINIO_NOTIFY_WEBHOOK_AUTH_TOKEN"
	EnvWebhookQueueDir   = "MINIO_NOTIFY_WEBHOOK_QUEUE_DIR"
	EnvWebhookQueueLimit = "MINIO_NOTIFY_WEBHOOK_QUEUE_LIMIT"
	EnvWebhookClientCert = "MINIO_NOTIFY_WEBHOOK_CLIENT_CERT"
	EnvWebhookClientKey  = "MINIO_NOTIFY_WEBHOOK_CLIENT_KEY"
)

// WebhookArgs - Webhook target arguments.
type WebhookArgs struct {
	Enable     bool            `json:"enable"`
	Endpoint   xnet.URL        `json:"endpoint"`
	AuthToken  string          `json:"authToken"`
	Transport  *http.Transport `json:"-"`
	QueueDir   string          `json:"queueDir"`
	QueueLimit uint64          `json:"queueLimit"`
	ClientCert string          `json:"clientCert"`
	ClientKey  string          `json:"clientKey"`
}

// Validate WebhookArgs fields
func (w WebhookArgs) Validate() error {
	if !w.Enable {
		return nil
	}
	if w.Endpoint.IsEmpty() {
		return errors.New("endpoint empty")
	}
	if w.QueueDir != "" {
		if !filepath.IsAbs(w.QueueDir) {
			return errors.New("queueDir path should be absolute")
		}
	}
	if w.ClientCert != "" && w.ClientKey == "" || w.ClientCert == "" && w.ClientKey != "" {
		return errors.New("cert and key must be specified as a pair")
	}
	return nil
}

// Equal compares effective webhook settings, excluding the shared transport.
func (w WebhookArgs) Equal(other WebhookArgs) bool {
	return w.Enable == other.Enable && w.Endpoint.String() == other.Endpoint.String() &&
		w.AuthToken == other.AuthToken && w.QueueDir == other.QueueDir &&
		w.QueueLimit == other.QueueLimit && w.ClientCert == other.ClientCert && w.ClientKey == other.ClientKey
}

// webhookClient is immutable after initialization. In-flight requests retain their
// client when a reload installs new settings.
type webhookClient struct {
	args       WebhookArgs
	transport  *http.Transport
	httpClient *http.Client
	initOnce   once.Init
	manager    *certs.Manager
	ctx        context.Context
	cancel     context.CancelFunc
}

func newWebhookClient(ctx context.Context, args WebhookArgs, transport *http.Transport) *webhookClient {
	ctx, cancel := context.WithCancel(ctx)
	client := &webhookClient{args: args, transport: transport.Clone(), ctx: ctx, cancel: cancel}
	// Configure the transport before publishing it. Loading certificates stays
	// lazy, but must not mutate transport settings concurrently with close.
	if args.ClientCert != "" && args.ClientKey != "" {
		if client.transport.TLSClientConfig == nil {
			client.transport.TLSClientConfig = &tls.Config{}
		}
		client.transport.TLSClientConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := client.init(); err != nil {
				return nil, err
			}
			return client.manager.GetClientCertificate(info)
		}
	}
	client.httpClient = &http.Client{Transport: client.transport}
	return client
}

func (client *webhookClient) init() error {
	return client.initOnce.Do(func() error {
		if client.args.ClientCert != "" && client.args.ClientKey != "" {
			manager, err := certs.NewManager(client.ctx, client.args.ClientCert, client.args.ClientKey, tls.LoadX509KeyPair)
			if err != nil {
				return err
			}
			manager.ReloadOnSignal(syscall.SIGHUP)
			client.manager = manager
		}
		return nil
	})
}

func (client *webhookClient) close() {
	client.cancel()
	client.transport.CloseIdleConnections()
}

// WebhookTarget - Webhook target.
type WebhookTarget struct {
	mu         sync.RWMutex
	client     *webhookClient
	startMu    sync.Mutex
	id         event.TargetID
	store      store.Store[event.Event]
	loggerOnce logger.LogOnce
	ctx        context.Context
	cancel     context.CancelFunc
	replayDone <-chan struct{}
}

// ID returns the target ID.
func (target *WebhookTarget) ID() event.TargetID { return target.id }

// Name returns the target name.
func (target *WebhookTarget) Name() string { return target.ID().String() }

func (target *WebhookTarget) currentClient() *webhookClient {
	target.mu.RLock()
	defer target.mu.RUnlock()
	return target.client
}

// Args returns the currently installed settings.
func (target *WebhookTarget) Args() WebhookArgs { return target.currentClient().args }

// CheckUpdate prevents a live reload from abandoning an existing disk queue.
func (target *WebhookTarget) CheckUpdate(args WebhookArgs) error {
	if target.Args().QueueDir != args.QueueDir {
		return fmt.Errorf("cannot change queue_dir on active webhook %s; drain and remove the target first", target.ID())
	}
	return nil
}

// IsActive checks connectivity without holding the target lock during network I/O.
func (target *WebhookTarget) IsActive() (bool, error) {
	client := target.currentClient()
	if err := client.init(); err != nil {
		return false, err
	}
	u := url.URL(client.args.Endpoint)
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(target.ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		if xnet.IsNetworkOrHostDown(err, false) {
			return false, store.ErrNotConnected
		}
		return false, err
	}
	conn.Close()
	return true, nil
}

// Store returns the disk queue, which remains the same across live updates.
func (target *WebhookTarget) Store() event.TargetStore { return target.store }

// Save persists events when a queue is configured, or sends using a client snapshot.
func (target *WebhookTarget) Save(eventData event.Event) error {
	if target.store != nil {
		target.mu.RLock()
		defer target.mu.RUnlock()
		if err := target.ctx.Err(); err != nil {
			return err
		}
		_, err := target.store.Put(eventData)
		return err
	}
	return target.send(eventData)
}

func (target *WebhookTarget) send(eventData event.Event) error {
	client := target.currentClient()
	if err := client.init(); err != nil {
		return err
	}
	objectName, err := url.QueryUnescape(eventData.S3.Object.Key)
	if err != nil {
		return err
	}
	key := eventData.S3.Bucket.Name + "/" + objectName
	data, err := json.Marshal(event.Log{EventName: eventData.EventName, Key: key, Records: []event.Event{eventData}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(target.ctx, http.MethodPost, client.args.Endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return err
	}
	tokens := strings.Fields(client.args.AuthToken)
	switch len(tokens) {
	case 2:
		req.Header.Set("Authorization", client.args.AuthToken)
	case 1:
		req.Header.Set("Authorization", "Bearer "+client.args.AuthToken)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.httpClient.Do(req)
	if err != nil {
		if xnet.IsNetworkOrHostDown(err, false) {
			return store.ErrNotConnected
		}
		return err
	}
	xhttp.DrainBody(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%s returned '%s', please check if your auth token is correctly set", client.args.Endpoint, resp.Status)
	}
	return fmt.Errorf("%s returned '%s', please check your endpoint configuration", client.args.Endpoint, resp.Status)
}

// SendFromStore sends and then removes an event from the unchanged disk queue.
func (target *WebhookTarget) SendFromStore(key store.Key) error {
	eventData, err := target.store.Get(key)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := target.send(eventData); err != nil {
		return err
	}
	return target.store.Del(key)
}

// Close cancels outstanding HTTP requests before waiting for replay to stop.
func (target *WebhookTarget) Close() error {
	target.mu.Lock()
	target.cancel()
	client := target.client
	target.mu.Unlock()
	target.startMu.Lock()
	defer target.startMu.Unlock()
	client.close()
	if target.replayDone != nil {
		<-target.replayDone
	}
	return nil
}

// Start begins replay after the target has been installed in the notifier.
func (target *WebhookTarget) Start() {
	target.startMu.Lock()
	defer target.startMu.Unlock()
	if target.store != nil && target.replayDone == nil {
		target.replayDone = store.StreamItems(target.store, target, target.ctx.Done(), target.loggerOnce)
	}
}

// Update installs prepared settings without waiting for outstanding POSTs.
// The caller must CheckUpdate before committing any target changes.
func (target *WebhookTarget) Update(args WebhookArgs, transport *http.Transport) {
	client := newWebhookClient(target.ctx, args, transport)
	target.mu.Lock()
	previous := target.client
	target.client = client
	target.mu.Unlock()
	if queue, ok := target.store.(*store.QueueStore[event.Event]); ok {
		queue.SetLimit(args.QueueLimit)
	}
	previous.close()
}

// NewWebhookTarget creates a target with lazy TLS initialization. Call Start to replay.
func NewWebhookTarget(ctx context.Context, id string, args WebhookArgs, loggerOnce logger.LogOnce, transport *http.Transport) (*WebhookTarget, error) {
	ctx, cancel := context.WithCancel(ctx)
	var queueStore store.Store[event.Event]
	if args.QueueDir != "" {
		queueDir := filepath.Join(args.QueueDir, storePrefix+"-webhook-"+id)
		queueStore = store.NewQueueStore[event.Event](queueDir, args.QueueLimit, event.StoreExtension)
		if err := queueStore.Open(); err != nil {
			cancel()
			return nil, fmt.Errorf("unable to initialize the queue store of Webhook `%s`: %w", id, err)
		}
	}
	return &WebhookTarget{
		id:     event.TargetID{ID: id, Name: "webhook"},
		client: newWebhookClient(ctx, args, transport),
		store:  queueStore, loggerOnce: loggerOnce, ctx: ctx, cancel: cancel,
	}, nil
}
