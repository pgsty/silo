// Copyright (c) 2026 PGSTY
// SPDX-License-Identifier: AGPL-3.0-or-later
package plugin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pgsty/silo-pkg/v3/net"
	"github.com/pgsty/silo-pkg/v3/policy"
)

func TestAuthZPluginExplicitDecision(t *testing.T) {
	for _, tc := range []struct {
		body        string
		status      int
		allow, fail bool
	}{
		{`{"result":true}`, 200, true, false}, {`{"result":false}`, 200, false, false},
		{`{"result":{"allow":true}}`, 200, true, false}, {`{"result":{"allow":false}}`, 200, false, false},
		{`{"result":true}`, 503, false, true}, {`{"result":true}`, 403, false, true},
		{`{}`, 200, false, true}, {`{"error":"unavailable"}`, 200, false, true}, {`{"result":null}`, 200, false, true},
		{`{"result":{}}`, 200, false, true}, {`{"result":{"allow":null}}`, 200, false, true}, {`{"result":"true"}`, 200, false, true},
		{`{"result":true} garbage`, 200, false, true},
	} {
		t.Run(tc.body+http.StatusText(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			u, err := net.ParseHTTPURL(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			plugin := New(Args{URL: u, CloseRespFn: func(r io.ReadCloser) { r.Close() }})
			allowed, err := plugin.IsAllowedContext(t.Context(), policy.Args{})
			if allowed != tc.allow || (err != nil) != tc.fail {
				t.Fatalf("allow=%v err=%v", allowed, err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if allowed, err := plugin.IsAllowedContext(ctx, policy.Args{}); allowed || err == nil {
				t.Fatal("canceled evaluation did not stop")
			}
		})
	}
}
