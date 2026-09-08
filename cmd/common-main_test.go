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
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	consoleapi "github.com/minio/console/api"
	"github.com/minio/minio/internal/config"
)

func Test_readFromSecret(t *testing.T) {
	testCases := []struct {
		content       string
		expectedErr   bool
		expectedValue string
	}{
		{
			"value\n",
			false,
			"value",
		},
		{
			" \t\n Hello, Gophers \n\t\r\n",
			false,
			"Hello, Gophers",
		},
	}

	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			tmpfile, err := os.CreateTemp(t.TempDir(), "testfile")
			if err != nil {
				t.Error(err)
			}
			tmpfile.WriteString(testCase.content)
			tmpfile.Sync()
			tmpfile.Close()

			value, err := readFromSecret(tmpfile.Name())
			if err != nil && !testCase.expectedErr {
				t.Error(err)
			}
			if err == nil && testCase.expectedErr {
				t.Error(errors.New("expected error, found success"))
			}
			if value != testCase.expectedValue {
				t.Errorf("Expected %s, got %s", testCase.expectedValue, value)
			}
		})
	}
}

func Test_minioEnvironFromFile(t *testing.T) {
	testCases := []struct {
		content      string
		expectedErr  bool
		expectedEkvs []envKV
	}{
		{
			`
export MINIO_ROOT_USER=minio
export MINIO_ROOT_PASSWORD=minio123`,
			false,
			[]envKV{
				{
					Key:   "MINIO_ROOT_USER",
					Value: "minio",
				},
				{
					Key:   "MINIO_ROOT_PASSWORD",
					Value: "minio123",
				},
			},
		},
		// Value with double quotes
		{
			`export MINIO_ROOT_USER="minio"`,
			false,
			[]envKV{
				{
					Key:   "MINIO_ROOT_USER",
					Value: "minio",
				},
			},
		},
		// Value with single quotes
		{
			`export MINIO_ROOT_USER='minio'`,
			false,
			[]envKV{
				{
					Key:   "MINIO_ROOT_USER",
					Value: "minio",
				},
			},
		},
		{
			`
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD=minio123`,
			false,
			[]envKV{
				{
					Key:   "MINIO_ROOT_USER",
					Value: "minio",
				},
				{
					Key:   "MINIO_ROOT_PASSWORD",
					Value: "minio123",
				},
			},
		},
		{
			`
export MINIO_ROOT_USERminio
export MINIO_ROOT_PASSWORD=minio123`,
			true,
			nil,
		},
		{
			`
# simple comment
# MINIO_ROOT_USER=minioadmin
# MINIO_ROOT_PASSWORD=minioadmin
MINIO_ROOT_USER=minio
MINIO_ROOT_PASSWORD=minio123`,
			false,
			[]envKV{
				{
					Key:   "MINIO_ROOT_USER",
					Value: "minio",
				},
				{
					Key:   "MINIO_ROOT_PASSWORD",
					Value: "minio123",
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run("", func(t *testing.T) {
			tmpfile, err := os.CreateTemp(t.TempDir(), "testfile")
			if err != nil {
				t.Error(err)
			}
			tmpfile.WriteString(testCase.content)
			tmpfile.Sync()
			tmpfile.Close()

			ekvs, err := minioEnvironFromFile(tmpfile.Name())
			if err != nil && !testCase.expectedErr {
				t.Error(err)
			}
			if err == nil && testCase.expectedErr {
				t.Error(errors.New("expected error, found success"))
			}

			if len(ekvs) != len(testCase.expectedEkvs) {
				t.Errorf("expected %v keys, got %v keys", len(testCase.expectedEkvs), len(ekvs))
			}

			if !reflect.DeepEqual(ekvs, testCase.expectedEkvs) {
				t.Errorf("expected %v, got %v", testCase.expectedEkvs, ekvs)
			}
		})
	}
}

func Test_minioEnvironFromFileWhitespaceAndValidation(t *testing.T) {
	testCases := []struct {
		name        string
		content     string
		want        []envKV
		errLine     int
		errContains string
		errExcludes string
	}{
		{
			name:    "spaces and tabs around separator",
			content: "MINIO_ROOT_USER = minio\nMINIO_ROOT_PASSWORD\t=\tminio123",
			want: []envKV{
				{Key: "MINIO_ROOT_USER", Value: "minio"},
				{Key: "MINIO_ROOT_PASSWORD", Value: "minio123"},
			},
		},
		{
			name:    "export tab and quoted spaces",
			content: "export\tMINIO_ROOT_USER = \"  minio user  \"\nexport MINIO_ROOT_PASSWORD = '  minio secret  '",
			want: []envKV{
				{Key: "MINIO_ROOT_USER", Value: "  minio user  "},
				{Key: "MINIO_ROOT_PASSWORD", Value: "  minio secret  "},
			},
		},
		{
			name:    "export Unicode whitespace",
			content: "export\u00a0MINIO_ROOT_USER=value",
			want: []envKV{
				{Key: "MINIO_ROOT_USER", Value: "value"},
			},
		},
		{
			name:    "export is only a standalone prefix",
			content: "export=value\nexportFOO=bar",
			want: []envKV{
				{Key: "export", Value: "value"},
				{Key: "exportFOO", Value: "bar"},
			},
		},
		{
			name:    "unquoted whitespace empty value and additional separators",
			content: "UNQUOTED =   value   \nEMPTY =\nTOKEN = scheme://user:password@example.com?a=b",
			want: []envKV{
				{Key: "UNQUOTED", Value: "value"},
				{Key: "EMPTY", Value: ""},
				{Key: "TOKEN", Value: "scheme://user:password@example.com?a=b"},
			},
		},
		{
			name:    "valid underscore and digits",
			content: "_VALID_2=value",
			want: []envKV{
				{Key: "_VALID_2", Value: "value"},
			},
		},
		{
			name: "named target punctuation and unicode",
			content: "MINIO_NOTIFY_WEBHOOK_ENABLE_my-hook=off\n" +
				"MINIO_NOTIFY_WEBHOOK_ENABLE_site.eu=off\n" +
				"MINIO_NOTIFY_WEBHOOK_ENABLE_team:blue=off\n" +
				"MINIO_NOTIFY_WEBHOOK_ENABLE_目标=off",
			want: []envKV{
				{Key: "MINIO_NOTIFY_WEBHOOK_ENABLE_my-hook", Value: "off"},
				{Key: "MINIO_NOTIFY_WEBHOOK_ENABLE_site.eu", Value: "off"},
				{Key: "MINIO_NOTIFY_WEBHOOK_ENABLE_team:blue", Value: "off"},
				{Key: "MINIO_NOTIFY_WEBHOOK_ENABLE_目标", Value: "off"},
			},
		},
		{
			name:        "missing separator redacts the line",
			content:     "MINIO_ROOT_PASSWORD=valid\nsuper-secret-without-equals",
			errLine:     2,
			errContains: "missing '='",
			errExcludes: "super-secret-without-equals",
		},
		{
			name:        "empty name",
			content:     "=empty-name-secret",
			errLine:     1,
			errContains: `invalid environment variable name ""`,
			errExcludes: "empty-name-secret",
		},
		{
			name:    "os compatible leading digit and punctuation",
			content: "1MINIO_ROOT_USER=digit-leading-secret\n-MINIO-ROOT-USER=hyphen-secret",
			want: []envKV{
				{Key: "1MINIO_ROOT_USER", Value: "digit-leading-secret"},
				{Key: "-MINIO-ROOT-USER", Value: "hyphen-secret"},
			},
		},
		{
			name:        "whitespace in name",
			content:     "MINIO ROOT USER=whitespace-secret",
			errLine:     1,
			errContains: `invalid environment variable name "MINIO ROOT USER"`,
			errExcludes: "whitespace-secret",
		},
		{
			name:        "NUL in name",
			content:     "MINIO\x00ROOT=nul-name-secret",
			errLine:     1,
			errContains: "invalid environment variable name",
			errExcludes: "nul-name-secret",
		},
		{
			name:        "format character in name",
			content:     "MINIO\u200bROOT=format-secret",
			errLine:     1,
			errContains: "invalid environment variable name",
			errExcludes: "format-secret",
		},
		{
			name:        "NUL in value",
			content:     "MINIO_ROOT_USER=before\x00nul-value-secret",
			errLine:     1,
			errContains: "environment variable value contains NUL",
			errExcludes: "nul-value-secret",
		},
		{
			name:        "diagnostic has file and line but no value",
			content:     "MINIO_ROOT_USER=valid\nBAD KEY=super-secret-value",
			errLine:     2,
			errContains: `invalid environment variable name "BAD KEY"`,
			errExcludes: "super-secret-value",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp(t.TempDir(), "testfile")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tmpfile.WriteString(testCase.content); err != nil {
				t.Fatal(err)
			}
			if err = tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			got, err := minioEnvironFromFile(tmpfile.Name())
			if testCase.errContains == "" {
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, testCase.want) {
					t.Errorf("expected %v, got %v", testCase.want, got)
				}
				return
			}

			if err == nil {
				t.Fatal("expected an error")
			}
			errText := err.Error()
			location := fmt.Sprintf("%s:%d:", tmpfile.Name(), testCase.errLine)
			if !strings.Contains(errText, location) {
				t.Errorf("expected error to contain %q, got %q", location, errText)
			}
			if !strings.Contains(errText, testCase.errContains) {
				t.Errorf("expected error to contain %q, got %q", testCase.errContains, errText)
			}
			if testCase.errExcludes != "" && strings.Contains(errText, testCase.errExcludes) {
				t.Errorf("expected error to redact %q, got %q", testCase.errExcludes, errText)
			}
			if got != nil {
				t.Errorf("expected no entries on parse error, got %v", got)
			}
		})
	}
}

func TestConfigEnvFileNamedTargetDiscovery(t *testing.T) {
	key := "MINIO_NOTIFY_WEBHOOK_ENABLE_my-hook"
	t.Setenv(key, "off")

	targets, err := (config.Config{}).GetAvailableTargets(config.NotifyWebhookSubSys)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(targets, "my-hook") {
		t.Fatalf("named target %q not discovered from %s: %v", "my-hook", key, targets)
	}
}

// TestConsoleMinIOServerEnv locks in the loopback TLS exemption that keeps
// embedded Console login working (issue #108) while ensuring an explicitly
// configured endpoint is never silently exempted from TLS verification.
func TestConsoleMinIOServerEnv(t *testing.T) {
	tests := []struct {
		name           string
		endpoint       string
		isTLS          bool
		port           string
		wantServer     string
		wantSkipVerify bool
	}{
		{
			name:           "loopback TLS is exempted so embedded login works",
			isTLS:          true,
			port:           "9000",
			wantServer:     "https://127.0.0.1:9000",
			wantSkipVerify: true,
		},
		{
			name:       "loopback plain HTTP needs no exemption",
			isTLS:      false,
			port:       "9000",
			wantServer: "http://127.0.0.1:9000",
		},
		{
			name:       "explicit https endpoint stays verified",
			endpoint:   "https://silo.example:9000",
			isTLS:      true,
			port:       "9000",
			wantServer: "https://silo.example:9000",
		},
		{
			name:       "explicit http endpoint stays verified",
			endpoint:   "http://silo.example:9000",
			isTLS:      false,
			port:       "9000",
			wantServer: "http://silo.example:9000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, skipVerify := consoleMinIOServerEnv(tt.endpoint, tt.isTLS, tt.port)
			if server != tt.wantServer {
				t.Fatalf("server = %q, want %q", server, tt.wantServer)
			}
			if skipVerify != tt.wantSkipVerify {
				t.Fatalf("skipVerify = %v, want %v", skipVerify, tt.wantSkipVerify)
			}
		})
	}
}

// The startup path clears process environment, so preserve all existing Console
// variables, including ones unrelated to this test, before exercising it.
func preserveConsoleEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, consolePrefix) {
			name, value, _ := strings.Cut(entry, "=")
			t.Setenv(name, value)
		}
	}
}

func TestResetConsoleEnvironment(t *testing.T) {
	preserveConsoleEnvironment(t)
	settings := map[string]string{
		consoleapi.ConsoleWSMaxConnections:                   "2048",
		consoleapi.ConsoleWSMaxConnectionsPerClient:          "512",
		consoleapi.ConsoleWSMaxAnonymousConnections:          "128",
		consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient: "16",
	}
	for key, value := range settings {
		t.Setenv(key, value)
	}
	decoys := []string{"CONSOLE_MINIO_SERVER_TLS_SKIP_VERIFY", "CONSOLE_MINIO_SERVER", "CONSOLE_PBKDF_SALT", "CONSOLE_TRUSTED_PROXIES", "CONSOLE_WS_MAX_UNKNOWN"}
	for _, key := range decoys {
		t.Setenv(key, "operator-value")
	}
	resetConsoleEnvironment()
	for key, want := range settings {
		if got, present := os.LookupEnv(key); !present || got != want {
			t.Errorf("%s = %q, present = %v; want %q", key, got, present, want)
		}
	}
	for _, key := range decoys {
		if _, present := os.LookupEnv(key); present {
			t.Errorf("unsupported override %s survived", key)
		}
	}
	for _, raw := range []string{"", " 16 ", "env://missing-limit"} {
		t.Setenv(consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient, raw)
		resetConsoleEnvironment()
		if got, present := os.LookupEnv(consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient); !present || got != raw {
			t.Fatalf("raw value %q was changed to %q (present = %v)", raw, got, present)
		}
	}
	os.Unsetenv(consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient)
	resetConsoleEnvironment()
	if _, present := os.LookupEnv(consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient); present {
		t.Fatal("unset setting became present")
	}
}

func TestInitConsoleServerConfigurationErrors(t *testing.T) {
	for _, tt := range []struct {
		name, proxy, limit, want string
	}{
		{"proxy error precedes limit error", "proxy.internal", "bad", "MINIO_API_TRUSTED_PROXIES"},
		{"blank limit", "", "", "CONSOLE_WS_MAX_ANONYMOUS_CONNECTIONS_PER_CLIENT"},
		{"non-integer limit", "", "bad", "CONSOLE_WS_MAX_ANONYMOUS_CONNECTIONS_PER_CLIENT"},
		{"out-of-range limit", "", "0", "CONSOLE_WS_MAX_ANONYMOUS_CONNECTIONS_PER_CLIENT"},
		{"inconsistent limits", "", "256", "must be less than"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Restore the process-wide library configuration after environment cleanup.
			t.Cleanup(func() {
				_ = consoleapi.ConfigureEmbeddedSourceIPTrust()
				_ = consoleapi.ConfigureWebSocketLimits()
			})
			preserveConsoleEnvironment(t)
			t.Setenv(consoleapi.EnvMinIOTrustedProxies, tt.proxy)
			t.Setenv(consoleapi.ConsoleWSMaxConnections, "1024")
			t.Setenv(consoleapi.ConsoleWSMaxConnectionsPerClient, "256")
			t.Setenv(consoleapi.ConsoleWSMaxAnonymousConnections, "64")
			t.Setenv(consoleapi.ConsoleWSMaxAnonymousConnectionsPerClient, tt.limit)
			server, err := initConsoleServer()
			if err == nil || !strings.Contains(err.Error(), tt.want) || server != nil {
				t.Fatalf("initConsoleServer() = %v, %v; want nil server and %q error", server, err, tt.want)
			}
		})
	}
}
