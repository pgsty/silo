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

package kafka

import (
	"testing"

	"github.com/IBM/sarama"
	xnet "github.com/pgsty/silo-pkg/v3/net"
)

// TestKafkaBrokerVersionCompatibility exercises the actual target constructor
// and producer: dependency upgrades must not raise the default broker protocol.
func TestKafkaBrokerVersionCompatibility(t *testing.T) {
	for _, test := range []struct {
		name, version string
		want          sarama.KafkaVersion
		metadata      int16
		sasl          bool
	}{
		{"default", "", sarama.V2_1_0_0, 7, false},
		{"explicit-old", "0.10.2.0", sarama.V0_10_2_0, 2, false},
		{"explicit-new", "2.8.0", sarama.V2_8_0_0, 11, false},
		{"default-sasl", "", sarama.V2_1_0_0, 7, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			broker := sarama.NewMockBroker(t, 1)
			defer broker.Close()
			broker.SetHandlerByMap(map[string]sarama.MockResponse{
				"ApiVersionsRequest": sarama.NewMockApiVersionsResponse(t).SetApiKeys([]sarama.ApiVersionsResponseKey{
					{ApiKey: 0, MinVersion: 0, MaxVersion: 8},
					{ApiKey: 3, MinVersion: 0, MaxVersion: 11},
					{ApiKey: 17, MinVersion: 0, MaxVersion: 1},
					{ApiKey: 18, MinVersion: 0, MaxVersion: 3},
					{ApiKey: 36, MinVersion: 0, MaxVersion: 2},
				}),
				"MetadataRequest":         sarama.NewMockMetadataResponse(t).SetBroker(broker.Addr(), broker.BrokerID()).SetLeader("events", 0, broker.BrokerID()),
				"ProduceRequest":          sarama.NewMockProduceResponse(t),
				"SaslHandshakeRequest":    sarama.NewMockSaslHandshakeResponse(t).SetEnabledMechanisms([]string{sarama.SASLTypePlaintext}),
				"SaslAuthenticateRequest": sarama.NewMockSaslAuthenticateResponse(t),
			})
			host, err := xnet.ParseHost(broker.Addr())
			if err != nil {
				t.Fatal(err)
			}
			target := &Target{kconfig: Config{Brokers: []xnet.Host{*host}, Topic: "events", Version: test.version}}
			target.kconfig.SASL.Enable = test.sasl
			target.kconfig.SASL.User = "user"
			target.kconfig.SASL.Password = "password"
			if err := target.send(map[string]string{"event": "probe"}); err != nil {
				t.Fatal(err)
			}

			defer target.client.Close()
			defer target.producer.Close()
			if target.config.Version != test.want {
				t.Fatalf("broker protocol: got %v, want %v", target.config.Version, test.want)
			}
			if target.config.Net.SASL.Version != sarama.SASLHandshakeV1 || !target.config.ApiVersionsRequest {
				t.Fatal("SASL/API version negotiation changed")
			}
			if err := target.config.Validate(); err != nil {
				t.Fatal(err)
			}
			var metadata, produced, authenticated bool
			for _, exchange := range broker.History() {
				switch req := exchange.Request.(type) {
				case *sarama.MetadataRequest:
					metadata = true
					if req.Version != test.metadata {
						t.Fatalf("metadata request version: got %d, want %d", req.Version, test.metadata)
					}
				case *sarama.ProduceRequest:
					produced = true
				case *sarama.SaslAuthenticateRequest:
					authenticated = true
				}
			}
			if !metadata || !produced || (test.sasl && !authenticated) {
				t.Fatalf("incomplete broker exchange: metadata=%v produce=%v authenticated=%v", metadata, produced, authenticated)
			}
		})
	}
}
