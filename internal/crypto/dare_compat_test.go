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

package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/minio/sio"
)

// These sealed keys were generated with minio/sio v0.4.3 before the v0.5 API
// change, using a 32-byte zero external key and IV bytes 32 through 63. They
// provide positive legacy DARE coverage instead of only rejecting bad keys.
func TestUnsealLegacyDAREKeys(t *testing.T) {
	for _, test := range []struct{ name, algorithm, ciphertext string }{
		{"v1-aes256", InsecureSealAlgorithm, "10001f000000000001020304050607081e469edeb77bba11c91cf3132fc00ab28b8effbaa92784ea004f07a1cf1c9af28b5b725e1e5c96819a94703b10aa5943"},
		{"v1-chacha20", InsecureSealAlgorithm, "10011f00000000000102030405060708948d4d3ed99f047010c7c9b54ec2c58d0b437a9e9a7df3c032fcdf99e863b2bda7c9f995a3313f65bff8b941cb689e0d"},
		{"v2-aes256", SealAlgorithm, "20001f008102030405060708090a0b0c990455a32f26fd5a3417b4357ef3b92455c13e37947e0fac9e85380daa7b2a3eaffb032630b8b4652f66f01322abb449"},
		{"v2-chacha20", SealAlgorithm, "20011f008102030405060708090a0b0c34f030b5744d4ad777d03b1ec5e0771480911ec60cc796b4b1842ee9d3f8aa96a047bd4d8c26896613bca7e0dbefa85c"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := hex.DecodeString(test.ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			sealed := SealedKey{Algorithm: test.algorithm}
			copy(sealed.Key[:], raw)
			var expected ObjectKey
			for i := range expected {
				expected[i] = byte(i)
				sealed.IV[i] = byte(i + 32)
			}
			var key ObjectKey
			if err := key.Unseal(make([]byte, 32), sealed, "SSE-S3", "bucket", "object"); err != nil {
				t.Fatal(err)
			}
			if key != expected {
				t.Fatalf("unsealed key: got %x, want %x", key, expected)
			}
			sealed.Key[32] ^= 1
			if err := key.Unseal(make([]byte, 32), sealed, "SSE-S3", "bucket", "object"); err == nil {
				t.Fatal("tampered sealed key was accepted")
			}
		})
	}
}

func TestDARE32ByteKeyRoundTrip(t *testing.T) {
	var key ObjectKey
	for i := range key {
		key[i] = byte(i)
	}
	// Include both sides of a DARE package boundary and a multi-package payload.
	for _, size := range []int{0, 1, 65535, 65536, 65537, 131073} {
		plaintext := bytes.Repeat([]byte{0xa5}, size)
		for _, cipher := range DARECiphers() {
			var ciphertext, decoded bytes.Buffer
			if _, err := sio.Encrypt(&ciphertext, bytes.NewReader(plaintext), sio.Config{Key: key[:], CipherSuites: []byte{cipher}}); err != nil {
				t.Fatal(err)
			}
			if size > 0 && ciphertext.Bytes()[0] != sio.Version20 {
				t.Fatal("new objects must retain DARE v2 format")
			}
			if _, err := sio.Decrypt(&decoded, bytes.NewReader(ciphertext.Bytes()), sio.Config{Key: key[:], CipherSuites: DARECiphers()}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded.Bytes(), plaintext) {
				t.Fatalf("cipher %d size %d did not round-trip", cipher, size)
			}
		}
	}
}
