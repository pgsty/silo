// Copyright (c) 2026 PGSTY
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package cmd

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/pgsty/silo-pkg/v3/policy"
)

type strictIAMStatementWire struct {
	SID          policy.ID       `json:"Sid,omitempty"`
	Effect       policy.Effect   `json:"Effect"`
	Actions      json.RawMessage `json:"Action,omitempty"`
	NotActions   json.RawMessage `json:"NotAction,omitempty"`
	Resources    json.RawMessage `json:"Resource,omitempty"`
	NotResources json.RawMessage `json:"NotResource,omitempty"`
	Conditions   json.RawMessage `json:"Condition,omitempty"`
}

type strictIAMPolicyWire struct {
	ID         policy.ID                `json:"ID,omitempty"`
	Version    string                   `json:"Version"`
	Statements []strictIAMStatementWire `json:"Statement"`
}

type strictPrincipalWire struct {
	AWS json.RawMessage `json:"AWS"`
}

type strictBucketStatementWire struct {
	SID          policy.ID       `json:"Sid,omitempty"`
	Effect       policy.Effect   `json:"Effect"`
	Principal    json.RawMessage `json:"Principal,omitempty"`
	Actions      json.RawMessage `json:"Action,omitempty"`
	NotActions   json.RawMessage `json:"NotAction,omitempty"`
	Resources    json.RawMessage `json:"Resource,omitempty"`
	NotResources json.RawMessage `json:"NotResource,omitempty"`
	Conditions   json.RawMessage `json:"Condition,omitempty"`
}

type strictBucketPolicyWire struct {
	ID         policy.ID                   `json:"ID,omitempty"`
	Version    string                      `json:"Version"`
	Statements []strictBucketStatementWire `json:"Statement"`
}

func validateStrictIAMPolicyWire(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, policy.Errorf("policy must be a JSON object")
	}
	var wire strictIAMPolicyWire
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return nil, policy.Errorf("%w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, policy.Errorf("unexpected trailing JSON data in policy")
		}
		return nil, policy.Errorf("%w", err)
	}
	return trimmed, nil
}

func parsePolicyStrictBytes(data []byte) (*policy.Policy, error) {
	trimmed, err := validateStrictIAMPolicyWire(data)
	if err != nil {
		return nil, err
	}
	p, err := policy.ParseConfigStrict(bytes.NewReader(trimmed))
	if err != nil {
		return nil, err
	}
	if p.IsEmpty() {
		return nil, policy.Errorf("empty policies are not allowed")
	}
	return p, nil
}

func parseSessionPolicyStrictBytes(data []byte) (*policy.Policy, error) {
	trimmed, err := validateStrictIAMPolicyWire(data)
	if err != nil {
		return nil, err
	}
	return policy.ParseConfigStrict(bytes.NewReader(trimmed))
}

// Snapshot imports retain supported historical policy semantics while rejecting
// unknown JSON fields that could silently discard restrictions.
func parsePolicySnapshotBytes(data []byte) (*policy.Policy, error) {
	trimmed, err := validateStrictIAMPolicyWire(data)
	if err != nil {
		return nil, err
	}
	return policy.ParseConfig(bytes.NewReader(trimmed))
}

func validateStrictPrincipalWire(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var pw strictPrincipalWire
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pw); err != nil {
		return policy.Errorf("%w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return policy.Errorf("unexpected trailing JSON data in principal")
		}
		return policy.Errorf("%w", err)
	}
	if len(bytes.TrimSpace(pw.AWS)) == 0 {
		return policy.Errorf("invalid principal '%s'", string(raw))
	}
	return nil
}

func parseBucketPolicyStrictBytes(data []byte, bucket string) (*policy.BucketPolicy, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, policy.Errorf("bucket policy must be a JSON object")
	}
	var wire strictBucketPolicyWire
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return nil, policy.Errorf("%w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, policy.Errorf("unexpected trailing JSON data in bucket policy")
		}
		return nil, policy.Errorf("%w", err)
	}
	for _, st := range wire.Statements {
		if err := validateStrictPrincipalWire(st.Principal); err != nil {
			return nil, err
		}
	}
	return policy.ParseBucketPolicyConfig(bytes.NewReader(trimmed), bucket)
}
