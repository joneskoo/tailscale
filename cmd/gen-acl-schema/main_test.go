// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	santhosh "github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tailscale/hujson"
)

// TestSchemaValidatesOfficialFixtures generates the schema and validates it
// against the JSON and HuJSON test fixtures from tailscale-client-go-v2.
// This catches type-mapping regressions (e.g. SSHCheckPeriod serialised as
// string) without requiring network access.
func TestSchemaValidatesOfficialFixtures(t *testing.T) {
	schema := compileSchema(t)

	// Locate the test fixtures from the module cache.
	modDir := moduleDir("tailscale.com/client/tailscale/v2")
	if modDir == "" {
		t.Skip("tailscale-client-go-v2 module not in cache")
	}
	testdata := filepath.Join(modDir, "testdata")

	for _, tc := range []struct {
		file   string
		hujson bool
	}{
		{"acl.json", false},
		{"acl.hujson", true},
	} {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(testdata, tc.file))
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}
			if tc.hujson {
				raw, err = hujson.Standardize(raw)
				if err != nil {
					t.Fatalf("hujson standardize: %v", err)
				}
			}

			var v any
			if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
				t.Fatalf("json decode: %v", err)
			}
			if err := schema.Validate(v); err != nil {
				t.Errorf("schema validation failed: %v", err)
			}
		})
	}
}

// TestSchemaSSHTests checks that the sshTests section, which is missing from
// the upstream client structs, is present in the schema. The policy is the
// example from https://tailscale.com/docs/reference/syntax/policy-file#sshtests.
func TestSchemaSSHTests(t *testing.T) {
	schema := compileSchema(t)

	valid := `{
		"sshTests": [
			{
				"src": "dave@example.com",
				"dst": ["example-host-1"],
				"accept": ["dave"],
				"check": ["admin"],
				"deny": ["root"],
				"srcPostureAttrs": {
					"node:os": "windows",
				},
			},
		],
	}`
	if err := schema.Validate(decodeHuJSON(t, valid)); err != nil {
		t.Errorf("valid sshTests rejected: %v", err)
	}

	invalid := `{"sshTests": [{"src": "dave@example.com", "dst": "example-host-1"}]}`
	if err := schema.Validate(decodeHuJSON(t, invalid)); err == nil {
		t.Errorf("sshTests with string dst accepted, want error")
	}
}

func compileSchema(t *testing.T) *santhosh.Schema {
	t.Helper()
	schemaFile := filepath.Join(t.TempDir(), "acl-schema.json")
	cmd := exec.Command("go", "run", ".", "-o", schemaFile)
	cmd.Dir = thisDir(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go run . -o %s: %v\n%s", schemaFile, err, out)
	}
	schema, err := santhosh.NewCompiler().Compile(schemaFile)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func decodeHuJSON(t *testing.T, s string) any {
	t.Helper()
	raw, err := hujson.Standardize([]byte(s))
	if err != nil {
		t.Fatalf("hujson standardize: %v", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	return v
}

func thisDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}
