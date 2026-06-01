// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command gen-acl-schema generates a JSON Schema document for the Tailscale
// ACL policy file format.
//
// The schema is derived automatically from the [tailscale.com/client/tailscale/v2.ACL]
// struct, so it stays in sync with the official Go API client without any
// additional maintenance. Run it via:
//
//	go generate tailscale.com/cmd/gen-acl-schema
//
// or by running go generate in any package that contains the directive:
//
//	//go:generate go run tailscale.com/cmd/gen-acl-schema -o <output>
package main

//go:generate go run tailscale.com/cmd/gen-acl-schema -o ../../acl-schema.json

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/invopop/jsonschema"
	tsclient "tailscale.com/client/tailscale/v2"
)

func main() {
	output := flag.String("o", "acl-schema.json", "output file path")
	flag.Parse()

	r := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
	}

	schema := r.Reflect(&tsclient.ACL{})
	schema.ID = "https://raw.githubusercontent.com/tailscale/tailscale/main/acl-schema.json"
	schema.Title = "Tailscale ACL Policy"
	schema.Description = "JSON Schema for the Tailscale network access control policy file " +
		"(policy.hujson). See https://tailscale.com/kb/1018/acls for documentation."

	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		log.Fatalf("marshal schema: %v", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(*output, data, 0644); err != nil {
		log.Fatalf("write %s: %v", *output, err)
	}
	log.Printf("wrote %s", *output)
}
