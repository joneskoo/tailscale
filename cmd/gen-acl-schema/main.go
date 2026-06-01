// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Command gen-acl-schema generates a JSON Schema document for the Tailscale
// ACL policy file format.
//
// The schema is derived automatically from the [tailscale.com/client/tailscale/v2.ACL]
// struct, which is already a module dependency, so it stays in sync as that
// package evolves. Descriptions come from two sources:
//
//  1. Go doc comments in the upstream source, extracted via [AddGoComments].
//  2. The [commentMap] below, keyed by the fully qualified Go field path
//     "pkg.Type.Field", which fills gaps where the upstream lacks comments.
//     It does not need to be exhaustive — new fields simply have no description
//     until added here.
//
// Run via:
//
//	go generate tailscale.com/cmd/gen-acl-schema
package main

//go:generate go run tailscale.com/cmd/gen-acl-schema -o ../../acl-schema.json

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"reflect"
	"strings"

	"github.com/invopop/jsonschema"
	tsclient "tailscale.com/client/tailscale/v2"
)

// commentMap supplements the upstream source comments (which are sparse) with
// descriptions for well-known fields. Keys are fully-qualified Go identifiers
// in the form "pkgpath.Type.Field" matching [jsonschema.Reflector.CommentMap].
//
// Descriptions are sourced from the official Tailscale documentation at
// https://tailscale.com/kb/1337/policy-syntax and co-located here so they stay
// adjacent to the schema generation logic rather than in a separate package.
//
// Coverage is best-effort: fields absent from this map produce no description
// in the schema, but the schema remains structurally correct.
var commentMap = func() map[string]string {
	const pkg = "tailscale.com/client/tailscale/v2"
	f := func(typ, field, desc string) string {
		return fmt.Sprintf("%s.%s.%s", pkg, typ, field)
	}
	m := map[string]string{}
	set := func(typ, field, desc string) { m[f(typ, field, desc)] = desc }

	// ACL — top-level policy file fields
	set("ACL", "ACLs", "Access control rules specifying which sources can reach which destinations. Both legacy (users/ports) and current (src/dst) forms are accepted.")
	set("ACL", "AutoApprovers", "Rules for automatically approving route or exit-node advertisements without manual admin action.")
	set("ACL", "Groups", "Named groups of users, prefixed 'group:'. Values are lists of user emails, tags, or other groups.")
	set("ACL", "Hosts", "Named aliases for IP addresses or CIDR ranges, usable in place of IPs anywhere in the policy.")
	set("ACL", "TagOwners", "Defines who may apply each tag (prefixed 'tag:') to devices. Values are user emails or groups.")
	set("ACL", "DERPMap", "Custom DERP relay configuration, extending or replacing Tailscale's built-in DERP infrastructure.")
	set("ACL", "Tests", "Test assertions verified on every policy update; a failing test blocks the update from taking effect.")
	set("ACL", "SSH", "Tailscale SSH access control rules governing which users may open SSH sessions to which devices.")
	set("ACL", "NodeAttrs", "Rules that grant capability attributes (e.g. funnel, mullvad, app-connector) to matched devices.")
	set("ACL", "DisableIPv4", "Disables IPv4 routing within the tailnet when true.")
	set("ACL", "OneCGNATRoute", "Assigns the full CGNAT range (100.64.0.0/10) as a route on a single device, rather than per-device.")
	set("ACL", "RandomizeClientPort", "Randomizes the WireGuard listen port on each connection for additional NAT traversal privacy.")
	set("ACL", "Grants", "Fine-grained access grants (newer alternative to acls) with per-IP or per-app destination controls.")
	set("ACL", "IPSets", "Named sets of IP addresses or CIDRs (prefixed 'ipset:') for reuse across multiple rules.")
	set("ACL", "Postures", "Named device posture checks (prefixed 'posture:') evaluated against device attribute values.")
	set("ACL", "DefaultSourcePosture", "Posture checks applied to all traffic sources by default, unless overridden by a per-rule srcPosture.")

	// ACLEntry — individual ACL rule
	set("ACLEntry", "Action", "Whether to accept or deny matching traffic. One of: 'accept', 'deny'.")
	set("ACLEntry", "Source", "Source identities: user emails, groups (group:x), tags (tag:x), autogroups, IPs, CIDRs, host aliases, or '*'.")
	set("ACLEntry", "Destination", "Destination targets with optional port specifier, e.g. 'host:80', 'tag:x:22-443', or '*:*'.")
	set("ACLEntry", "Protocol", "IP protocol restriction: 'tcp', 'udp', 'icmp', etc. Omit to match all protocols.")
	set("ACLEntry", "Ports", "(Legacy) Destination in 'host:port' form. Prefer dst.")
	set("ACLEntry", "Users", "(Legacy) Source identities. Prefer src.")
	set("ACLEntry", "SourcePosture", "Posture check names that must pass for traffic from the source to be accepted.")

	// ACLAutoApprovers — automatic approval rules
	set("ACLAutoApprovers", "Routes", "Maps subnet CIDRs to tags or users whose devices are auto-approved to advertise those routes.")
	set("ACLAutoApprovers", "ExitNode", "Tags or users whose devices are auto-approved to advertise themselves as exit nodes.")

	// ACLSSH — SSH access rule
	set("ACLSSH", "Action", "SSH connection action: 'accept', 'check' (require IdP re-auth), or 'deny'.")
	set("ACLSSH", "Source", "Source identities allowed to initiate SSH sessions.")
	set("ACLSSH", "Destination", "Destination devices this SSH rule applies to, e.g. 'tag:server' or 'autogroup:self'.")
	set("ACLSSH", "Users", "OS-level usernames permitted for the session, e.g. 'root' or 'autogroup:nonroot'.")
	set("ACLSSH", "CheckPeriod", "How often re-authorization is required when action is 'check', e.g. '12h' or 'always'.")
	set("ACLSSH", "Recorder", "Tailscale IPs or tags of session-recorder hosts. Sessions are streamed to all reachable recorders.")
	set("ACLSSH", "EnforceRecorder", "If true, reject the SSH session when no recorder from the Recorder list is reachable.")

	// NodeAttrGrant — device capability grant
	set("NodeAttrGrant", "Target", "Devices to grant attributes to: tags, users, autogroups, or '*' for all devices.")
	set("NodeAttrGrant", "Attr", "Capability attribute names to grant, e.g. 'funnel', 'mullvad', 'app-connector'.")
	set("NodeAttrGrant", "App", "Application-connector route configuration keyed by app name.")
	set("NodeAttrGrant", "IPPool", "IP address pool to assign to matched devices.")

	// Grant — fine-grained access grant
	set("Grant", "Source", "Source identities for this grant.")
	set("Grant", "Destination", "Destination identities for this grant.")
	set("Grant", "IP", "Permitted destination IP addresses or CIDR ranges.")
	set("Grant", "App", "Application-level access rules keyed by app name.")
	set("Grant", "SrcPosture", "Posture checks that must pass for the source device.")
	set("Grant", "Via", "App Connector identities through which access is tunnelled.")

	// ACLTest — policy test assertion
	set("ACLTest", "Source", "Source identity for this test: user email, tag, or Tailscale IP.")
	set("ACLTest", "Accept", "Destination:port pairs the source must be allowed to reach.")
	set("ACLTest", "Deny", "Destination:port pairs the source must NOT be allowed to reach.")
	set("ACLTest", "User", "(Legacy) Source identity. Prefer src.")
	set("ACLTest", "Allow", "(Legacy) Allowed destinations. Prefer accept.")
	set("ACLTest", "SrcPostureAttrs", "Device attribute key/value pairs to simulate when evaluating posture checks for this test.")

	// ACLDERPMap / ACLDERPRegion / ACLDERPNode
	set("ACLDERPMap", "Regions", "Custom DERP regions keyed by integer region ID.")
	set("ACLDERPMap", "OmitDefaultRegions", "When true, only the regions in this map are used; Tailscale's built-in regions are omitted.")
	set("ACLDERPRegion", "RegionID", "Unique numeric ID for this DERP region (must not collide with Tailscale's built-in IDs).")
	set("ACLDERPRegion", "RegionCode", "Short region code, e.g. 'nyc'.")
	set("ACLDERPRegion", "RegionName", "Human-readable region name.")
	set("ACLDERPRegion", "Avoid", "If true, this region is used only as a last-resort fallback.")
	set("ACLDERPRegion", "Nodes", "DERP relay nodes in this region.")
	set("ACLDERPNode", "Name", "Node name within the region.")
	set("ACLDERPNode", "RegionID", "Region this node belongs to.")
	set("ACLDERPNode", "HostName", "DNS hostname of the DERP relay.")
	set("ACLDERPNode", "CertName", "TLS certificate hostname if different from HostName.")
	set("ACLDERPNode", "IPv4", "IPv4 address (overrides DNS lookup).")
	set("ACLDERPNode", "IPv6", "IPv6 address (overrides DNS lookup).")
	set("ACLDERPNode", "STUNPort", "STUN port (default 3478).")
	set("ACLDERPNode", "STUNOnly", "If true, this node provides STUN only, not DERP relay.")
	set("ACLDERPNode", "DERPPort", "DERP port (default 443).")

	// NodeAttrGrantApp
	set("NodeAttrGrantApp", "Name", "App name, used to match traffic for this app connector route.")
	set("NodeAttrGrantApp", "Connectors", "Tags or IPs of the App Connector devices to route through.")
	set("NodeAttrGrantApp", "Domains", "DNS domains whose traffic is routed through this app connector.")

	return m
}()

func main() {
	output := flag.String("o", "acl-schema.json", "output file path")
	flag.Parse()

	r := &jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true,
		CommentMap:                 commentMap,
		// SSHCheckPeriod is a time.Duration alias that marshals as a string
		// ("20h", "1h30m", "always") via encoding.TextMarshaler. The reflector
		// sees the underlying int64 and would emit "integer" without this override.
		Mapper: func(t reflect.Type) *jsonschema.Schema {
			if t == reflect.TypeOf(tsclient.SSHCheckPeriod(0)) {
				return &jsonschema.Schema{
					Type:        "string",
					Description: `Duration string (e.g. "20h", "1h30m") or the special value "always" to force re-auth on every connection.`,
					Examples:    []any{"20h", "1h30m", "always"},
				}
			}
			return nil
		},
	}

	// Pull any doc comments that exist in the upstream source from the module
	// cache. Currently sparse, but AddGoComments is non-fatal if unavailable.
	if dir := moduleDir("tailscale.com/client/tailscale/v2"); dir != "" {
		if err := r.AddGoComments("tailscale.com/client/tailscale/v2", dir); err != nil {
			log.Printf("warning: could not extract go comments: %v", err)
		}
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

// moduleDir returns the local filesystem directory of the named module as
// recorded in the module cache, or an empty string if unavailable.
func moduleDir(modPath string) string {
	out, err := exec.Command("go", "list", "-m", "-json", modPath).Output()
	if err != nil {
		return ""
	}
	var info struct{ Dir string }
	if err := json.Unmarshal(out, &info); err != nil {
		return ""
	}
	// Trim any trailing path separator variants returned on some platforms.
	return strings.TrimRight(info.Dir, "/\\")
}
