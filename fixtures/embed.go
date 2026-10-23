// Package fixtures provides the synthetic, versioned laboratory dataset.
package fixtures

import _ "embed"

// LabJSON contains public test identities and exports, never real credentials.
//
//go:embed lab-v1.json
var LabJSON []byte
