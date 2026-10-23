// Package lab implements a synthetic local target, not a scanning service.
package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"example.com/unified-harness/fixtures"
)

type Identity struct {
	ID     string `json:"identity_id"`
	Tenant string `json:"tenant_id"`
	Role   string `json:"role"`
	Token  string `json:"token"`
}
type Export struct {
	ID      string `json:"export_id"`
	Tenant  string `json:"tenant_id"`
	Content string `json:"content"`
}
type dataset struct {
	Version    int        `json:"schema_version"`
	ID         string     `json:"fixture_id"`
	Identities []Identity `json:"identities"`
	Exports    []Export   `json:"exports"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func New(variant string) (http.Handler, error) {
	if variant != "vulnerable" && variant != "patched" {
		return nil, fmt.Errorf("unknown lab variant %q", variant)
	}
	var data dataset
	decoder := json.NewDecoder(strings.NewReader(string(fixtures.LabJSON)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}
	if data.Version != 1 || len(data.Identities) != 2 || len(data.Exports) != 2 {
		return nil, fmt.Errorf("invalid lab fixtures")
	}
	identities := map[string]Identity{}
	exports := map[string]Export{}
	for _, id := range data.Identities {
		if id.Token == "" || id.Tenant == "" {
			return nil, fmt.Errorf("invalid test identity")
		}
		if _, ok := identities[id.Token]; ok {
			return nil, fmt.Errorf("duplicate test token")
		}
		identities[id.Token] = id
	}
	for _, item := range data.Exports {
		if _, ok := exports[item.ID]; ok {
			return nil, fmt.Errorf("duplicate export")
		}
		exports[item.ID] = item
	}
	hash := sha256.Sum256(fixtures.LabJSON)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"fixture_id": data.ID, "variant": variant, "fixture_sha256": hex.EncodeToString(hash[:]),
			"source_mapping": "unverified; fixture digest is not a source commit",
		})
	})
	authenticate := func(w http.ResponseWriter, r *http.Request) (Identity, bool) {
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
			if id, ok := identities[fields[1]]; ok {
				return id, true
			}
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return Identity{}, false
	}
	mux.HandleFunc("GET /exports", func(w http.ResponseWriter, r *http.Request) {
		id, ok := authenticate(w, r)
		if !ok {
			return
		}
		own := []Export{}
		for _, item := range data.Exports {
			if item.Tenant == id.Tenant {
				own = append(own, item)
			}
		}
		writeJSON(w, http.StatusOK, own)
	})
	mux.HandleFunc("GET /exports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, ok := authenticate(w, r)
		if !ok {
			return
		}
		item, exists := exports[r.PathValue("id")]
		// Intentional seed: the vulnerable variant omits this ownership check.
		if !exists || (variant == "patched" && item.Tenant != id.Tenant) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		writeJSON(w, http.StatusOK, item)
	})
	return mux, nil
}
