//go:build integration

// Package testdb provides isolated PostgreSQL schemas for integration tests.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
}
func Core() string {
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(Root(), "target", "debug", name)
}

// New only creates and removes its own random schema. It never resets the
// database or modifies existing schemas. Use a dedicated development database.
func New(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HARNESS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("HARNESS_TEST_DATABASE_URL is required for -tags=integration; refusing to skip PostgreSQL tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	config.MaxConns = 1
	admin, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var entropy [12]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	schema := "harness_test_" + hex.EncodeToString(entropy[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		defer admin.Close()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("cleanup private test schema: %v", err)
		}
	})

	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid test database URL")
		}
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return dsn + " search_path=" + schema
}

func Task(t *testing.T, mode, id, retry string, dependencies ...string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(Root(), "examples", "task."+mode+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value["task_id"] = id
	value["run_id"] = "run-test"
	value["project_id"] = "lab-project"
	value["created_at"] = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	value["deadline"] = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	value["retry_class"] = retry
	if dependencies == nil {
		dependencies = []string{}
	}
	value["dependencies"] = dependencies
	value["budget"] = map[string]any{"max_wall_seconds": 60, "max_model_tokens": 100, "max_requests": 10, "max_artifact_bytes": 65536}
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func Change(t *testing.T, raw json.RawMessage, key string, value any) json.RawMessage {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc[key] = value
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
