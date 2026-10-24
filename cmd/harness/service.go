package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/artifact"
	"example.com/unified-harness/internal/coordinator"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
	"example.com/unified-harness/internal/worker"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func serveCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8090", "literal listen address")
	authFile := f.String("auth", "", "hashed credential configuration")
	artifacts := f.String("artifacts", "work/artifacts", "private evidence artifact directory")
	policies := f.String("policies", "", "target policy JSON")
	cert := f.String("tls-cert", "", "TLS certificate")
	key := f.String("tls-key", "", "TLS key")
	core := f.String("core", coreclient.DefaultBinary(), "Rust validator")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *authFile == "" || *policies == "" {
		return errors.New("--auth and --policies are required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil {
		return errors.New("listen requires a literal IP address")
	}
	if (*cert == "") != (*key == "") {
		return errors.New("both TLS certificate and key are required")
	}
	if !net.ParseIP(host).IsLoopback() && *cert == "" {
		return errors.New("non-loopback API listeners require TLS")
	}
	auth, err := coordinator.LoadAuth(*authFile)
	if err != nil {
		return err
	}
	registry, err := policy.Load(ctx, *policies, *core)
	if err != nil {
		return err
	}
	dsn := os.Getenv("HARNESS_DATABASE_URL")
	if dsn == "" {
		return errors.New("HARNESS_DATABASE_URL is required")
	}
	store, err := queue.Open(ctx, dsn, queue.CoreValidator{Binary: *core}, queue.DefaultSettings())
	if err != nil {
		return err
	}
	defer store.Close()
	blobs, err := artifact.OpenLocal(*artifacts)
	if err != nil {
		return err
	}
	defer blobs.Close()
	if err = store.ConfigureEvidence(*core, blobs); err != nil {
		return err
	}
	handler, err := coordinator.New(store, auth, registry)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	scheme := "http"
	if *cert != "" {
		scheme = "https"
	}
	fmt.Fprintf(out, "Authenticated coordinator: %s://%s\n", scheme, listener.Addr())
	if *cert != "" {
		err = server.ServeTLS(listener, *cert, *key)
	} else {
		err = server.Serve(listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func tokenFromFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 258))
	if err != nil {
		return "", err
	}
	if len(raw) > 257 {
		return "", errors.New("token file too large")
	}
	return strings.TrimSpace(string(raw)), nil
}
func apiCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("api", flag.ContinueOnError)
	base := f.String("url", "http://127.0.0.1:8090", "coordinator URL")
	tokenFile := f.String("token-file", "", "bearer token file")
	ca := f.String("ca", "", "optional trusted CA PEM")
	operation := f.String("operation", "", "queue operation")
	file := f.String("file", "", "JSON request")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected API arguments")
	}
	token, err := tokenFromFile(*tokenFile)
	if err != nil {
		return err
	}
	client, err := coordinator.NewClient(*base, token, *ca)
	if err != nil {
		return err
	}
	defer client.Close()
	input, err := readJSONFile(*file)
	if err != nil {
		return err
	}
	raw, err := client.Call(ctx, *operation, input)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, string(raw))
	return nil
}
func authInitCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("auth-init", flag.ContinueOnError)
	dir := f.String("out", "work/auth", "new private output directory")
	project := f.String("project", "lab-project", "authorized project")
	runID := f.String("run", "queue-demo", "authorized run")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected auth-init arguments")
	}
	var credentials []coordinator.Credential
	tokens := map[string][]byte{}
	for _, role := range []string{"operator", "worker"} {
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return err
		}
		token := hex.EncodeToString(entropy[:])
		sum := sha256.Sum256([]byte(token))
		credentials = append(credentials, coordinator.Credential{Subject: "local-" + role, Role: role, TokenSHA256: hex.EncodeToString(sum[:]), Scopes: map[string][]string{*project: {*runID}}})
		tokens[role+".token"] = []byte(token)
	}
	if _, err := coordinator.NewAuth(credentials); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*dir), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(*dir, 0700); err != nil {
		return fmt.Errorf("auth output directory must be new: %w", err)
	}
	raw, _ := json.MarshalIndent(credentials, "", "  ")
	tokens["credentials.json"] = raw
	for name, contents := range tokens {
		if err := os.WriteFile(filepath.Join(*dir, name), contents, 0600); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Created scoped credentials and private token files in %s\n", *dir)
	return nil
}
func workerCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("worker", flag.ContinueOnError)
	base := f.String("url", "http://127.0.0.1:8090", "coordinator URL")
	tokenFile := f.String("token-file", "", "worker token file")
	ca := f.String("ca", "", "trusted CA PEM")
	project := f.String("project", "", "project ID")
	runID := f.String("run", "", "run ID")
	policies := f.String("policies", "", "worker target policies")
	snapshots := f.String("snapshots", "", "registered source archive manifest")
	credentials := f.String("probe-credentials", "", "operator-configured scoped target credential references")
	image := f.String("image", "", "local sha256 Docker image ID")
	core := f.String("core", coreclient.DefaultBinary(), "Rust validator")
	once := f.Bool("once", false, "process at most one task")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *project == "" || *runID == "" || *policies == "" || *image == "" {
		return errors.New("--project, --run, --policies and --image are required")
	}
	token, err := tokenFromFile(*tokenFile)
	if err != nil {
		return err
	}
	client, err := coordinator.NewClient(*base, token, *ca)
	if err != nil {
		return err
	}
	defer client.Close()
	info, err := client.Info(ctx)
	if err != nil {
		return err
	}
	if info.Role != "worker" {
		return errors.New("worker credential required")
	}
	registry, err := policy.Load(ctx, *policies, *core)
	if err != nil {
		return err
	}
	registered, err := runner.LoadSnapshots(*snapshots)
	if err != nil {
		return err
	}
	engine, err := runner.NewDocker(ctx, *image, runner.DefaultLimits(), nil)
	if err != nil {
		return err
	}
	probeCredentials, err := policy.LoadCredentials(*credentials)
	if err != nil {
		return err
	}
	handler := runner.Handler{Policies: registry, Broker: policy.Broker{Policies: registry, Credentials: probeCredentials}, Executor: engine, Snapshots: registered}
	w := worker.Worker{Store: client, ProjectID: *project, RunID: *runID, WorkerID: info.Subject, HeartbeatEvery: client.LeaseDuration() / 3}
	if *once {
		if _, err = client.Reap(ctx, *project, *runID); err != nil {
			return err
		}
		status, err := w.RunOnce(ctx, handler.Run)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{"task_status": status})
	}
	fmt.Fprintln(out, "Worker connected; polling for scoped tasks.")
	return w.Run(ctx, time.Second, handler.Run)
}
