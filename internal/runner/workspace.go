package runner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/webinvestigator"
)

// WorkspaceDocker launches an offline, disposable Linux browser and shell.
// Only the host broker can reach a target; the guest has no network, mounts,
// Docker socket, credentials, or inherited environment.
type WorkspaceDocker struct {
	Image   string
	Seccomp string
	Binary  string
}

const workspaceSeccompSHA256 = "cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"

func NewWorkspaceDocker(ctx context.Context, image, seccomp string) (*WorkspaceDocker, error) {
	if _, err := NewDocker(ctx, image, Limits{MemoryBytes: 768 << 20, CPUMillis: 1000, PIDs: 96, TmpBytes: 32 << 20}, nil); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(seccomp)
	if err != nil || len(raw) > 32<<10 {
		return nil, errors.New("workspace seccomp profile unavailable")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != workspaceSeccompSHA256 {
		return nil, errors.New("workspace seccomp profile digest mismatch")
	}
	absolute, err := filepath.Abs(seccomp)
	if err != nil {
		return nil, err
	}
	return &WorkspaceDocker{Image: image, Seccomp: absolute, Binary: "docker"}, nil
}

type workspaceFrame struct {
	Type           string `json:"type"`
	BrowserVersion string `json:"browser_version"`
	ID             int64  `json:"id"`
	ActionID       int64  `json:"action_id"`
	Text           string `json:"text"`
	Error          string `json:"error"`
	Request        struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	} `json:"request"`
}
type workspaceReply struct {
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body_base64,omitempty"`
	Error   string            `json:"error,omitempty"`
}
type workspaceTool struct {
	docker         *WorkspaceDocker
	name           string
	cmd            *exec.Cmd
	stdin          io.WriteCloser
	frames         chan workspaceFrame
	done           chan struct{}
	cancel         context.CancelFunc
	broker         policy.Broker
	policy         policy.Policy
	credentials    *policy.Credentials
	task           webinvestigator.Spec
	admissions     int64
	observations   int64
	closed         bool
	browserVersion string
}

func (w *WorkspaceDocker) binary() string {
	if w.Binary == "" {
		return "docker"
	}
	return w.Binary
}
func (w *WorkspaceDocker) createArgs(name string) []string {
	return []string{"create", "--name", name, "--pull=never", "--label=opensec.workspace=1", "--interactive",
		"--network=none", "--cgroupns=private", "--ipc=private", "--read-only", "--user=10001:10001",
		"--cap-drop=ALL", "--cap-add=SYS_CHROOT", "--security-opt=no-new-privileges:true", "--security-opt=seccomp=" + w.Seccomp,
		"--pids-limit=96", "--memory=805306368", "--memory-swap=805306368", "--cpus=1.000",
		"--tmpfs=/tmp:rw,nosuid,nodev,size=33554432,mode=1777",
		"--tmpfs=/work:rw,nosuid,nodev,size=33554432,mode=1777",
		"--tmpfs=/dev/shm:rw,nosuid,nodev,size=67108864,mode=1777",
		"--ulimit=nofile=128:128", "--restart=no", "--log-driver=none", w.Image}
}
func boundedDocker(ctx context.Context, binary string, args ...string) error {
	check, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(check, binary, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	stdout := &cappedWriter{limit: 8 << 10, cancel: cancel}
	stderr := &cappedWriter{limit: 8 << 10, cancel: cancel}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return errors.New("workspace Docker operation failed")
	}
	if stdout.overflow || stderr.overflow {
		return errors.New("workspace Docker output limit")
	}
	return nil
}
func (w *WorkspaceDocker) Open(ctx context.Context, deadline time.Time, broker policy.Broker, p policy.Policy, s webinvestigator.Spec) (tool *workspaceTool, err error) {
	if w == nil || w.Image == "" || w.Seccomp == "" {
		return nil, errors.New("workspace is not configured")
	}
	name := "opensec-web-" + randomName()
	// Always try removal, even when create times out after Docker accepted it.
	created := false
	defer func() {
		if err != nil || !created {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = boundedDocker(cleanup, w.binary(), "rm", "--force", name)
		}
	}()
	if err = boundedDocker(ctx, w.binary(), w.createArgs(name)...); err != nil {
		return nil, err
	}
	created = true
	deadline = minDeadline(deadline, minDeadline(s.Deadline, time.Now().Add(15*time.Minute)))
	procCtx, cancel := context.WithDeadline(ctx, deadline)
	cmd := exec.CommandContext(procCtx, w.binary(), "start", "--attach", "--interactive", name)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		cancel()
		return nil, e
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		cancel()
		return nil, e
	}
	stderr := &cappedWriter{limit: 16 << 10, cancel: cancel}
	cmd.Stderr = stderr
	cmd.WaitDelay = 2 * time.Second
	if e = cmd.Start(); e != nil {
		cancel()
		return nil, errors.New("workspace failed to start")
	}
	t := &workspaceTool{docker: w, name: name, cmd: cmd, stdin: stdin, frames: make(chan workspaceFrame, 16), done: make(chan struct{}), broker: broker, policy: p, credentials: broker.Credentials, task: s}
	go func() {
		defer close(t.done)
		defer close(t.frames)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 256<<10)
		count := 0
		for scanner.Scan() {
			count++
			if count > 2048 {
				cancel()
				return
			}
			var f workspaceFrame
			if json.Unmarshal(scanner.Bytes(), &f) != nil {
				cancel()
				return
			}
			select {
			case t.frames <- f:
			case <-procCtx.Done():
				return
			}
		}
	}()
	readyCtx, readyCancel := context.WithTimeout(procCtx, 45*time.Second)
	defer readyCancel()
	select {
	case frame, ok := <-t.frames:
		if !ok || frame.Type != "ready" {
			cancel()
			_ = cmd.Wait()
			detail := strings.TrimSpace(frame.Text)
			if detail == "" {
				detail = strings.TrimSpace(stderr.buffer.String())
			}
			if len(detail) > 1024 {
				detail = detail[len(detail)-1024:]
			}
			if detail != "" {
				return nil, fmt.Errorf("workspace browser failed to initialize: %s", detail)
			}
			return nil, errors.New("workspace browser failed to initialize")
		}
		if frame.BrowserVersion == "" || len(frame.BrowserVersion) > 128 {
			cancel()
			_ = cmd.Wait()
			return nil, errors.New("workspace browser version unavailable")
		}
		t.browserVersion = frame.BrowserVersion
	case <-readyCtx.Done():
		cancel()
		_ = cmd.Wait()
		return nil, errors.New("workspace browser startup timed out")
	}
	// Closing the process context is handled by Close after all model steps.
	t.cancel = cancel
	return t, nil
}
func (t *workspaceTool) Close() error {
	if t == nil || t.closed {
		return nil
	}
	t.closed = true
	t.cancel()
	_ = t.stdin.Close()
	_ = t.cmd.Wait()
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := boundedDocker(cleanup, t.docker.binary(), "rm", "--force", t.name); err != nil {
		return errors.New("workspace cleanup could not be confirmed")
	}
	return nil
}
func (t *workspaceTool) send(value any) error {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 128<<10 {
		return errors.New("workspace frame too large")
	}
	_, e = t.stdin.Write(append(raw, '\n'))
	return e
}
func (t *workspaceTool) network(ctx context.Context, action webinvestigator.Action, f workspaceFrame) (workspaceReply, *webinvestigator.NetworkEvent, int64, bool, error) {
	deny := workspaceReply{Error: "request_denied"}
	if f.ActionID != t.observations || f.ID < 1 || f.ID > 100000 || f.Request.URL == "" || t.admissions >= t.task.Budget.Requests {
		return deny, nil, 0, false, errors.New("workspace request outside active action or budget")
	}
	method := f.Request.Method
	if method != "GET" && method != "HEAD" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
		return deny, nil, 0, false, errors.New("unsupported method")
	}
	mutation := method != "GET" && method != "HEAD"
	if mutation && !t.task.Investigator.AllowMutations {
		return deny, nil, 0, false, errors.New("mutation outside task scope")
	}
	if mutation {
		switch action.Kind {
		case "request":
			if action.NetworkMethod() != method || action.URL != f.Request.URL {
				return deny, nil, 0, false, errors.New("mutation differs from explicit request")
			}
		case "click":
			if !action.AllowMutation {
				return deny, nil, 0, false, errors.New("browser write needs explicit click authority")
			}
		case "command":
			// The shell command explicitly names its brokered HTTP operation.
		default:
			return deny, nil, 0, false, errors.New("browser write is not an explicit action")
		}
	}
	if len(f.Request.Body) > 32768 || policy.ValidateHeaders(f.Request.Headers) != nil {
		return deny, nil, 0, false, errors.New("invalid guest request")
	}
	probe := policy.Probe{URL: f.Request.URL, IdentityRef: action.IdentityRef, Method: method, Body: []byte(f.Request.Body), Headers: f.Request.Headers}
	observed, count, _, e := t.broker.FetchProbes(ctx, t.policy, []policy.Probe{probe}, 1, 32<<10)
	t.admissions += count
	uncertain := errors.Is(e, policy.ErrTrafficUnavailable)
	if len(observed) == 0 {
		if e != nil {
			return workspaceReply{Error: "target_request_failed"}, nil, count, uncertain, e
		}
		return workspaceReply{Error: "empty_response"}, nil, count, false, errors.New("empty broker response")
	}
	o := observed[0]
	redacted := t.credentials.Redact(o.Body)
	recordedURL := o.URL
	if parsed, e := url.Parse(recordedURL); e == nil {
		parsed.RawQuery = ""
		parsed.ForceQuery = false
		parsed.Fragment = ""
		recordedURL = parsed.String()
	}
	sum := sha256.Sum256(redacted)
	event := &webinvestigator.NetworkEvent{URL: recordedURL, Method: method, IdentityRef: action.IdentityRef, Status: o.Status, BodyBytes: int64(len(redacted)), BodySHA256: hex.EncodeToString(sum[:])}
	headers := map[string]string{}
	for k, v := range o.Headers {
		headers[k] = string(t.credentials.Redact([]byte(v)))
	}
	reply := workspaceReply{Status: o.Status, Headers: headers, Body: base64.StdEncoding.EncodeToString(redacted)}
	if e != nil {
		return workspaceReply{Error: "target_request_incomplete"}, event, count, uncertain, e
	}
	return reply, event, count, false, nil
}
func (t *workspaceTool) Execute(ctx context.Context, a webinvestigator.Action) (webinvestigator.ToolResult, error) {
	result := webinvestigator.ToolResult{Events: []webinvestigator.NetworkEvent{}, BrowserVersion: t.browserVersion}
	if t.closed {
		return result, errors.New("workspace closed")
	}
	t.observations++
	id := t.observations
	if err := t.send(map[string]any{"type": "action", "id": id, "action": a}); err != nil {
		return result, err
	}
	actionCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
	defer cancel()
	for {
		select {
		case <-actionCtx.Done():
			return result, actionCtx.Err()
		case f, ok := <-t.frames:
			if !ok {
				return result, errors.New("workspace exited")
			}
			switch f.Type {
			case "network_request":
				reply, event, count, uncertain, e := t.network(actionCtx, a, f)
				result.Admissions += count
				result.UsageUncertain = result.UsageUncertain || uncertain
				if event != nil {
					result.Events = append(result.Events, *event)
				}
				if f.Request.Method != "GET" && f.Request.Method != "HEAD" {
					result.Mutating = result.Mutating || count > 0
				}
				if sendErr := t.send(map[string]any{"type": "network_reply", "id": f.ID, "response": reply}); sendErr != nil {
					return result, sendErr
				}
				if e != nil {
					if count == 0 && !uncertain && !errors.Is(e, policy.ErrLimit) && !errors.Is(e, policy.ErrTargetBackoff) {
						// A page may load out-of-scope resources. Abort only that request;
						// the authorized navigation can still complete.
						continue
					}
					result.Text = reply.Error
					return result, e
				}
			case "action_result":
				if f.ID != id {
					return result, errors.New("workspace action mismatch")
				}
				result.Text = string(t.credentials.Redact([]byte(f.Text)))
				if len(result.Text) > webinvestigator.MaxToolOutput {
					result.Text = result.Text[:webinvestigator.MaxToolOutput]
				}
				if f.Error != "" {
					return result, fmt.Errorf("workspace action failed")
				}
				return result, nil
			case "fatal":
				return result, errors.New("workspace browser failed")
			default:
				return result, errors.New("unknown workspace frame")
			}
		}
	}
}
