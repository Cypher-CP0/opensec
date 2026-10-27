package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrOutputLimit = errors.New("container output limit exceeded")

type Command interface {
	Run(context.Context, []byte, int64, ...string) ([]byte, error)
}
type DockerCommand struct{ Binary string }
type cappedWriter struct {
	buffer   bytes.Buffer
	limit    int64
	cancel   context.CancelFunc
	overflow bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if int64(w.buffer.Len()+len(p)) > w.limit {
		w.overflow = true
		w.cancel()
		return 0, ErrOutputLimit
	}
	return w.buffer.Write(p)
}
func (c DockerCommand) Run(ctx context.Context, input []byte, limit int64, args ...string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := &cappedWriter{limit: limit, cancel: cancel}
	stderr := &cappedWriter{limit: 16 << 10, cancel: cancel}
	binary := c.Binary
	if binary == "" {
		binary = "docker"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if stdout.overflow || stderr.overflow {
		return nil, ErrOutputLimit
	}
	if err != nil {
		return nil, errors.New("Docker operation failed")
	}
	return stdout.buffer.Bytes(), nil
}

type Limits struct {
	MemoryBytes int64
	CPUMillis   int64
	PIDs        int
	TmpBytes    int64
}

func DefaultLimits() Limits { return Limits{128 << 20, 500, 32, 16 << 20} }
func (l Limits) validate() error {
	if l.MemoryBytes < 32<<20 || l.MemoryBytes > 1<<30 || l.CPUMillis < 100 || l.CPUMillis > 2000 || l.PIDs < 8 || l.PIDs > 128 || l.TmpBytes < 1<<20 || l.TmpBytes > 64<<20 {
		return errors.New("unsupported container resource limits")
	}
	return nil
}

type Docker struct {
	Image   string
	Limits  Limits
	command Command
}

func NewDocker(ctx context.Context, image string, limits Limits, command Command) (*Docker, error) {
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(image) {
		return nil, errors.New("runner image must be a local immutable sha256 image ID")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if command == nil {
		command = DockerCommand{}
	}
	d := &Docker{image, limits, command}
	// Docker Desktop on WSL can take more than ten seconds to answer info,
	// particularly after startup. This preflight happens before task execution;
	// container deadlines and cleanup retain their separate, shorter bounds.
	check, done := context.WithTimeout(ctx, 30*time.Second)
	defer done()
	raw, err := command.Run(check, nil, 128<<10, "info", "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var info struct {
		OSType, CgroupVersion                          string
		MemoryLimit, SwapLimit, CpuCfsQuota, PidsLimit bool
		SecurityOptions                                []string
	}
	if json.Unmarshal(raw, &info) != nil || info.OSType != "linux" || info.CgroupVersion != "2" || !info.MemoryLimit || !info.SwapLimit || !info.CpuCfsQuota || !info.PidsLimit {
		return nil, errors.New("runner requires Linux cgroup v2 with memory, swap, CPU and PID enforcement")
	}
	seccomp := false
	for _, option := range info.SecurityOptions {
		if strings.Contains(option, "name=seccomp") {
			seccomp = true
		}
	}
	if !seccomp {
		return nil, errors.New("runner requires Docker's default seccomp protection")
	}
	raw, err = command.Run(check, nil, 16<<10, "image", "inspect", image, "--format", "{{json .}}")
	if err != nil {
		return nil, err
	}
	var imageInfo struct {
		ID     string `json:"Id"`
		OS     string `json:"Os"`
		Config struct{ Volumes map[string]any }
	}
	if json.Unmarshal(raw, &imageInfo) != nil || imageInfo.ID != image || imageInfo.OS != "linux" || len(imageInfo.Config.Volumes) != 0 {
		return nil, errors.New("image must be a local Linux image without implicit volumes")
	}
	return d, nil
}
func (d *Docker) createArgs(name string, deadline time.Time) []string {
	l := d.Limits
	return []string{"create", "--name", name, "--pull=never", "--label=opensec.runner=1", "--interactive", "--network=none", "--cgroupns=private", "--ipc=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=" + strconv.Itoa(l.PIDs), "--memory=" + strconv.FormatInt(l.MemoryBytes, 10), "--memory-swap=" + strconv.FormatInt(l.MemoryBytes, 10), "--cpus=" + strconv.FormatFloat(float64(l.CPUMillis)/1000, 'f', 3, 64), "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=" + strconv.FormatInt(l.TmpBytes, 10) + ",mode=1777", "--ulimit=nofile=64:64", "--restart=no", "--log-driver=none", "--entrypoint=/inspector", d.Image, "--deadline-unix-ms", strconv.FormatInt(deadline.UnixMilli(), 10), "--memory-bytes", strconv.FormatInt(l.MemoryBytes, 10), "--cpu-millis", strconv.FormatInt(l.CPUMillis, 10), "--pids", strconv.Itoa(l.PIDs), "--tmp-bytes", strconv.FormatInt(l.TmpBytes, 10)}
}
func (d *Docker) Execute(ctx context.Context, deadline time.Time, input Input, maxOutput int64) (result json.RawMessage, err error) {
	if maxOutput < 1 || maxOutput > MaxOutput {
		return nil, errors.New("invalid output limit")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxInput {
		return nil, errors.New("container input exceeds limit")
	}
	deadline = minDeadline(deadline, time.Now().Add(5*time.Minute))
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	name := "opensec-" + randomName()
	// Install cleanup before create: a timed-out create may still have succeeded.
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_, removeErr := d.command.Run(cleanup, nil, 16<<10, "rm", "--force", name)
		if removeErr != nil {
			result = nil
			err = errors.New("container cleanup could not be confirmed")
		}
	}()
	if _, err = d.command.Run(ctx, nil, 16<<10, d.createArgs(name, deadline)...); err != nil {
		return nil, err
	}
	result, err = d.command.Run(ctx, raw, maxOutput, "start", "--attach", "--interactive", name)
	if err != nil {
		return nil, err
	}
	state, err := d.command.Run(ctx, nil, 16<<10, "inspect", name, "--format", "{{json .State}}")
	if err != nil {
		return nil, err
	}
	var status struct {
		Running, OOMKilled bool
		ExitCode           int
	}
	if json.Unmarshal(state, &status) != nil || status.Running || status.OOMKilled || status.ExitCode != 0 {
		return nil, errors.New("container failed or exceeded a resource limit")
	}
	judgment := "deterministic_check"
	if input.Preflight {
		judgment = "preflight_only"
	}
	var report Report
	decoder := json.NewDecoder(bytes.NewReader(result))
	decoder.DisallowUnknownFields()
	if !json.Valid(result) || decoder.Decode(&report) != nil || report.Kind != "inspection" || ((input.Check == nil && (report.SecurityJudgment != "not_performed" || report.Check != nil)) || (input.Check != nil && (report.SecurityJudgment != judgment || report.Check == nil))) {
		return nil, errors.New("invalid inspector result")
	}
	return result, nil
}
func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func randomName() string {
	var b [16]byte
	if _, err := io.ReadFull(randomReader, b[:]); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b[:])
}
