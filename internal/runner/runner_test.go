package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/policy"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testImage = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeCommand struct {
	calls [][]string
	fail  string
	state string
	wait  bool
}

func (f *fakeCommand) Run(ctx context.Context, input []byte, limit int64, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	if args[0] == f.fail {
		return nil, errors.New("injected daemon failure")
	}
	switch args[0] {
	case "info":
		return []byte(`{"OSType":"linux","CgroupVersion":"2","MemoryLimit":true,"SwapLimit":true,"CpuCfsQuota":true,"PidsLimit":true,"SecurityOptions":["name=seccomp,profile=builtin"]}`), nil
	case "image":
		return []byte(`{"Id":"` + testImage + `","Os":"linux","Config":{"Volumes":null}}`), nil
	case "create":
		return []byte("id"), nil
	case "start":
		if f.wait {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		var out bytes.Buffer
		if err := InspectStream(bytes.NewReader(input), &out); err != nil {
			return nil, err
		}
		if int64(out.Len()) > limit {
			return nil, ErrOutputLimit
		}
		return out.Bytes(), nil
	case "inspect":
		if f.state != "" {
			return []byte(f.state), nil
		}
		return []byte(`{"Running":false,"OOMKilled":false,"ExitCode":0}`), nil
	case "rm":
		return nil, nil
	}
	return nil, errors.New("unexpected Docker command")
}
func TestDockerConfinementAndCleanup(t *testing.T) {
	command := &fakeCommand{}
	d, err := NewDocker(t.Context(), testImage, DefaultLimits(), command)
	if err != nil {
		t.Fatal(err)
	}
	input := Input{Observations: []policy.Observation{{URL: "https://example.com", Status: 200, Body: []byte("sample")}}}
	raw, err := d.Execute(t.Context(), time.Now().Add(time.Minute), input, MaxOutput)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if json.Unmarshal(raw, &report) != nil || report.SecurityJudgment != "not_performed" {
		t.Fatal("invalid report")
	}
	create := command.calls[2]
	required := []string{"--pull=never", "--network=none", "--read-only", "--user=65532:65532", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=32", "--memory=134217728", "--memory-swap=134217728", "--cpus=0.500", "--restart=no", "--log-driver=none", "--entrypoint=/inspector"}
	for _, flag := range required {
		found := false
		for _, got := range create {
			if got == flag {
				found = true
			}
		}
		if !found {
			t.Error("missing confinement", flag)
		}
	}
	for _, arg := range create {
		if strings.HasPrefix(arg, "--mount") || strings.HasPrefix(arg, "--volume") || strings.HasPrefix(arg, "--env") || strings.HasPrefix(arg, "--privileged") {
			t.Fatal("host data or privilege exposed", arg)
		}
	}
	last := command.calls[len(command.calls)-1]
	if last[0] != "rm" || last[1] != "--force" || last[2] != create[2] {
		t.Fatal("container not removed by identity", last)
	}
}
func TestDockerFailuresStillCleanUp(t *testing.T) {
	for _, step := range []string{"create", "start", "inspect", "rm"} {
		t.Run(step, func(t *testing.T) {
			command := &fakeCommand{fail: step}
			d, err := NewDocker(t.Context(), testImage, DefaultLimits(), command)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.Execute(t.Context(), time.Now().Add(time.Minute), Input{}, 1024); err == nil {
				t.Fatal("failure accepted")
			}
			if command.calls[len(command.calls)-1][0] != "rm" {
				t.Fatal("cleanup missing after failure")
			}
		})
	}
	command := &fakeCommand{wait: true}
	d, err := NewDocker(t.Context(), testImage, DefaultLimits(), command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Execute(t.Context(), time.Now().Add(30*time.Millisecond), Input{}, 1024); err == nil {
		t.Fatal("deadline ignored")
	}
	if command.calls[len(command.calls)-1][0] != "rm" {
		t.Fatal("deadline did not remove container")
	}
}
func TestDockerRejectsOOMOutputOverflowAndMutableImages(t *testing.T) {
	if _, err := NewDocker(t.Context(), "runner:latest", DefaultLimits(), &fakeCommand{}); err == nil {
		t.Fatal("mutable image accepted")
	}
	command := &fakeCommand{state: `{"Running":false,"OOMKilled":true,"ExitCode":137}`}
	d, err := NewDocker(t.Context(), testImage, DefaultLimits(), command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Execute(t.Context(), time.Now().Add(time.Minute), Input{}, 1024); err == nil {
		t.Fatal("OOM reported as success")
	}
	command = &fakeCommand{}
	d, err = NewDocker(t.Context(), testImage, DefaultLimits(), command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Execute(t.Context(), time.Now().Add(time.Minute), Input{}, 1); !errors.Is(err, ErrOutputLimit) {
		t.Fatal("output bound ignored", err)
	}
	cancelled := false
	writer := cappedWriter{limit: 3, cancel: func() { cancelled = true }}
	if _, err = writer.Write([]byte("abcd")); err != ErrOutputLimit || !cancelled || writer.buffer.Len() != 0 {
		t.Fatal("process output was not bounded")
	}
}
func archive(t *testing.T, headers ...tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, header := range headers {
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(bytes.Repeat([]byte("x"), int(header.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestInspectorRejectsUnsafeArchives(t *testing.T) {
	for _, header := range []tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg}, {Name: "/absolute", Typeflag: tar.TypeReg},
		{Name: `folder\escape`, Typeflag: tar.TypeReg}, {Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "hardlink", Typeflag: tar.TypeLink, Linkname: "secret"},
	} {
		if _, err := Inspect(Input{SourceTar: archive(t, header)}); err == nil {
			t.Error("unsafe archive accepted", header)
		}
	}
	dup := tar.Header{Name: "same", Typeflag: tar.TypeReg}
	if _, err := Inspect(Input{SourceTar: archive(t, dup, dup)}); err == nil {
		t.Fatal("duplicate archive accepted")
	}
	good := archive(t, tar.Header{Name: "src/main.go", Typeflag: tar.TypeReg, Size: 5})
	report, err := Inspect(Input{SourceTar: good})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(report.Files, []File{{"src/main.go", 5, digest([]byte("xxxxx"))}}) {
		t.Fatal(report)
	}
}
func TestSnapshotDigestAndInputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.tar")
	data := archive(t, tar.Header{Name: "file", Typeflag: tar.TypeReg})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Archive: path, SHA256: digest(data)}
	if _, err := readSnapshot(snapshot, int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshot(snapshot, 1); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
	snapshot.SHA256 = strings.Repeat("0", 64)
	if _, err := readSnapshot(snapshot, int64(len(data))); err == nil {
		t.Fatal("changed snapshot accepted")
	}
}
