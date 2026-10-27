package runner

import (
	"context"
	"strings"
	"testing"

	"example.com/unified-harness/internal/webinvestigator"
)

func TestWorkspaceContainerHasNoDirectTargetNetworkOrHostMounts(t *testing.T) {
	d := &WorkspaceDocker{Image: "sha256:" + strings.Repeat("a", 64), Seccomp: "/tmp/seccomp.json"}
	args := strings.Join(d.createArgs("test"), " ")
	for _, required := range []string{"--network=none", "--read-only", "--cap-drop=ALL", "--cap-add=SYS_CHROOT", "--security-opt=no-new-privileges:true", "--security-opt=seccomp=/tmp/seccomp.json", "--user=10001:10001", "--memory=", "--pids-limit=", "--log-driver=none"} {
		if !strings.Contains(args, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"--privileged", "--cap-add=SYS_ADMIN", "--network=host", "--volume", "--mount", "docker.sock"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("unsafe Docker option %s", forbidden)
		}
	}
}
func TestWorkspaceRejectsMutationAndStaleActionBeforeBroker(t *testing.T) {
	s := webinvestigator.Spec{Investigator: &webinvestigator.Config{AllowMutations: false}}
	s.Budget.Requests = 2
	tool := &workspaceTool{task: s, observations: 1}
	var f workspaceFrame
	f.ActionID = 1
	f.ID = 1
	f.Request.URL = "http://127.0.0.1:8081/object/a"
	f.Request.Method = "POST"
	if _, _, n, _, err := tool.network(context.Background(), webinvestigator.Action{}, f); err == nil || n != 0 {
		t.Fatal("mutation admitted")
	}
	f.Request.Method = "GET"
	f.ActionID = 0
	if _, _, n, _, err := tool.network(context.Background(), webinvestigator.Action{}, f); err == nil || n != 0 {
		t.Fatal("stale action admitted")
	}
	s.Investigator.AllowMutations = true
	tool.task = s
	f.ActionID = 1
	f.Request.Method = "POST"
	if _, _, n, _, err := tool.network(context.Background(), webinvestigator.Action{Kind: "snapshot"}, f); err == nil || n != 0 {
		t.Fatal("ambient browser mutation admitted")
	}
}
