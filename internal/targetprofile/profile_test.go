package targetprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"example.com/unified-harness/internal/configfile"
)

func testProfile(t *testing.T) Profile {
	t.Helper()
	var p Profile
	if err := configfile.Read("../../examples/target.web.json", &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func core(t *testing.T) string {
	t.Helper()
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p, err := filepath.Abs(filepath.Join("../..", "target/debug", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPrepareIsOfflineAndRetainsNoSourceOrSecrets(t *testing.T) {
	p := testProfile(t)
	base := t.TempDir()
	b, err := Prepare(t.Context(), p, "pilot-run", base, core(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if b.Run.MaxTasks != 3 || b.Run.MaxAttempts != 3 || b.Run.Limits.Requests != 9 || b.Run.Limits.Tokens != 0 || len(b.Tasks) != 2 {
		t.Fatal(b)
	}
	if !filepath.IsAbs(b.Credentials[0].TokenFile) {
		t.Fatal("credential path not resolved")
	}
	var prepare, hunt struct {
		Stage        string   `json:"stage"`
		Dependencies []string `json:"dependencies"`
		Budget       struct {
			Requests int `json:"max_requests"`
		} `json:"budget"`
	}
	if err = json.Unmarshal(b.Tasks[0].Task, &prepare); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b.Tasks[1].Task, &hunt); err != nil {
		t.Fatal(err)
	}
	if prepare.Stage != "prepare" || prepare.Budget.Requests != 2 || len(prepare.Dependencies) != 0 || hunt.Stage != "hunt" || hunt.Budget.Requests != 3 || len(hunt.Dependencies) != 1 || hunt.Dependencies[0] != b.Tasks[0].ID {
		t.Fatal(prepare, hunt)
	}
	raw := b.Tasks[0].Task
	var task map[string]any
	if err = json.Unmarshal(raw, &task); err != nil {
		t.Fatal(err)
	}
	target := task["target"].(map[string]any)
	if target["mode"] != "web" || target["source"] != nil || task["investigator"] != nil {
		t.Fatal("source or investigator required", task)
	}
	if _, err = os.Stat(filepath.Join(base, "secrets")); !os.IsNotExist(err) {
		t.Fatal("unexpected secret file operation", err)
	}
}
func TestPrepareRejectsInvalidProfilesBeforeWriting(t *testing.T) {
	for _, change := range []func(*Profile){
		func(p *Profile) { p.Checks[0].Plan.IdentityB = "missing" },
		func(p *Profile) { p.Identities[1].Ref = p.Identities[0].Ref },
		func(p *Profile) { p.Checks[0].ID = "../escape" },
		func(p *Profile) { p.Checks[0].ID = "bad:file" },
		func(p *Profile) { p.Checks[0].ID = "preflight-invoice-access" },
		func(p *Profile) { copy := p.Checks[0]; copy.ID = "INVOICE-ACCESS"; p.Checks = append(p.Checks, copy) },
		func(p *Profile) { p.Checks[0].Plan.Object.PathTemplate = "//other.test/{id}" },
		func(p *Profile) { p.Checks[0].Plan.Object.Response.ProtectedValue = "/data/id" },
		func(p *Profile) { p.MaxAttempts = 1000 },
		func(p *Profile) { p.WallSeconds = 0 },
		func(p *Profile) { p.DeadlineSeconds = 1 },
		func(p *Profile) { p.CIDRs = []string{} },
		func(p *Profile) { p.Origin = "http://api.example.test" },
		func(p *Profile) { p.Identities[0].AuthKind = "api_key"; p.Identities[0].HeaderName = "Host" },
	} {
		p := testProfile(t)
		change(&p)
		if _, err := Prepare(t.Context(), p, "pilot-run", t.TempDir(), core(t), time.Now()); err == nil {
			t.Fatal("accepted invalid profile", p)
		}
	}
}
