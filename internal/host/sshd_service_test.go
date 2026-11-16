package host

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// states builds the activeState function ResolveSSHDService asks, from a
// table of `systemctl is-active` answers. A unit not in the table reads as
// "inactive", which is what systemctl prints for a unit it has never loaded.
func states(table map[string]string) func(string) string {
	return func(unit string) string {
		if state, ok := table[unit]; ok {
			return state
		}
		return "inactive"
	}
}

// TestResolveSSHDService covers the machines the probe meets: Fedora and Arch
// (sshd.service runs sshd), Debian without the socket (ssh.service), Ubuntu
// 22.10 and later with nothing connected yet (ssh.socket listening, the service
// idle), the same Ubuntu after a connection, and a machine with no server.
func TestResolveSSHDService(t *testing.T) {
	cases := []struct {
		name      string
		table     map[string]string
		want      SSHDService
		exposed   bool
		stateWord string
	}{
		{"fedora", map[string]string{"sshd": "active"},
			SSHDService{Unit: "sshd", Running: true}, true, "sshd is active"},
		{"debian", map[string]string{"ssh": "active"},
			SSHDService{Unit: "ssh", Running: true}, true, "ssh is active"},
		{"ubuntu idle", map[string]string{"ssh.socket": "active"},
			SSHDService{Unit: "ssh", Socket: "ssh.socket"}, true,
			"ssh idle, ssh.socket listening"},
		{"ubuntu connected", map[string]string{"ssh": "active", "ssh.socket": "active"},
			SSHDService{Unit: "ssh", Running: true, Socket: "ssh.socket"}, true,
			"ssh is active, started by ssh.socket"},
		{"sshd socket idle", map[string]string{"sshd.socket": "active"},
			SSHDService{Unit: "sshd", Socket: "sshd.socket"}, true,
			"sshd idle, sshd.socket listening"},
		{"socket failed", map[string]string{"ssh.socket": "failed"},
			SSHDService{Unit: "sshd"}, false, "not running"},
		{"nothing", map[string]string{},
			SSHDService{Unit: "sshd"}, false, "not running"},
	}
	for _, tc := range cases {
		got := ResolveSSHDService(states(tc.table))
		if got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
		if got.Exposed() != tc.exposed {
			t.Errorf("%s: Exposed() = %v, want %v", tc.name, got.Exposed(), tc.exposed)
		}
		if got.State() != tc.stateWord {
			t.Errorf("%s: State() = %q, want %q", tc.name, got.State(), tc.stateWord)
		}
	}
}

// TestSSHDApplyCommand: an idle socket-activated server must not get
// `systemctl reload`, which fails with "is not active, cannot reload" after
// the drop-in is already installed. A plain running server keeps the reload.
func TestSSHDApplyCommand(t *testing.T) {
	cases := []struct {
		service SSHDService
		want    string
	}{
		{SSHDService{Unit: "sshd", Running: true}, "systemctl reload sshd"},
		{SSHDService{Unit: "ssh", Socket: "ssh.socket"},
			"systemctl try-reload-or-restart ssh"},
		{SSHDService{Unit: "ssh", Running: true, Socket: "ssh.socket"},
			"systemctl try-reload-or-restart ssh"},
		{SSHDService{Unit: "sshd"}, "systemctl try-reload-or-restart sshd"},
	}
	for _, tc := range cases {
		cmd, err := BuildSSHDApply(tc.service)
		if err != nil {
			t.Fatalf("%+v: %v", tc.service, err)
		}
		if got := cmd.String(); got != tc.want {
			t.Errorf("%+v: argv = %q, want %q", tc.service, got, tc.want)
		}
		if !cmd.Destructive {
			t.Errorf("%+v: applying an sshd change is destructive", tc.service)
		}
	}
	for _, bad := range []SSHDService{
		{Unit: "nginx", Socket: "ssh.socket"},
		{Unit: "ssh", Socket: "evil.socket"},
		{Unit: "ssh; rm -rf /"},
	} {
		if _, err := BuildSSHDApply(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

// TestMissingPrivsepDir reads the directory from sshd's own message.
func TestMissingPrivsepDir(t *testing.T) {
	dir, ok := MissingPrivsepDir("Missing privilege separation directory: /run/sshd\n")
	if !ok || dir != "/run/sshd" {
		t.Errorf("got %q, %v; want /run/sshd", dir, ok)
	}
	if _, ok := MissingPrivsepDir("sshd: no hostkeys available -- exiting."); ok {
		t.Error("an unrelated failure was taken for the missing directory")
	}
	for _, good := range []string{"/run/sshd", "/var/run/sshd"} {
		if !IsRuntimePrivsepDir(good) {
			t.Errorf("%s should be a runtime directory", good)
		}
	}
	for _, bad := range []string{"/var/empty/sshd", "/usr/share/empty.sshd",
		"/run/../etc", "/run/a/b", "/run/", "run/sshd"} {
		if IsRuntimePrivsepDir(bad) {
			t.Errorf("%s was taken for a runtime directory", bad)
		}
		if _, err := BuildEnsurePrivsepDir(bad); err == nil {
			t.Errorf("BuildEnsurePrivsepDir(%q) was accepted", bad)
		}
	}
}

// idlePlanInput is a weak keyword on an idle Ubuntu server whose /run/sshd
// does not exist yet.
func idlePlanInput() SSHDPlanInput {
	return SSHDPlanInput{
		Key: "PermitRootLogin",
		Effective: map[string]string{
			"permitrootlogin": "yes", "pubkeyauthentication": "yes",
			"passwordauthentication": "yes",
		},
		Unit:       "ssh",
		Service:    SSHDService{Unit: "ssh", Socket: "ssh.socket"},
		PrivsepDir: "/run/sshd",
		Paths:      LoginPath{Keys: []string{"deploy"}},
	}
}

// TestSSHDPlanOnIdleSocketServer: the plan creates the missing directory
// before the check (which would otherwise fail), keeps the check, and applies
// with try-reload-or-restart. Nothing is skipped to make the change go through.
func TestSSHDPlanOnIdleSocketServer(t *testing.T) {
	temp := "/tmp/tui-secure-3/50-tui-secure.conf"
	plan, err := SSHDPlan(idlePlanInput(), temp)
	if err != nil {
		t.Fatalf("SSHDPlan: %v", err)
	}
	var got []string
	for _, cmd := range plan.Commands {
		got = append(got, cmd.String())
	}
	want := []string{
		"install -d -m 0755 -o root -g root /run/sshd",
		"sshd -t -f " + temp,
		"install -m " + SSHDFileMode + " " + temp + " " + SSHDDropInPath,
		"systemctl try-reload-or-restart ssh",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("commands:\n%s\nwant:\n%s", strings.Join(got, "\n"),
			strings.Join(want, "\n"))
	}
	if !strings.Contains(plan.Body, "idle under socket activation") {
		t.Errorf("the dialog does not explain the extra step:\n%s", plan.Body)
	}
}

// TestSSHDPlanRefusesPackagePrivsepDir: a missing directory outside /run is a
// broken package, not something to create, and the plan fails closed.
func TestSSHDPlanRefusesPackagePrivsepDir(t *testing.T) {
	in := idlePlanInput()
	in.PrivsepDir = "/var/empty/sshd"
	plan, err := SSHDPlan(in, "/tmp/tui-secure-4/50-tui-secure.conf")
	if err == nil {
		t.Fatalf("the plan was built anyway: %v", plan.Commands)
	}
	if !strings.Contains(err.Error(), "reinstalling the package") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
}

// TestSSHDPlanWithoutServiceKeepsReload: a plan built from the unit name alone
// (the zero Service) is the one this tool always built.
func TestSSHDPlanWithoutServiceKeepsReload(t *testing.T) {
	in := idlePlanInput()
	in.Service, in.PrivsepDir, in.Unit = SSHDService{}, "", "sshd"
	plan, err := SSHDPlan(in, "/tmp/tui-secure-5/50-tui-secure.conf")
	if err != nil {
		t.Fatalf("SSHDPlan: %v", err)
	}
	if got := plan.Commands[len(plan.Commands)-1].String(); got != "systemctl reload sshd" {
		t.Errorf("apply = %q, want the plain reload", got)
	}
}

// TestSSHSummaryIdleSocket: an idle socket-activated server is graded like a
// running one, and the summary says it is listening rather than running.
func TestSSHSummaryIdleSocket(t *testing.T) {
	settings := map[string]string{"permitrootlogin": "yes"}
	idle := SSHDService{Unit: "ssh", Socket: "ssh.socket"}
	got := sshSummary(settings, posture.StatusWarn, idle)
	if !strings.Contains(got, "ssh.socket listening") ||
		!strings.Contains(got, "root login enabled") {
		t.Errorf("summary = %q", got)
	}
	if got := sshdStackValue(idle); got != "sshd: idle (ssh.socket)" {
		t.Errorf("stack = %q", got)
	}
	if got := sshdFixCommand(idle); !strings.HasSuffix(got, "try-reload-or-restart ssh") {
		t.Errorf("fix = %q", got)
	}
	running := SSHDService{Unit: "sshd", Running: true}
	if got := sshdFixCommand(running); got != "sudo sshd -t && sudo systemctl reload sshd" {
		t.Errorf("fix = %q", got)
	}
}

// TestActiveState takes the first line of is-active's output, whatever the
// exit code was.
func TestActiveState(t *testing.T) {
	for out, want := range map[string]string{
		"active\n": "active", "inactive\n": "inactive", "": "",
		"  active  ": "active",
	} {
		if got := activeState(out); got != want {
			t.Errorf("activeState(%q) = %q, want %q", out, got, want)
		}
	}
}
