package host

import (
	"errors"
	"strings"
	"testing"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// TestFirewallEnableArgvIsExact pins the two commands that turn on the
// firewalls ufw is not.
func TestFirewallEnableArgvIsExact(t *testing.T) {
	for unit, want := range map[string]string{
		"firewalld": "systemctl enable --now firewalld",
		"nftables":  "systemctl enable --now nftables",
	} {
		cmd, err := BuildEnableFirewall(unit)
		if err != nil {
			t.Fatalf("BuildEnableFirewall(%q): %v", unit, err)
		}
		if got := cmd.String(); got != want {
			t.Errorf("argv = %q, want %q", got, want)
		}
		if !cmd.Destructive {
			t.Errorf("%s: starting a firewall over the network can end the session",
				unit)
		}
	}
	for _, unit := range []string{"", "nginx", "firewalld.service",
		"firewalld; rm -rf /", "ufw"} {
		if _, err := BuildEnableFirewall(unit); err == nil {
			t.Errorf("BuildEnableFirewall(%q) was accepted", unit)
		}
	}
}

// TestFirewalldPlanSaysWhatUfwSays: the same change deserves the same warning,
// whichever firewall the machine happens to ship.
func TestFirewalldPlanSaysWhatUfwSays(t *testing.T) {
	plan, err := FirewallEnablePlan(ActionFirewalldEnable, "", "")
	if err != nil {
		t.Fatalf("FirewallEnablePlan: %v", err)
	}
	if !plan.Danger {
		t.Error("enabling a firewall is a red dialog")
	}
	if !strings.Contains(plan.Body, "ssh") {
		t.Errorf("the dialog does not warn about the session:\n%s", plan.Body)
	}
	if len(plan.Commands) != 1 {
		t.Fatalf("built %d commands, want one", len(plan.Commands))
	}
}

// TestNftablesPlanRefusesWithoutARuleset: nftables.service is a loader for a
// file. Starting it without one is a machine as open as it was, wearing a
// green row.
func TestNftablesPlanRefusesWithoutARuleset(t *testing.T) {
	if _, err := FirewallEnablePlan(ActionNftablesEnable, "", ""); err == nil {
		t.Fatal("enabling nftables with no ruleset file was accepted")
	}

	_, err := FirewallEnablePlan(ActionNftablesEnable, "/etc/nftables.conf",
		"/etc/nftables.conf:4:1-5: Error: syntax error")
	if err == nil {
		t.Fatal("a ruleset nft will not parse was accepted")
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("the refusal does not carry what nft said: %v", err)
	}

	plan, err := FirewallEnablePlan(ActionNftablesEnable, "/etc/nftables.conf", "")
	if err != nil {
		t.Fatalf("FirewallEnablePlan: %v", err)
	}
	if !strings.Contains(plan.Body, "/etc/nftables.conf") {
		t.Errorf("the dialog does not name the ruleset:\n%s", plan.Body)
	}
}

func TestBuildNftablesCheck(t *testing.T) {
	cmd, err := BuildNftablesCheck("/etc/nftables.conf")
	if err != nil {
		t.Fatalf("BuildNftablesCheck: %v", err)
	}
	if got := cmd.String(); got != "nft -c -f /etc/nftables.conf" {
		t.Errorf("argv = %q", got)
	}
	if cmd.Destructive {
		t.Error("parsing a file without loading it is a read")
	}
	// The list of files this tool will hand to nft is closed, so nothing else
	// reaches an `nft -f`.
	for _, path := range []string{"", "/tmp/evil.conf", "/etc/nftables.conf ",
		"../etc/nftables.conf", "/etc/nftables.conf;reboot"} {
		if _, err := BuildNftablesCheck(path); err == nil {
			t.Errorf("BuildNftablesCheck(%q) was accepted", path)
		}
	}
}

// TestBuildDisableUnitProtectsTheWayIn: a posture tool that offers to stop the
// ssh server has misunderstood its job.
func TestBuildDisableUnitProtectsTheWayIn(t *testing.T) {
	cmd, err := BuildDisableUnit("nginx.service")
	if err != nil {
		t.Fatalf("BuildDisableUnit: %v", err)
	}
	if got := cmd.String(); got != "systemctl disable --now nginx.service" {
		t.Errorf("argv = %q", got)
	}
	if !cmd.Destructive {
		t.Error("stopping a service is a change worth a red dialog")
	}

	for _, unit := range []string{"sshd.service", "ssh.service", "sshd.socket"} {
		if _, err := BuildDisableUnit(unit); err == nil {
			t.Errorf("BuildDisableUnit(%q) was accepted", unit)
		}
	}
	for _, unit := range []string{"", "nginx", "nginx.timer", "nginx.socket",
		"evil; rm -rf /.service", "../nginx.service", "nginx service.service"} {
		if _, err := BuildDisableUnit(unit); err == nil {
			t.Errorf("BuildDisableUnit(%q) was accepted", unit)
		}
	}
}

func TestParseCgroupUnit(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/nginx.service\n":                       "nginx.service",
		"0::/system.slice/system-getty.slice/getty@tty1.service": "getty@tty1.service",
		"12:name=systemd:/system.slice/postgresql.service\n" +
			"11:memory:/system.slice/postgresql.service\n": "postgresql.service",
		// A user's own session is not a service this tool would offer to stop.
		"0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service": "",
		"0::/system.slice/docker-abc.scope":                                      "",
		"0::/":                                                                   "",
		"":                                                                       "",
		"nonsense":                                                               "",
	}
	for text, want := range cases {
		if got := ParseCgroupUnit(text); got != want {
			t.Errorf("ParseCgroupUnit(%q) = %q, want %q", text, got, want)
		}
	}
}

// TestPortActionNamesTheUnitTheProbeFound: the port is the action's argument
// and the unit is not, so a plan can only ever name a unit a probe on this
// machine actually attributed a socket to.
func TestPortActionNamesTheUnitTheProbeFound(t *testing.T) {
	f := NewFake()
	ports, err := f.Reload(t.Context(), posture.ProbePorts)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(ports.Actions) != 1 || ports.Actions[0].ID != "port:80" {
		t.Fatalf("the sample machine offers %v", ports.Actions)
	}
	// Port 22 is sshd's, and it is never offered.
	for _, action := range ports.Actions {
		if strings.Contains(action.Label, "sshd") {
			t.Errorf("stopping the ssh server was offered: %s", action.Label)
		}
	}

	plan, err := f.BuildAction(posture.ProbePorts, "port:80")
	if err != nil {
		t.Fatalf("BuildAction: %v", err)
	}
	if len(plan.Commands) != 1 ||
		plan.Commands[0].String() != "systemctl disable --now nginx.service" {
		t.Fatalf("plan runs %v", plan.Commands)
	}

	// A port nothing was traced to is refused rather than guessed at.
	if _, err := f.BuildAction(posture.ProbePorts, "port:22"); err == nil {
		t.Error("stopping whatever answers on 22 was accepted")
	}
	for _, id := range []string{"port:", "port:nonsense", "port:5432"} {
		if _, err := f.BuildAction(posture.ProbePorts, id); err == nil {
			t.Errorf("BuildAction(%q) was accepted", id)
		}
	}
}

// TestFakeAppliesThePortChange: --demo has to move the way the machine would.
func TestFakeAppliesThePortChange(t *testing.T) {
	f := NewFake()
	plan, err := f.BuildAction(posture.ProbePorts, "port:80")
	if err != nil {
		t.Fatalf("BuildAction: %v", err)
	}
	for _, cmd := range plan.Commands {
		if _, runErr := f.Run(t.Context(), cmd); runErr != nil {
			t.Fatalf("Run(%s): %v", cmd.String(), runErr)
		}
	}
	after, err := f.Reload(t.Context(), posture.ProbePorts)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if strings.Contains(after.Raw, "nginx") {
		t.Errorf("the sample machine still answers on 80:\n%s", after.Raw)
	}
	if len(after.Actions) != 0 {
		t.Errorf("the fix is still offered: %v", after.Actions)
	}
}

// TestFirewalldStateOverSSH: on Fedora 44, an ordinary user over SSH gets
// polkit's refusal from `firewall-cmd --state` (exit 253), not an answer. Seen
// on a lab machine whose firewalld had been running since boot: the probe read
// the refusal as "not running", scored it bad and offered to start it. The
// refusal now sends the read through sudo -n, and when that is refused too,
// systemd's view of the unit decides.
func TestFirewalldStateOverSSH(t *testing.T) {
	refused := fixture(t, "firewall-cmd-state-refused-fedora44.txt")
	errRefused := errors.New("exit status 253")
	errSudo := errors.New("sudo: a password is required")

	for _, tc := range []struct {
		name      string
		plain     string
		plainErr  error
		escalated string
		escErr    error
		active    string
		want      string
		wantNote  bool
		wantErr   bool
	}{
		{name: "answered as the user", plain: "running", want: "running"},
		// firewall-cmd exits 252 when firewalld is down; the error rides along
		// with the answer, which the probe reads first.
		{name: "not running, as the user", plain: "not running",
			plainErr: errors.New("exit status 252"), want: "not running", wantErr: true},
		{name: "refused, answered through sudo", plain: refused, plainErr: errRefused,
			escalated: "running", want: "running"},
		{name: "refused twice, the unit is active", plain: refused, plainErr: errRefused,
			escalated: "", escErr: errSudo, active: "active", want: "running", wantNote: true},
		{name: "refused twice, the unit is inactive", plain: refused, plainErr: errRefused,
			escalated: "", escErr: errSudo, active: "inactive", want: "not running"},
		{name: "refused, and nothing else answers", plain: refused, plainErr: errRefused,
			escErr: errSudo, want: "", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(escalate bool) (string, string, error) {
				if escalate {
					return tc.escalated, "sudo -n firewall-cmd --state", tc.escErr
				}
				return tc.plain, "firewall-cmd --state", tc.plainErr
			}
			active := func() (string, string, error) {
				return tc.active, "systemctl is-active firewalld", nil
			}
			state, _, note, err := firewalldState(read, active)
			if state != tc.want {
				t.Errorf("state = %q, want %q", state, tc.want)
			}
			if (note != "") != tc.wantNote {
				t.Errorf("note = %q", note)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v", err)
			}
		})
	}

	if !firewalldRefused(refused) || firewalldRefused("running") ||
		firewalldRefused("not running") {
		t.Error("firewalldRefused does not tell the refusal from an answer")
	}
}

// TestFirewalldReadEscalatesOnlyOnRefusal: the zone reads go through sudo -n
// only when polkit refused them, and a refusal is never returned as output.
func TestFirewalldReadEscalatesOnlyOnRefusal(t *testing.T) {
	refused := fixture(t, "firewall-cmd-state-refused-fedora44.txt")
	var escalations int
	read := func(escalate bool, _ ...string) (string, string, error) {
		if escalate {
			escalations++
			return "public", "sudo -n firewall-cmd --get-default-zone", nil
		}
		return refused, "firewall-cmd --get-default-zone", errors.New("exit status 253")
	}
	out, _, err := firewalldRead(read, "--get-default-zone")
	if err != nil || out != "public" || escalations != 1 {
		t.Errorf("out = %q, err = %v, escalations = %d", out, err, escalations)
	}

	plain := func(escalate bool, _ ...string) (string, string, error) {
		if escalate {
			t.Error("an answered read was escalated")
		}
		return "public", "firewall-cmd --get-default-zone", nil
	}
	if out, _, err := firewalldRead(plain, "--get-default-zone"); err != nil || out != "public" {
		t.Errorf("out = %q, err = %v", out, err)
	}
}
