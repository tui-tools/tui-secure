package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// TestSSHDCommandArgvIsExact pins the three command lines an sshd action runs,
// in the order it runs them. The check comes first on purpose: it is what keeps
// a file sshd refuses out of /etc.
func TestSSHDCommandArgvIsExact(t *testing.T) {
	temp := "/tmp/tui-secure-1/50-tui-secure.conf"

	validate, err := BuildSSHDValidate(temp)
	if err != nil {
		t.Fatalf("BuildSSHDValidate: %v", err)
	}
	if got, want := validate.String(), "sshd -t -f "+temp; got != want {
		t.Errorf("validate argv = %q, want %q", got, want)
	}
	if validate.Destructive {
		t.Error("parsing a file is a read, not a change")
	}

	install, err := BuildInstallSSHDDropIn(temp)
	if err != nil {
		t.Fatalf("BuildInstallSSHDDropIn: %v", err)
	}
	want := "install -m 600 " + temp + " " + SSHDDropInPath
	if got := install.String(); got != want {
		t.Errorf("install argv = %q, want %q", got, want)
	}
	if !strings.Contains(install.String(), " -m 600 ") {
		t.Error("an sshd_config drop-in must not be readable by anyone but root")
	}

	reload, err := BuildSSHDReload("ssh")
	if err != nil {
		t.Fatalf("BuildSSHDReload: %v", err)
	}
	if got := reload.String(); got != "systemctl reload ssh" {
		t.Errorf("reload argv = %q", got)
	}
}

// TestSSHDBuildersRefuseNonsense: every argument these builders take ends up in
// an argv, so each one is checked even though it comes from this package's own
// tables.
func TestSSHDBuildersRefuseNonsense(t *testing.T) {
	for _, path := range []string{"", "relative/file.conf", "/tmp/a b.conf",
		"/tmp/$(id).conf", "/tmp/a;rm -rf /.conf", "/tmp/a\nb.conf"} {
		if _, err := BuildSSHDValidate(path); err == nil {
			t.Errorf("BuildSSHDValidate(%q) was accepted", path)
		}
		if _, err := BuildInstallSSHDDropIn(path); err == nil {
			t.Errorf("BuildInstallSSHDDropIn(%q) was accepted", path)
		}
	}
	for _, unit := range []string{"", "nginx", "sshd.socket", "evil; rm -rf /",
		"../sshd", "sshd.timer", "openssh-server"} {
		if _, err := BuildSSHDReload(unit); err == nil {
			t.Errorf("BuildSSHDReload(%q) was accepted", unit)
		}
	}
	for _, unit := range []string{"sshd", "ssh", "sshd.service", "ssh.service"} {
		if _, err := BuildSSHDReload(unit); err != nil {
			t.Errorf("BuildSSHDReload(%q) was refused: %v", unit, err)
		}
	}
}

func TestRenderSSHDDropIn(t *testing.T) {
	first, err := RenderSSHDDropIn("", "PasswordAuthentication", "no")
	if err != nil {
		t.Fatalf("RenderSSHDDropIn: %v", err)
	}
	if !strings.Contains(first, "PasswordAuthentication no") {
		t.Errorf("the new file does not carry the keyword:\n%s", first)
	}
	if !strings.HasPrefix(first, "# Written by tui-secure") {
		t.Errorf("the file does not say who wrote it:\n%s", first)
	}

	// A second keyword keeps the first: the file belongs to this tool, and
	// each line in it was agreed to once.
	second, err := RenderSSHDDropIn(first, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("RenderSSHDDropIn: %v", err)
	}
	if !strings.Contains(second, "PasswordAuthentication no") ||
		!strings.Contains(second, "PermitRootLogin no") {
		t.Errorf("the second write lost the first keyword:\n%s", second)
	}

	// Setting the same keyword again replaces it rather than repeating it.
	third, err := RenderSSHDDropIn(second, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("RenderSSHDDropIn: %v", err)
	}
	if strings.Count(third, "PermitRootLogin") != 1 {
		t.Errorf("the keyword was repeated:\n%s", third)
	}

	// The whole file is regenerated from this package's table, so a keyword
	// the tool does not own is not carried forward — which is what makes the
	// preview the complete file.
	fourth, err := RenderSSHDDropIn(
		"Port 2222\nAllowUsers root\nPasswordAuthentication yes\n",
		"PasswordAuthentication", "no")
	if err != nil {
		t.Fatalf("RenderSSHDDropIn: %v", err)
	}
	if strings.Contains(fourth, "Port") || strings.Contains(fourth, "AllowUsers") {
		t.Errorf("a keyword this tool does not own survived a write:\n%s", fourth)
	}
	if !strings.Contains(fourth, "PasswordAuthentication no") {
		t.Errorf("the keyword was not updated:\n%s", fourth)
	}
}

func TestRenderSSHDDropInRefusesNonsense(t *testing.T) {
	for _, key := range []string{"", "Port", "AllowUsers", "PermitRootLogin extra",
		"Match"} {
		if _, err := RenderSSHDDropIn("", key, "no"); err == nil {
			t.Errorf("RenderSSHDDropIn(%q) was accepted", key)
		}
	}
	for _, value := range []string{"", "no\nAllowUsers root", "yes maybe",
		"$(id)", "no;reboot", strings.Repeat("n", 33)} {
		if _, err := RenderSSHDDropIn("", "PasswordAuthentication", value); err == nil {
			t.Errorf("value %q was accepted", value)
		}
	}
}

// TestSSHDKeysAreCoherent guards the table itself: every keyword must explain
// itself, and the value this tool would write must be one it is allowed to
// write and one it would not immediately flag as weak.
func TestSSHDKeysAreCoherent(t *testing.T) {
	for _, key := range SSHDKeys {
		if key.Why == "" {
			t.Errorf("%s has no explanation", key.Key)
		}
		if key.Weak == nil {
			t.Fatalf("%s cannot say when it is worth changing", key.Key)
		}
		if key.Weak(strings.ToLower(key.Want)) {
			t.Errorf("%s would flag the value it writes (%s)", key.Key, key.Want)
		}
		if _, err := RenderSSHDDropIn("", key.Key, key.Want); err != nil {
			t.Errorf("%s is offered as a fix but cannot be written: %v", key.Key, err)
		}
	}
}

// TestSSHDLockoutRefusesTheLastWayIn is the guard that matters most in this
// file: turning passwords off on a machine with no key anywhere is a machine
// nobody gets back into.
func TestSSHDLockoutRefusesTheLastWayIn(t *testing.T) {
	withKey := LoginPath{Keys: []string{"deploy"}}
	noKey := LoginPath{}
	rootOnly := LoginPath{Keys: []string{"root"}}
	blocked := LoginPath{Blocked: []string{"deploy"}}

	cases := []struct {
		name   string
		after  map[string]string
		paths  LoginPath
		refuse bool
	}{
		{"passwords off, nobody has a key", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "yes",
		}, noKey, true},
		{"passwords off, a key exists", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "yes",
		}, withKey, false},
		{"both authentication methods off", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "no",
		}, withKey, true},
		{"root has the only key and root login goes off", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "yes",
			"permitrootlogin": "no",
		}, rootOnly, true},
		{"root has the only key and may still log in", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "yes",
			"permitrootlogin": "prohibit-password",
		}, rootOnly, false},
		{"a home could not be read, so absence is not proven", map[string]string{
			"passwordauthentication": "no", "pubkeyauthentication": "yes",
		}, blocked, false},
		{"passwords stay on", map[string]string{
			"passwordauthentication": "yes", "pubkeyauthentication": "yes",
		}, noKey, false},
	}
	for _, tc := range cases {
		refusal := SSHDLockout(tc.after, tc.paths)
		if tc.refuse && refusal == "" {
			t.Errorf("%s: the change was allowed", tc.name)
		}
		if !tc.refuse && refusal != "" {
			t.Errorf("%s: the change was refused: %s", tc.name, refusal)
		}
	}
}

// TestSSHDPlanRefusesLockout: the refusal has to reach the plan, not just the
// guard, and it has to leave no commands behind when it fires.
func TestSSHDPlanRefusesLockout(t *testing.T) {
	in := SSHDPlanInput{
		Key: "PasswordAuthentication",
		Effective: map[string]string{
			"permitrootlogin": "no", "pubkeyauthentication": "yes",
			"passwordauthentication": "yes",
		},
		Unit:  "sshd",
		Paths: LoginPath{},
	}
	plan, err := SSHDPlan(in, "/tmp/tui-secure-2/50-tui-secure.conf")
	if err == nil {
		t.Fatalf("the plan was built anyway: %v", plan.Commands)
	}
	if !strings.Contains(err.Error(), "authorized key") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// The same change on a machine that has a key goes ahead.
	in.Paths = LoginPath{Keys: []string{"deploy"}}
	plan, err = SSHDPlan(in, "/tmp/tui-secure-2/50-tui-secure.conf")
	if err != nil {
		t.Fatalf("SSHDPlan: %v", err)
	}
	if len(plan.Commands) != 3 {
		t.Fatalf("built %d commands, want the check, the install and the reload",
			len(plan.Commands))
	}
	if got := plan.Commands[0].Argv[0]; got != "sshd" {
		t.Errorf("the first command is %q, want the sshd check", got)
	}
	if !plan.Danger {
		t.Error("a change to how the machine is logged into is a red dialog")
	}
	if !strings.Contains(plan.Body, "PasswordAuthentication no") {
		t.Errorf("the dialog does not show the file it will write:\n%s", plan.Body)
	}
}

// TestSSHDPlanWarnsAboutIncludeOrder: sshd takes the first value it is given,
// so a drop-in sorting before this tool's decides the keyword and the dialog
// has to say so.
func TestSSHDPlanWarnsAboutIncludeOrder(t *testing.T) {
	in := SSHDPlanInput{
		Key:       "PasswordAuthentication",
		Effective: map[string]string{"passwordauthentication": "yes"},
		Unit:      "sshd",
		Paths:     LoginPath{Keys: []string{"deploy"}},
		Shadow:    "10-cloud-init.conf",
	}
	plan, err := SSHDPlan(in, "/tmp/tui-secure-3/50-tui-secure.conf")
	if err != nil {
		t.Fatalf("SSHDPlan: %v", err)
	}
	if !strings.Contains(plan.Body, "10-cloud-init.conf") {
		t.Errorf("the dialog does not name the file that wins:\n%s", plan.Body)
	}
}

func TestSSHDShadowedBy(t *testing.T) {
	contents := map[string]string{
		"10-cloud-init.conf":  "PasswordAuthentication yes\n",
		"60-something.conf":   "PermitRootLogin yes\n",
		SSHDDropInName:        "PasswordAuthentication no\n",
		"20-unrelated.conf":   "# a comment only\n",
		"30-other-thing.conf": "Port 2222\n",
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}

	if got := SSHDShadowedBy(names, contents, "PasswordAuthentication"); got != "10-cloud-init.conf" {
		t.Errorf("shadow = %q, want 10-cloud-init.conf", got)
	}
	// A file sorting after this tool's is read second, so it does not win.
	if got := SSHDShadowedBy(names, contents, "PermitRootLogin"); got != "" {
		t.Errorf("shadow = %q, want nothing", got)
	}
	if got := SSHDShadowedBy(names, contents, "X11Forwarding"); got != "" {
		t.Errorf("shadow = %q, want nothing", got)
	}
}

func TestScanLoginPaths(t *testing.T) {
	home := t.TempDir()
	keyed := filepath.Join(home, "deploy")
	bare := filepath.Join(home, "empty")
	for _, dir := range []string{filepath.Join(keyed, ".ssh"),
		filepath.Join(bare, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	write(filepath.Join(keyed, ".ssh", "authorized_keys"),
		"# a comment\nssh-ed25519 AAAAC3Nz deploy@example\n")
	// A file with nothing but a comment is not a way in.
	write(filepath.Join(bare, ".ssh", "authorized_keys"), "# nothing here\n")

	passwd := strings.Join([]string{
		"root:x:0:0:root:" + filepath.Join(home, "root") + ":/bin/bash",
		"deploy:x:1000:1000::" + keyed + ":/bin/bash",
		"empty:x:1001:1001::" + bare + ":/bin/bash",
		// An account that cannot log in at all is not a way back in.
		"nginx:x:990:990::/var/lib/nginx:/usr/sbin/nologin",
	}, "\n")

	found := ScanLoginPaths(passwd)
	if len(found.Keys) != 1 || found.Keys[0] != "deploy" {
		t.Errorf("accounts with a key = %v, want [deploy]", found.Keys)
	}
	if len(found.Blocked) != 0 {
		t.Errorf("blocked = %v, want none", found.Blocked)
	}
}

// TestScanLoginPathsReportsWhatItCouldNotRead: an unreadable home is not an
// account without a key, and the difference decides whether a change is refused
// or only warned about.
func TestScanLoginPathsReportsWhatItCouldNotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory, so there is nothing to be blocked by")
	}
	home := t.TempDir()
	locked := filepath.Join(home, "locked")
	if err := os.MkdirAll(filepath.Join(locked, ".ssh"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(locked, ".ssh", "authorized_keys"),
		[]byte("ssh-ed25519 AAAAC3Nz locked@example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(filepath.Join(locked, ".ssh"), 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() {
		// 0700 on a directory, restored so t.TempDir can remove it again.
		_ = os.Chmod(filepath.Join(locked, ".ssh"), 0o700) //nolint:gosec // a directory the test must be able to delete
	})

	found := ScanLoginPaths("locked:x:1000:1000::" + locked + ":/bin/bash")
	if len(found.Blocked) != 1 {
		t.Fatalf("blocked = %v, want [locked]", found.Blocked)
	}
	if len(found.Keys) != 0 {
		t.Errorf("a key was reported from a directory that could not be read: %v",
			found.Keys)
	}
}

func TestParsePasswdLoginAccounts(t *testing.T) {
	accounts := ParsePasswdLoginAccounts(strings.Join([]string{
		"root:x:0:0:root:/root:/bin/bash",
		"deploy:x:1000:1000::/home/deploy:/bin/zsh",
		"nginx:x:990:990::/var/lib/nginx:/usr/sbin/nologin",
		"sync:x:5:0:sync:/sbin:/bin/sync",
		"bin:x:1:1:bin:/:/sbin/nologin",
		"truncated:x:2:2",
	}, "\n"))
	var names []string
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	want := []string{"root", "deploy", "sync"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("accounts = %v, want %v", names, want)
	}
}

// TestSSHDActionsFollowTheGrading: an action is offered exactly where the probe
// would grade the value down, and never for a keyword sshd did not report.
func TestSSHDActionsFollowTheGrading(t *testing.T) {
	actions := sshdActions(map[string]string{
		"permitrootlogin":        "prohibit-password",
		"passwordauthentication": "yes",
		"pubkeyauthentication":   "yes",
		"maxauthtries":           "10",
		"x11forwarding":          "no",
		// permitemptypasswords is deliberately absent: sshd did not say.
	})
	var ids []string
	for _, action := range actions {
		ids = append(ids, action.ID)
		if !action.Danger {
			t.Errorf("%s is not marked as a change worth a red dialog", action.ID)
		}
	}
	want := []string{"sshd:PermitRootLogin", "sshd:PasswordAuthentication",
		"sshd:MaxAuthTries"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("actions = %v, want %v", ids, want)
	}

	if offered := sshdActions(map[string]string{
		"permitrootlogin": "no", "passwordauthentication": "no",
		"pubkeyauthentication": "yes", "maxauthtries": "4",
		"x11forwarding": "no", "permitemptypasswords": "no",
	}); len(offered) != 0 {
		t.Errorf("a hardened machine was offered %v", offered)
	}
}

// TestFakeAppliesTheSSHDChange: --demo has to move the way the machine would,
// or the preview is a promise about something nobody watched happen.
func TestFakeAppliesTheSSHDChange(t *testing.T) {
	f := NewFake()
	before, err := f.Reload(t.Context(), posture.ProbeSSH)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// The sample machine takes passwords and allows six guesses per
	// connection, which is the shape a stock sshd has.
	var ids []string
	for _, action := range before.Actions {
		ids = append(ids, action.ID)
	}
	want := []string{"sshd:PasswordAuthentication", "sshd:MaxAuthTries"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("the sample machine offers %v, want %v", ids, want)
	}

	for _, action := range before.Actions {
		plan, planErr := f.BuildAction(posture.ProbeSSH, action.ID)
		if planErr != nil {
			t.Fatalf("BuildAction(%s): %v", action.ID, planErr)
		}
		for _, cmd := range plan.Commands {
			if _, runErr := f.Run(t.Context(), cmd); runErr != nil {
				t.Fatalf("Run(%s): %v", cmd.String(), runErr)
			}
		}
	}

	after, err := f.Reload(t.Context(), posture.ProbeSSH)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if after.Status != posture.StatusOK {
		t.Errorf("the row is still %s after the change", after.Status)
	}
	if len(after.Actions) != 0 {
		t.Errorf("the fix is still offered: %v", after.Actions)
	}
}

// TestSSHDGradeMatchesWeak is the promise the two halves of an SSHDKey make to
// each other: a value the screen paints as a weakness is a value the a key
// offers to change, and nothing else is. Break it and the row says
// "MaxAuthTries 6, each connection may guess 6 times" over a fix column
// pointing at a tool that does not exist yet.
func TestSSHDGradeMatchesWeak(t *testing.T) {
	corpus := map[string][]string{
		"PermitRootLogin": {"yes", "no", "prohibit-password",
			"without-password", "forced-commands-only"},
		"PasswordAuthentication": {"yes", "no"},
		"PermitEmptyPasswords":   {"yes", "no"},
		"PubkeyAuthentication":   {"yes", "no"},
		"MaxAuthTries":           {"1", "3", "4", "5", "6", "10"},
		"X11Forwarding":          {"yes", "no"},
	}
	if len(corpus) != len(SSHDKeys) {
		t.Fatalf("the corpus covers %d keywords, the table has %d",
			len(corpus), len(SSHDKeys))
	}

	for _, key := range SSHDKeys {
		values, covered := corpus[key.Key]
		if !covered {
			t.Fatalf("%s has no values to grade", key.Key)
		}
		for _, value := range values {
			status, note := key.Grade(value)
			flagged := status == posture.StatusWarn || status == posture.StatusBad
			if flagged != key.Weak(strings.ToLower(value)) {
				t.Errorf("%s %s: graded %s but Weak reports %v",
					key.Key, value, status, key.Weak(strings.ToLower(value)))
			}
			if flagged && note == "" {
				t.Errorf("%s %s: flagged with no note", key.Key, value)
			}
		}
		// The value this tool writes is never a weakness itself, or the fix
		// would be offered again the moment it is applied.
		if key.Weak(strings.ToLower(key.Want)) {
			t.Errorf("%s: the value it writes, %s, is one it would change",
				key.Key, key.Want)
		}
		if status, _ := key.Grade(""); status != posture.StatusUnknown {
			t.Errorf("%s: an unreported keyword graded %s, want unknown",
				key.Key, status)
		}
	}
}

// TestSSHDActionForEveryWeakKeyword walks a stock sshd — the one the probe
// meets on a machine nobody has hardened — and asks for a fix per weak row.
func TestSSHDActionForEveryWeakKeyword(t *testing.T) {
	stock := map[string]string{
		"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
		"permitemptypasswords": "no", "pubkeyauthentication": "yes",
		"maxauthtries": "6", "x11forwarding": "yes",
	}
	offered := map[string]bool{}
	for _, action := range sshdActions(stock) {
		offered[strings.TrimPrefix(action.ID, ActionSSHD+":")] = true
	}

	for _, key := range SSHDKeys {
		status, _ := key.Grade(stock[strings.ToLower(key.Key)])
		flagged := status == posture.StatusWarn || status == posture.StatusBad
		if flagged != offered[key.Key] {
			t.Errorf("%s: graded %s, offered as a fix: %v",
				key.Key, status, offered[key.Key])
		}
	}
	if want := 4; len(offered) != want {
		t.Errorf("a stock sshd was offered %d fixes, want %d", len(offered), want)
	}
}

// TestRealAppliesTheSSHDChange runs the whole sshd fix against the machine the
// test is on: probe it, take the action the probe offered, run the three
// commands the plan built, and probe again. MaxAuthTries is the keyword it
// drives because it is the one a stock sshd leaves at 6 and no distribution
// pins in a drop-in of its own.
//
// It changes /etc/ssh/sshd_config.d, so it only runs as root and only when
// asked for by name — TUI_SECURE_ROOT_LAB=1 in a throwaway container. CI skips
// it; it is here so the flow the screen drives can be exercised without a
// human at the keyboard.
func TestRealAppliesTheSSHDChange(t *testing.T) {
	if os.Getenv("TUI_SECURE_ROOT_LAB") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root on a throwaway machine: TUI_SECURE_ROOT_LAB=1")
	}
	r, err := NewReal(nil)
	if err != nil {
		t.Fatalf("NewReal: %v", err)
	}

	before, err := r.Reload(t.Context(), posture.ProbeSSH)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if before.Fix.Tool != "" {
		t.Errorf("a machine with %d fix(es) of its own says the job belongs "+
			"to %q", len(before.Actions), before.Fix.Tool)
	}
	target := ActionSSHD + ":MaxAuthTries"
	offered := false
	for _, action := range before.Actions {
		if action.ID == target {
			offered = true
		}
	}
	if !offered {
		t.Fatalf("MaxAuthTries was not offered; the probe offers %v",
			before.Actions)
	}

	plan, err := r.BuildAction(posture.ProbeSSH, target)
	if err != nil {
		t.Fatalf("BuildAction: %v", err)
	}
	if len(plan.Commands) != 3 {
		t.Fatalf("the plan runs %d command(s): %v", len(plan.Commands), plan.Commands)
	}
	for _, cmd := range plan.Commands {
		if out, runErr := r.Run(t.Context(), cmd); runErr != nil {
			t.Fatalf("Run(%s): %v\n%s", cmd.String(), runErr, out)
		}
	}

	after, err := r.Reload(t.Context(), posture.ProbeSSH)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	for _, action := range after.Actions {
		if action.ID == target {
			t.Errorf("MaxAuthTries is still offered after the change")
		}
	}
	for _, finding := range after.Findings {
		if finding.Label == "MaxAuthTries" && finding.Value != "4" {
			t.Errorf("MaxAuthTries = %q after the change", finding.Value)
		}
	}
}

// TestRealNamesTheDropInThatShadowsIt: on a distribution that pins a keyword
// in a drop-in sorting before this tool's, the file this tool writes would be
// read and ignored — sshd keeps the first value it is given. The plan has to
// say so before it is confirmed, and it says which file to edit instead.
//
// Fedora's 50-redhat.conf sets X11Forwarding, which is what makes this
// runnable in the same container as the test above.
func TestRealNamesTheDropInThatShadowsIt(t *testing.T) {
	if os.Getenv("TUI_SECURE_ROOT_LAB") != "1" || os.Geteuid() != 0 {
		t.Skip("needs root on a throwaway machine: TUI_SECURE_ROOT_LAB=1")
	}
	names, contents := sshdDropInFiles()
	shadow := SSHDShadowedBy(names, contents, "X11Forwarding")
	if shadow == "" {
		t.Skip("nothing on this machine shadows X11Forwarding")
	}

	r, err := NewReal(nil)
	if err != nil {
		t.Fatalf("NewReal: %v", err)
	}
	if _, err = r.Reload(t.Context(), posture.ProbeSSH); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	plan, err := r.BuildAction(posture.ProbeSSH, ActionSSHD+":X11Forwarding")
	if err != nil {
		t.Fatalf("BuildAction: %v", err)
	}
	if !strings.Contains(plan.Body, shadow) {
		t.Errorf("the plan does not name %s:\n%s", shadow, plan.Body)
	}
	if !strings.Contains(plan.Body, "read and ignored") {
		t.Errorf("the plan does not say the file would be ignored:\n%s", plan.Body)
	}
}
