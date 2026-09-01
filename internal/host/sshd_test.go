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
	if len(before.Actions) != 1 || before.Actions[0].ID != "sshd:PasswordAuthentication" {
		t.Fatalf("the sample machine offers %v", before.Actions)
	}

	plan, err := f.BuildAction(posture.ProbeSSH, before.Actions[0].ID)
	if err != nil {
		t.Fatalf("BuildAction: %v", err)
	}
	for _, cmd := range plan.Commands {
		if _, runErr := f.Run(t.Context(), cmd); runErr != nil {
			t.Fatalf("Run(%s): %v", cmd.String(), runErr)
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
