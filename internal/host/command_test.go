package host

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// TestCommandArgvIsExact pins the command lines the firewall, timer and sysctl
// actions run. They are part of the whole of what tui-secure does to a machine
// — the sshd and unit ones are pinned next door — so a change to any of them
// should be a change to this test as well.
func TestCommandArgvIsExact(t *testing.T) {
	ufw, err := BuildUfwEnable()
	if err != nil {
		t.Fatalf("BuildUfwEnable: %v", err)
	}
	if got := ufw.String(); got != "ufw enable" {
		t.Errorf("ufw argv = %q", got)
	}
	if !ufw.Destructive {
		t.Error("enabling a firewall over the network can end the session")
	}

	timer, err := BuildEnableTimer("dnf-automatic.timer")
	if err != nil {
		t.Fatalf("BuildEnableTimer: %v", err)
	}
	if got := timer.String(); got != "systemctl enable --now dnf-automatic.timer" {
		t.Errorf("timer argv = %q", got)
	}

	set, err := BuildSysctlSet("kernel.kptr_restrict", "1")
	if err != nil {
		t.Fatalf("BuildSysctlSet: %v", err)
	}
	if got := set.String(); got != "sysctl -w kernel.kptr_restrict=1" {
		t.Errorf("sysctl argv = %q", got)
	}

	install, err := BuildInstallDropIn("/tmp/tui-secure-1/90-tui-secure.conf")
	if err != nil {
		t.Fatalf("BuildInstallDropIn: %v", err)
	}
	want := "install -m 644 /tmp/tui-secure-1/90-tui-secure.conf " + DropInPath
	if got := install.String(); got != want {
		t.Errorf("install argv = %q, want %q", got, want)
	}
}

// TestBuildersRefuseNonsense: the arguments come from this package's own
// tables today, and the validation is what keeps that true tomorrow.
func TestBuildersRefuseNonsense(t *testing.T) {
	for _, unit := range []string{"", "nginx", "evil; rm -rf /", "../timer",
		"foo.socket"} {
		if _, err := BuildEnableTimer(unit); err == nil {
			t.Errorf("BuildEnableTimer(%q) was accepted", unit)
		}
	}
	for _, key := range []string{"", "kernel.kptr restrict", "Kernel.Foo",
		"kernel", "kernel.$(id)"} {
		if _, err := BuildSysctlSet(key, "1"); err == nil {
			t.Errorf("BuildSysctlSet(%q) was accepted", key)
		}
	}
	for _, value := range []string{"", "yes", "1 2", "-1"} {
		if _, err := BuildSysctlSet("kernel.kptr_restrict", value); err == nil {
			t.Errorf("value %q was accepted", value)
		}
	}
	for _, path := range []string{"relative/file.conf", "/tmp/a b.conf"} {
		if _, err := BuildInstallDropIn(path); err == nil {
			t.Errorf("BuildInstallDropIn(%q) was accepted", path)
		}
	}
}

func TestRenderDropIn(t *testing.T) {
	first, err := RenderDropIn("", "kernel.kptr_restrict", "1")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if !strings.Contains(first, "kernel.kptr_restrict = 1") {
		t.Errorf("the new file does not carry the setting:\n%s", first)
	}
	if !strings.HasPrefix(first, "# Written by tui-secure") {
		t.Errorf("the file does not say who wrote it:\n%s", first)
	}

	// A second key keeps the first: the file belongs to this tool, and each
	// line in it was agreed to once.
	second, err := RenderDropIn(first, "fs.protected_regular", "2")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if !strings.Contains(second, "kernel.kptr_restrict = 1") ||
		!strings.Contains(second, "fs.protected_regular = 2") {
		t.Errorf("the second write lost the first setting:\n%s", second)
	}

	// Setting the same key again replaces it rather than repeating it.
	third, err := RenderDropIn(second, "kernel.kptr_restrict", "2")
	if err != nil {
		t.Fatalf("RenderDropIn: %v", err)
	}
	if strings.Count(third, "kernel.kptr_restrict") != 1 {
		t.Errorf("the key was repeated:\n%s", third)
	}
	if !strings.Contains(third, "kernel.kptr_restrict = 2") {
		t.Errorf("the key was not updated:\n%s", third)
	}
}

func TestSysctlKeySatisfied(t *testing.T) {
	restrict := SysctlKey{Key: "kernel.kptr_restrict", Want: "1", AtLeast: true}
	if restrict.Satisfied("0") {
		t.Error("0 does not meet a minimum of 1")
	}
	// A machine stricter than the recommendation is not misconfigured.
	if !restrict.Satisfied("2") {
		t.Error("2 meets a minimum of 1")
	}

	dumpable := SysctlKey{Key: "fs.suid_dumpable", Want: "0"}
	if dumpable.Satisfied("2") || !dumpable.Satisfied("0") {
		t.Error("an exact key must match exactly")
	}

	pattern := SysctlKey{Key: "kernel.core_pattern", Report: true}
	if !pattern.Satisfied("|/usr/lib/systemd/systemd-coredump") {
		t.Error("a reported key is never graded")
	}
}

// TestHardeningKeysAreCoherent guards the table itself: every fixable key must
// have a value this tool is allowed to write, and every key must explain
// itself.
func TestHardeningKeysAreCoherent(t *testing.T) {
	for _, key := range HardeningKeys {
		if key.Why == "" {
			t.Errorf("%s has no explanation", key.Key)
		}
		if !sysctlKeyRe.MatchString(key.Key) {
			t.Errorf("%s is not a valid sysctl name", key.Key)
		}
		if !key.Fixable {
			continue
		}
		if _, err := BuildSysctlSet(key.Key, key.Want); err != nil {
			t.Errorf("%s is offered as a fix but cannot be built: %v", key.Key, err)
		}
	}
}

// TestBuildActionRefusesWhatIsNotOffered: an action ID that no probe produced
// must not reach a command builder.
func TestBuildActionRefusesWhatIsNotOffered(t *testing.T) {
	backend := NewFake()
	for _, id := range []string{"", "nonsense", "sysctl:net.ipv4.ip_forward",
		"timer:evil.socket", "sysctl:kernel.made_up", "sshd", "sshd:",
		"sshd:Port", "sshd:AllowUsers", "sshd:PermitRootLogin extra",
		"firewalld-enable:evil", "port:evil", "ufw-enable:nonsense"} {
		if _, err := backend.BuildAction(posture.ProbeKernel, id); err == nil {
			t.Errorf("BuildAction(%q) was accepted", id)
		}
	}
}

// TestHardeningSummaryCountsTheFixesItOffers is the bug the kernel row had: it
// said "4 keys below the recommended value" while the picker held three,
// because net.ipv4.ip_forward is graded and never offered. The number in the
// line and the number of fixes behind the a key are now the same count.
func TestHardeningSummaryCountsTheFixesItOffers(t *testing.T) {
	// A machine with three fixable keys wrong and ip_forward on, which is the
	// shape a container host or a router has.
	values := map[string]string{
		"kernel.kptr_restrict":   "0",
		"kernel.dmesg_restrict":  "1",
		"fs.protected_hardlinks": "1",
		"fs.protected_symlinks":  "1",
		"fs.protected_fifos":     "1",
		"fs.protected_regular":   "1",
		"fs.suid_dumpable":       "2",
		"net.ipv4.ip_forward":    "1",
		"kernel.core_pattern":    "|/usr/lib/systemd/systemd-coredump",
	}

	grade := GradeHardening(values, nil)
	if len(grade.Actions) != 3 {
		t.Fatalf("offers %d fix(es): %v", len(grade.Actions), grade.Actions)
	}
	if len(grade.Weak) != 4 {
		t.Fatalf("graded %d key(s) weak: %v", len(grade.Weak), grade.Weak)
	}
	if !strings.HasPrefix(grade.Summary, "3 hardening key(s) below") {
		t.Errorf("summary = %q, want it to count the 3 fixes it offers",
			grade.Summary)
	}
	if !strings.Contains(grade.Summary, "1 worth a look this tool leaves alone") {
		t.Errorf("summary = %q, want it to say ip_forward is not one of them",
			grade.Summary)
	}
	if grade.Status != posture.StatusWarn {
		t.Errorf("status = %s, want warn", grade.Status)
	}
}

// TestHardeningSummaryStopsCountingWhenNothingIsWrong covers the two ends: a
// machine with nothing to fix, and one whose only finding is the key this tool
// reports and never sets.
func TestHardeningSummaryStopsCountingWhenNothingIsWrong(t *testing.T) {
	values := map[string]string{}
	for _, key := range HardeningKeys {
		values[key.Key] = key.Want
	}
	values["kernel.core_pattern"] = "|/usr/lib/systemd/systemd-coredump"

	grade := GradeHardening(values, nil)
	if grade.Summary != "the hardening basics are set" {
		t.Errorf("summary = %q", grade.Summary)
	}
	if len(grade.Actions) != 0 || grade.Status != posture.StatusOK {
		t.Errorf("a hardened machine got %v / %s", grade.Actions, grade.Status)
	}

	values["net.ipv4.ip_forward"] = "1"
	grade = GradeHardening(values, nil)
	if len(grade.Actions) != 0 {
		t.Errorf("ip_forward was offered as a fix: %v", grade.Actions)
	}
	if !strings.Contains(grade.Summary, "1 key(s) worth a look") {
		t.Errorf("summary = %q", grade.Summary)
	}
}

// TestHardeningUnknownKeyIsNotCounted: a key the read could not answer is a
// row saying so, not a weakness and not a fix.
func TestHardeningUnknownKeyIsNotCounted(t *testing.T) {
	grade := GradeHardening(map[string]string{},
		map[string]string{"kernel.kptr_restrict": "sysctl: not found"})
	if len(grade.Actions) != 0 || len(grade.Weak) != 0 {
		t.Fatalf("an unread machine offered %v", grade.Actions)
	}
	if grade.Status != posture.StatusUnknown {
		t.Errorf("status = %s, want unknown", grade.Status)
	}
	if grade.Findings[0].Note != "sysctl: not found" {
		t.Errorf("the reason was dropped: %q", grade.Findings[0].Note)
	}
	if want := "9 hardening key(s) could not be read"; grade.Summary != want {
		t.Errorf("summary = %q, want %q", grade.Summary, want)
	}
}
