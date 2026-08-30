package host

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// This file holds everything tui-secure can do *to* a machine, which is three
// things. That is deliberate: a posture tool that also fixes everything it
// finds becomes a second configuration manager, and the family already has
// tools that own those changes. What is offered here is the set of one-liners
// that are safe to preview, obvious to read and easy to undo:
//
//	ufw enable                       turn the firewall on
//	sysctl -w <key>=<value>          set one hardening key, plus its drop-in
//	systemctl enable --now <timer>   let updates apply themselves
//
// Everything else is a Fix: a sentence naming the sibling tool or the command,
// shown but never run.

// The action kinds. A probe's Action.ID is the kind, optionally followed by a
// colon and the one argument the action takes.
const (
	ActionUfwEnable   = "ufw-enable"
	ActionSysctl      = "sysctl"
	ActionEnableTimer = "timer"
)

// DropInPath is the file a sysctl action writes, and the only path in /etc
// this tool ever creates. The 90 prefix puts it after the distribution's own
// drop-ins, so it wins.
const DropInPath = "/etc/sysctl.d/90-tui-secure.conf"

// FileMode is the mode the drop-in gets: readable by everyone, writable only
// by root, which is what systemd ships its own files with.
const FileMode = "644"

// SysctlKey is one kernel setting this tool has an opinion about.
type SysctlKey struct {
	// Key is the sysctl name.
	Key string
	// Want is the value the key should have.
	Want string
	// AtLeast reports that any value greater than or equal to Want is fine,
	// which is how the restrict-style knobs work: a stricter machine must not
	// be told it is misconfigured.
	AtLeast bool
	// Why is the one line explaining what the key buys.
	Why string
	// Fixable marks a key tui-secure offers to set. A key whose right value
	// depends on what the machine is for is left to the reader.
	Fixable bool
	// Report marks a key that is shown and never graded, because it has no
	// single right value.
	Report bool
}

// Satisfied reports whether a read value meets the recommendation.
func (k SysctlKey) Satisfied(value string) bool {
	if k.Report {
		return true
	}
	if !k.AtLeast {
		return value == k.Want
	}
	got, gotErr := strconv.Atoi(strings.TrimSpace(value))
	want, wantErr := strconv.Atoi(k.Want)
	if gotErr != nil || wantErr != nil {
		return value == k.Want
	}
	return got >= want
}

// HardeningKeys are the sysctl basics the kernel probe reads, in the order it
// shows them.
//
// The list is short on purpose. Every entry is a setting whose recommended
// value is the same on a laptop, a server and a container host — except
// net.ipv4.ip_forward, which is here because a machine that forwards packets
// when nobody meant it to is worth knowing about, and which is therefore
// reported and never offered as a fix.
var HardeningKeys = []SysctlKey{
	{Key: "kernel.kptr_restrict", Want: "1", AtLeast: true, Fixable: true,
		Why: "hides kernel pointers from unprivileged readers"},
	{Key: "kernel.dmesg_restrict", Want: "1", AtLeast: true, Fixable: true,
		Why: "keeps the kernel log away from unprivileged users"},
	{Key: "fs.protected_hardlinks", Want: "1", AtLeast: true, Fixable: true,
		Why: "stops a hardlink attack on a file you cannot read"},
	{Key: "fs.protected_symlinks", Want: "1", AtLeast: true, Fixable: true,
		Why: "stops a symlink attack in a world-writable directory"},
	{Key: "fs.protected_fifos", Want: "1", AtLeast: true, Fixable: true,
		Why: "stops a FIFO planted in a shared directory being written to"},
	{Key: "fs.protected_regular", Want: "2", AtLeast: true, Fixable: true,
		Why: "stops a regular file planted in a shared directory being written to"},
	{Key: "fs.suid_dumpable", Want: "0", Fixable: true,
		Why: "keeps a crashing setuid process from writing a core dump"},
	{Key: "net.ipv4.ip_forward", Want: "0", Fixable: false,
		Why: "1 is right for a router or a container host, and wrong everywhere else"},
	{Key: "kernel.core_pattern", Report: true,
		Why: "where a crashing process's memory is written"},
}

// hardeningKey finds a key by name.
func hardeningKey(name string) (SysctlKey, bool) {
	for _, key := range HardeningKeys {
		if key.Key == name {
			return key, true
		}
	}
	return SysctlKey{}, false
}

// sysctlKeyRe is the shape of a sysctl name. The key ends up in an argv and in
// a file, so it is validated even though it comes from this package's own
// table: the table is the only thing standing between a future caller and a
// crafted key.
var sysctlKeyRe = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_-]+)+$`)

// sysctlValueRe is the shape of a value this tool will write.
var sysctlValueRe = regexp.MustCompile(`^[0-9]+$`)

// unitRe is the shape of a systemd unit name.
var unitRe = regexp.MustCompile(`^[A-Za-z0-9@._-]+\.(timer|service)$`)

// BuildUfwEnable turns ufw on. It is destructive in the family's sense: on a
// machine reached over the network, enabling a firewall whose ssh rule is
// missing ends the session.
func BuildUfwEnable() (posture.Command, error) {
	return posture.Command{
		Argv:        []string{"ufw", "enable"},
		Description: "Enable ufw, now and on every boot",
		Destructive: true,
	}, nil
}

// BuildEnableTimer enables and starts a unit.
func BuildEnableTimer(unit string) (posture.Command, error) {
	if !unitRe.MatchString(unit) {
		return posture.Command{}, fmt.Errorf("host: %q is not a unit name", unit)
	}
	return posture.Command{
		Argv:        []string{"systemctl", "enable", "--now", unit},
		Description: "Enable and start " + unit,
	}, nil
}

// BuildSysctlSet applies one key to the running kernel.
func BuildSysctlSet(key, value string) (posture.Command, error) {
	if !sysctlKeyRe.MatchString(key) {
		return posture.Command{}, fmt.Errorf("host: %q is not a sysctl key", key)
	}
	if !sysctlValueRe.MatchString(value) {
		return posture.Command{}, fmt.Errorf(
			"host: %q is not a value this tool will set", value)
	}
	return posture.Command{
		Argv:        []string{"sysctl", "-w", key + "=" + value},
		Description: "Set " + key + " to " + value + " on the running kernel",
	}, nil
}

// BuildInstallDropIn copies a staged drop-in into /etc/sysctl.d. `install` is
// used rather than `cp` because it sets the mode in the same call, so there is
// no window where the file is on disk with the wrong permissions.
func BuildInstallDropIn(tempPath string) (posture.Command, error) {
	if strings.ContainsAny(tempPath, " \t") || !filepath.IsAbs(tempPath) {
		return posture.Command{}, fmt.Errorf(
			"host: %q is not a staged file path", tempPath)
	}
	return posture.Command{
		Argv: []string{"install", "-m", FileMode, tempPath, DropInPath},
		Description: "Install " + tempPath + " as " + DropInPath +
			", so the setting survives a reboot",
		Destructive: true,
	}, nil
}

// RenderDropIn returns the text of the drop-in with one key set.
//
// It starts from what the file holds today, so setting a second key keeps the
// first: the file belongs to this tool, and rewriting it from scratch each
// time would quietly undo the last change the user agreed to.
func RenderDropIn(existing, key, value string) (string, error) {
	if !sysctlKeyRe.MatchString(key) {
		return "", fmt.Errorf("host: %q is not a sysctl key", key)
	}
	if !sysctlValueRe.MatchString(value) {
		return "", fmt.Errorf("host: %q is not a value this tool will set", value)
	}

	type setting struct{ key, value string }
	var settings []setting
	replaced := false
	for _, line := range splitLines(existing) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") {
			continue
		}
		name, current, ok := cutKey(trimmed)
		if !ok {
			continue
		}
		if name == key {
			settings, replaced = append(settings, setting{key, value}), true
			continue
		}
		settings = append(settings, setting{name, current})
	}
	if !replaced {
		settings = append(settings, setting{key, value})
	}

	var b strings.Builder
	b.WriteString("# Written by tui-secure. Each line was previewed and confirmed.\n")
	b.WriteString("# Remove a line and run `sudo sysctl --system` to undo it.\n\n")
	for _, s := range settings {
		fmt.Fprintf(&b, "%s = %s\n", s.key, s.value)
	}
	return b.String(), nil
}

// BuildAction turns an offered action into a plan: what it is called, what it
// will do, and the exact commands that do it. Nothing here runs anything —
// the plan goes to a confirm dialog first.
func (r *Real) BuildAction(probeID, actionID string) (posture.Plan, error) {
	kind, argument, _ := strings.Cut(actionID, ":")
	switch kind {
	case ActionUfwEnable:
		cmd, err := BuildUfwEnable()
		if err != nil {
			return posture.Plan{}, err
		}
		return posture.Plan{
			Title: "Enable ufw",
			Body: "ufw will start filtering now and on every boot.\n" +
				"If you are connected over the network and ufw has no rule for " +
				"ssh, this ends the session.",
			Commands: []posture.Command{cmd},
			Danger:   true,
		}, nil

	case ActionEnableTimer:
		cmd, err := BuildEnableTimer(argument)
		if err != nil {
			return posture.Plan{}, err
		}
		return posture.Plan{
			Title: "Enable " + argument,
			Body: argument + " will be enabled and started, so updates are " +
				"applied without being asked for.",
			Commands: []posture.Command{cmd},
		}, nil

	case ActionSysctl:
		return r.sysctlPlan(argument)
	}
	return posture.Plan{}, fmt.Errorf("host: %q offers no action %q",
		probeID, actionID)
}

// sysctlPlan stages the drop-in and returns the two commands that apply one
// hardening key: the file that makes it survive a reboot, and the write that
// makes it true now.
//
// Staging first is what makes the change reviewable: the file the user
// approves is a file that already exists, and `install` copies exactly that
// one. Nothing is written to /etc until the confirmed commands run.
func (r *Real) sysctlPlan(name string) (posture.Plan, error) {
	key, ok := hardeningKey(name)
	if !ok {
		return posture.Plan{}, fmt.Errorf("host: %q is not a key this tool sets", name)
	}
	if !key.Fixable {
		return posture.Plan{}, fmt.Errorf(
			"host: %s depends on what this machine is for, so tui-secure will "+
				"not set it", key.Key)
	}

	existing, err := os.ReadFile(DropInPath)
	if err != nil && !os.IsNotExist(err) {
		return posture.Plan{}, err
	}
	content, err := RenderDropIn(string(existing), key.Key, key.Want)
	if err != nil {
		return posture.Plan{}, err
	}
	temp, err := r.stage(content)
	if err != nil {
		return posture.Plan{}, err
	}
	installCmd, err := BuildInstallDropIn(temp)
	if err != nil {
		return posture.Plan{}, err
	}
	setCmd, err := BuildSysctlSet(key.Key, key.Want)
	if err != nil {
		return posture.Plan{}, err
	}
	return posture.Plan{
		Title:    "Set " + key.Key + " to " + key.Want,
		Body:     key.Why + ".\n\n" + DropInPath + " will read:\n\n" + content,
		Commands: []posture.Command{installCmd, setCmd},
		Danger:   true,
	}, nil
}

// stage writes the pending drop-in to a private temporary directory and
// returns its path. The directory is the user's own, so staging needs no
// privileges; only the install step does.
func (r *Real) stage(content string) (string, error) {
	dir, err := os.MkdirTemp("", "tui-secure-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, filepath.Base(DropInPath))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec // the file is installed as 0644 by design
		return "", err
	}
	r.mu.Lock()
	r.staged[DropInPath] = content
	r.mu.Unlock()
	return path, nil
}
