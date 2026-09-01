package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// This file holds everything tui-secure can do *to* a machine. The rule for
// what belongs here has not changed: a change is offered only when it is safe
// to preview, obvious to read and easy to undo. What has changed is the reach —
// a probe that can name what is wrong and cannot offer to fix it is a probe
// that sends the reader somewhere else for a one-line change.
//
//	ufw enable                          turn the firewall on
//	systemctl enable --now firewalld    the same, where firewalld is the one
//	systemctl enable --now nftables     the same, from /etc/nftables.conf
//	sysctl -w <key>=<value>             set one hardening key, plus its drop-in
//	systemctl enable --now <timer>      let updates apply themselves
//	sshd:<keyword>                      set one sshd keyword, checked and reloaded
//	systemctl disable --now <unit>      stop what is listening on a port
//
// Everything whose right answer depends on what the machine is for is still a
// Fix: a sentence naming the sibling tool or the command, shown but never run.

// The action kinds. A probe's Action.ID is the kind, optionally followed by a
// colon and the one argument the action takes.
const (
	ActionUfwEnable       = "ufw-enable"
	ActionFirewalldEnable = "firewalld-enable"
	ActionNftablesEnable  = "nftables-enable"
	ActionSysctl          = "sysctl"
	ActionEnableTimer     = "timer"
	ActionSSHD            = "sshd"
	ActionDisablePort     = "port"
)

// firewallUnits are the units the two firewall-enable actions start, named here
// rather than taken from the action ID: an action that can only name one of two
// constants cannot be talked into starting a third thing.
var firewallUnits = map[string]string{
	ActionFirewalldEnable: "firewalld",
	ActionNftablesEnable:  "nftables",
}

// NftablesConfigPaths are the files nftables.service loads a ruleset from, in
// the order they are looked for. Debian and Arch ship the first; Fedora's unit
// reads the second.
var NftablesConfigPaths = []string{
	"/etc/nftables.conf",
	"/etc/sysconfig/nftables.conf",
}

// NftablesConfig returns the ruleset file this machine's nftables.service would
// load, and whether it found one. Without it, enabling the service starts a
// unit that loads nothing and leaves the machine exactly as unfiltered as
// before — which looks like a fix and is not one.
func NftablesConfig() (string, bool) {
	for _, path := range NftablesConfigPaths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
}

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

// serviceRe is the shape of a systemd service name. The unit behind a listening
// socket is read off the machine rather than chosen from a table, so it is
// checked before it reaches an argv.
var serviceRe = regexp.MustCompile(`^[A-Za-z0-9@:._-]{1,64}\.service$`)

// protectedUnits are the services this tool will not offer to stop, whatever
// port they answer on. sshd is the way back into a machine that is not in front
// of you, and a posture tool that offers to close it has misunderstood its job.
var protectedUnits = map[string]bool{
	"sshd.service": true, "ssh.service": true, "sshd@.service": true,
	"sshd.socket": true, "ssh.socket": true,
}

// BuildEnableFirewall enables and starts a firewall service. Like `ufw enable`
// it is destructive in the family's sense: on a machine reached over the
// network, starting a firewall whose ruleset has no rule for ssh ends the
// session.
func BuildEnableFirewall(unit string) (posture.Command, error) {
	if unit != "firewalld" && unit != "nftables" {
		return posture.Command{}, fmt.Errorf(
			"host: %q is not a firewall this tool will start", unit)
	}
	return posture.Command{
		Argv:        []string{"systemctl", "enable", "--now", unit},
		Description: "Enable " + unit + ", now and on every boot",
		Destructive: true,
	}, nil
}

// BuildNftablesCheck asks nft to parse a ruleset file without loading it. It is
// a read, and it is why the nftables action refuses a file that would leave the
// service failing to start.
func BuildNftablesCheck(path string) (posture.Command, error) {
	if !isNftablesConfig(path) {
		return posture.Command{}, fmt.Errorf(
			"host: %q is not an nftables ruleset this tool checks", path)
	}
	return posture.Command{
		Argv:        []string{"nft", "-c", "-f", path},
		Description: "Check " + path + " without loading it",
	}, nil
}

// isNftablesConfig reports whether a path is one of the two files the service
// loads. The list is closed on purpose: nothing else reaches an `nft -f`.
func isNftablesConfig(path string) bool {
	for _, known := range NftablesConfigPaths {
		if path == known {
			return true
		}
	}
	return false
}

// BuildDisableUnit stops a service and keeps it stopped across reboots.
func BuildDisableUnit(unit string) (posture.Command, error) {
	if !serviceRe.MatchString(unit) {
		return posture.Command{}, fmt.Errorf("host: %q is not a service name", unit)
	}
	if protectedUnits[unit] {
		return posture.Command{}, fmt.Errorf(
			"host: %s is how you reach this machine, so tui-secure will not "+
				"stop it", unit)
	}
	return posture.Command{
		Argv:        []string{"systemctl", "disable", "--now", unit},
		Description: "Stop " + unit + " and keep it stopped across reboots",
		Destructive: true,
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
	kind, argument, hasArgument := strings.Cut(actionID, ":")
	switch kind {
	case ActionUfwEnable, ActionFirewalldEnable, ActionNftablesEnable:
		// These three take no argument, so one is a sign the ID did not come
		// from a probe on this machine.
		if hasArgument {
			return posture.Plan{}, fmt.Errorf(
				"host: %q takes no argument", kind)
		}
	}

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

	case ActionFirewalldEnable, ActionNftablesEnable:
		return r.firewallPlan(kind)

	case ActionSysctl:
		return r.sysctlPlan(argument)

	case ActionSSHD:
		return r.sshdPlan(argument)

	case ActionDisablePort:
		return r.portPlan(argument)
	}
	return posture.Plan{}, fmt.Errorf("host: %q offers no action %q",
		probeID, actionID)
}

// FirewallEnablePlan is the plan behind the firewalld and nftables actions,
// shared with the fake backend so --demo previews the very same commands.
//
// The nftables half refuses more than the firewalld half does, and for a
// concrete reason: firewalld ships its own default zone and starts filtering
// the moment it runs, while nftables.service is a loader for a file. Enabling
// it without that file, or with one nft will not parse, is a service that fails
// or a machine that is exactly as open as before — and both look like a fix
// from the outside.
func FirewallEnablePlan(kind, configPath, checkError string) (posture.Plan, error) {
	unit, known := firewallUnits[kind]
	if !known {
		return posture.Plan{}, fmt.Errorf("host: %q is not a firewall action", kind)
	}
	if kind == ActionNftablesEnable {
		if configPath == "" {
			return posture.Plan{}, fmt.Errorf(
				"host: nftables.service loads its ruleset from %s, and this "+
					"machine has no such file — enabling it would start a "+
					"service that filters nothing",
				strings.Join(NftablesConfigPaths, " or "))
		}
		if checkError != "" {
			return posture.Plan{}, fmt.Errorf(
				"host: nft will not parse %s, so the service would fail to "+
					"start: %s", configPath, checkError)
		}
	}

	cmd, err := BuildEnableFirewall(unit)
	if err != nil {
		return posture.Plan{}, err
	}
	body := unit + " will start filtering now and on every boot.\n" +
		"If you are connected over the network and its ruleset has no rule " +
		"for ssh, this ends the session."
	if configPath != "" {
		body += "\n\nThe ruleset it will load is " + configPath +
			", and nft has already parsed it without complaint."
	}
	return posture.Plan{
		Title:    "Enable " + unit,
		Body:     body,
		Commands: []posture.Command{cmd},
		Danger:   true,
	}, nil
}

// firewallPlan gathers what the refusal above needs from this machine, then
// builds the plan.
func (r *Real) firewallPlan(kind string) (posture.Plan, error) {
	if kind != ActionNftablesEnable {
		return FirewallEnablePlan(kind, "", "")
	}
	path, found := NftablesConfig()
	if !found {
		return FirewallEnablePlan(kind, "", "")
	}
	return FirewallEnablePlan(kind, path, r.nftablesCheckError(path))
}

// nftablesCheckError runs `nft -c -f` and returns what nft said, or "" when the
// file parsed — and also "" when the check itself could not run at all. A
// missing sudo is not evidence that the ruleset is broken, so it does not
// become a refusal; the plan goes ahead and the body stops claiming the file
// was checked.
func (r *Real) nftablesCheckError(path string) string {
	check, err := BuildNftablesCheck(path)
	if err != nil {
		return ""
	}
	out, runErr := r.Run(context.Background(), check)
	if runErr == nil {
		return ""
	}
	if trimmed := strings.TrimSpace(out); trimmed != "" {
		return runner.FirstLine(trimmed)
	}
	return ""
}

// portPlan stops whatever is listening on one port.
//
// The port is the argument, and the unit behind it is not: it is read out of
// the map the ports probe filled when it offered this action. That is what
// keeps the argv honest — an action can only name a unit that a probe on this
// machine actually attributed a listening socket to.
func (r *Real) portPlan(port string) (posture.Plan, error) {
	r.mu.Lock()
	unit, known := r.portUnits[port]
	r.mu.Unlock()
	if !known {
		return posture.Plan{}, fmt.Errorf(
			"host: nothing on port %s was traced back to a unit this tool can "+
				"stop; re-run the probe", port)
	}
	return PortDisablePlan(port, unit)
}

// PortDisablePlan is the plan behind a port action, shared with the fake
// backend.
func PortDisablePlan(port, unit string) (posture.Plan, error) {
	cmd, err := BuildDisableUnit(unit)
	if err != nil {
		return posture.Plan{}, err
	}
	return posture.Plan{
		Title: "Stop " + unit,
		// The lines are wrapped here rather than left to the dialog, which
		// shows a body as it is given.
		Body: unit + " is what answers on port " + port + ".\n\n" +
			"Stopping it closes that port and keeps it closed across reboots.\n" +
			"Anything that depends on this service stops working with it, so\n" +
			"this is a decision about what the machine is for rather than a\n" +
			"hardening default: it is only ever offered, never suggested.",
		Commands: []posture.Command{cmd},
		Danger:   true,
	}, nil
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

// sshdPlan gathers what the machine has to say about one sshd keyword and
// hands it to SSHDPlan, which decides whether the change may go ahead.
//
// Everything it reads is a file. The effective settings and the unit name come
// from the ssh probe, which has already run: an action is only ever offered by
// a probe that read this machine, so the plan is built from that same read
// rather than from a second one that might disagree with what the screen shows.
func (r *Real) sshdPlan(name string) (posture.Plan, error) {
	r.mu.Lock()
	unit, settings := r.sshdUnit, r.sshdSettingsSeen
	r.mu.Unlock()
	if unit == "" {
		unit = "sshd"
	}
	if settings == nil {
		return posture.Plan{}, fmt.Errorf(
			"host: the ssh probe has not read this machine yet, so there is " +
				"nothing to change; re-run the probe")
	}

	existing, err := os.ReadFile(SSHDDropInPath)
	if err != nil && !os.IsNotExist(err) {
		return posture.Plan{}, err
	}
	key, known := sshdKey(name)
	if !known {
		// The keyword is rejected before anything is staged, so an action ID
		// this tool does not own never leaves a file behind.
		return posture.Plan{}, fmt.Errorf(
			"host: %q is not a keyword this tool sets", name)
	}
	passwd, _ := os.ReadFile("/etc/passwd")
	names, contents := sshdDropInFiles()

	input := SSHDPlanInput{
		Key:       key.Key,
		Effective: settings,
		Existing:  string(existing),
		Unit:      unit,
		Paths:     ScanLoginPaths(string(passwd)),
		Shadow:    SSHDShadowedBy(names, contents, key.Key),
	}
	staged, err := r.stageSSHD(input)
	if err != nil {
		return posture.Plan{}, err
	}
	return SSHDPlan(input, staged)
}

// stageSSHD writes the drop-in the plan will install to a private temporary
// directory and returns its path. It renders the same content SSHDPlan will,
// which is what makes `sshd -t -f` a check of the file that gets installed
// rather than of one that looks like it.
func (r *Real) stageSSHD(in SSHDPlanInput) (string, error) {
	key, ok := sshdKey(in.Key)
	if !ok {
		return "", fmt.Errorf("host: %q is not a keyword this tool sets", in.Key)
	}
	content, err := RenderSSHDDropIn(in.Existing, key.Key, key.Want)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "tui-secure-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, SSHDDropInName)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	r.mu.Lock()
	r.staged[SSHDDropInPath] = content
	r.mu.Unlock()
	return path, nil
}

// sshdDropInFiles reads the drop-in directory sshd itself reads, so the plan
// can say whether a file sorting before this tool's already decides the
// keyword.
func sshdDropInFiles() ([]string, map[string]string) {
	entries, err := os.ReadDir(sshdDropInDir)
	if err != nil {
		return nil, nil
	}
	var names []string
	contents := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		raw, readErr := os.ReadFile( //nolint:gosec // sshd's own drop-in directory, read to warn about include order
			filepath.Join(sshdDropInDir, entry.Name()))
		if readErr != nil {
			continue
		}
		names = append(names, entry.Name())
		contents[entry.Name()] = string(raw)
	}
	return names, contents
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
