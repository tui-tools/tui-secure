package host

import (
	"context"
	"fmt"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// Fake is an in-memory machine. It backs --demo and the tests: every key
// works, every command is built and previewed exactly as the real backend
// builds it, and nothing reaches the system.
//
// The commands are recorded rather than run, and a hook applies to the
// in-memory machine the change the real command would have made — so enabling
// the update timer in --demo really does turn that row green, and the argv the
// confirm dialog displayed is the argv a test can assert on.
type Fake struct {
	state demoState
	run   *runner.Fake
	// staged is the drop-in a sysctl action rendered, keyed by destination.
	// --demo writes no file at all, so the "staging directory" is this map.
	staged map[string]string
}

// demoState is everything about the sample machine that a confirmed action can
// change. The report is rendered from it on every read, so the screen and the
// commands cannot drift apart.
type demoState struct {
	kptrRestrict string
	timerEnabled bool
	ufwActive    bool
	// passwordAuth is the sample sshd's PasswordAuthentication, which the sshd
	// action turns off.
	passwordAuth string
	// nginxRunning is whether the sample machine still answers on port 80,
	// which the port action stops.
	nginxRunning bool
}

// demoTimer is the unattended update unit the sample machine has.
const demoTimer = "omarchy-server-update.timer"

// demoUnits maps the sample machine's listening processes onto the units they
// belong to. On a real machine this comes out of /proc/<pid>/cgroup; here it is
// written down, because the demo has no processes.
var demoUnits = map[string]string{
	"901":  "sshd.service",
	"1841": "nginx.service",
}

// demoLoginPaths is the sample machine's answer to "is there a key to log in
// with", which is what keeps the sshd action from refusing itself in --demo.
var demoLoginPaths = LoginPath{Keys: []string{"demo"}}

// NewFake builds the sample machine: Secure Boot on, SELinux enforcing with a
// few denials, ufw active, an sshd that still takes passwords, a dozen pending
// updates with a reboot owed, a second root account, one kernel hardening key
// left at zero, and two sockets on the network.
func NewFake() *Fake {
	f := &Fake{
		state: demoState{
			kptrRestrict: "0", timerEnabled: false, ufwActive: true,
			passwordAuth: "yes", nginxRunning: true,
		},
		staged: map[string]string{},
	}
	f.run = &runner.Fake{Prefix: "sudo -n", Hook: f.apply}
	return f
}

// Name identifies the backend. It is the real backend's name, because --demo
// shows what the real one would show.
func (f *Fake) Name() string { return "host" }

// Describe says plainly that nothing here is real.
func (f *Fake) Describe() string { return "demo (in-memory sample machine)" }

// Preview renders the command line the real backend would run.
func (f *Fake) Preview(cmd posture.Command) string { return f.run.Preview(cmd) }

// Run records the command and applies its effect to the sample machine.
func (f *Fake) Run(ctx context.Context, cmd posture.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Ran exposes the recorded commands, which is what a test asserts on.
func (f *Fake) Ran() []posture.Command { return f.run.Ran }

// apply is the hook the fake runner calls: it makes to the sample machine the
// change the real command would have made, so the demo stays coherent as keys
// are pressed.
func (f *Fake) apply(cmd posture.Command) (string, error) {
	argv := cmd.Argv
	if len(argv) < 2 {
		return "", nil
	}
	switch argv[0] + " " + argv[1] {
	case "ufw enable":
		f.state.ufwActive = true
		return "Firewall is active and enabled on system startup", nil
	case "systemctl enable":
		if len(argv) > 3 && argv[3] == demoTimer {
			f.state.timerEnabled = true
			return "Created symlink /etc/systemd/system/timers.target.wants/" +
				demoTimer, nil
		}
		return "", nil
	case "systemctl disable":
		if len(argv) > 3 && argv[3] == "nginx.service" {
			f.state.nginxRunning = false
			return "Removed /etc/systemd/system/multi-user.target.wants/nginx.service", nil
		}
		return "", nil
	case "systemctl reload":
		// The reload is what makes an installed sshd drop-in true, so this is
		// where the sample machine picks the new keywords up.
		f.applySSHDDropIn()
		return "", nil
	case "sshd -t":
		return "", nil
	case "sysctl -w":
		if len(argv) > 2 {
			if _, value, ok := cutKey(argv[2]); ok {
				f.state.kptrRestrict = value
			}
		}
		return argv[2], nil
	case "install -m":
		return "", nil
	}
	return "", nil
}

// applySSHDDropIn folds the staged sshd drop-in into the sample machine, which
// is what a real reload does with the file the install just put in /etc.
func (f *Fake) applySSHDDropIn() {
	for key, value := range parseSSHDDropIn(f.staged[SSHDDropInPath]) {
		if key == "passwordauthentication" {
			f.state.passwordAuth = value
		}
	}
}

// Load returns the sample machine's posture.
func (f *Fake) Load(_ context.Context) (posture.Report, error) {
	report := posture.Report{
		Backend:  f.Name(),
		Distro:   "Sample Linux 1.0 (demo)",
		DistroID: "demo",
		Kernel:   "6.16.3-demo",
	}
	for _, id := range posture.IDs {
		probe, _ := f.probe(id)
		report.Probes = append(report.Probes, probe)
	}
	report.Stack = stackOf(report.Probes)
	report.Finish()
	return report, nil
}

// Reload runs one probe of the sample machine again.
func (f *Fake) Reload(_ context.Context, id string) (posture.Probe, error) {
	return f.probe(id)
}

// BuildAction builds the same plan the real backend builds, from the same
// builders. Only the staging differs: --demo writes no file, so the drop-in
// lives in a map and the path it would have been written to is a name.
func (f *Fake) BuildAction(probeID, actionID string) (posture.Plan, error) {
	kind, argument, hasArgument := strings.Cut(actionID, ":")
	switch kind {
	case ActionFirewalldEnable, ActionNftablesEnable:
		if hasArgument {
			return posture.Plan{}, fmt.Errorf("host: %q takes no argument", kind)
		}
	}

	switch kind {
	case ActionSSHD:
		return f.sshdPlan(argument)

	case ActionDisablePort:
		unit, known := f.portUnits()[argument]
		if !known {
			return posture.Plan{}, fmt.Errorf(
				"host: nothing on port %s was traced back to a unit this tool "+
					"can stop; re-run the probe", argument)
		}
		return PortDisablePlan(argument, unit)

	case ActionFirewalldEnable:
		return FirewallEnablePlan(kind, "", "")

	case ActionNftablesEnable:
		// The sample machine runs ufw, so this never comes from its own
		// screen. It is built from a ruleset the demo says exists, so the
		// commands and the refusals can still be exercised without one.
		return FirewallEnablePlan(kind, NftablesConfigPaths[0], "")

	case ActionSysctl:
		// Handled below: staging is the only thing the demo does differently.
	default:
		real := &Real{staged: map[string]string{}}
		return real.BuildAction(probeID, actionID)
	}

	key, ok := hardeningKey(argument)
	if !ok || !key.Fixable {
		return posture.Plan{}, fmt.Errorf("host: %q is not a key this tool sets",
			argument)
	}
	content, err := RenderDropIn(f.staged[DropInPath], key.Key, key.Want)
	if err != nil {
		return posture.Plan{}, err
	}
	f.staged[DropInPath] = content
	installCmd, err := BuildInstallDropIn("/tmp/tui-secure/90-tui-secure.conf")
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

// sshdPlan builds the same plan the real backend builds for one sshd keyword,
// from the same function. Only the staging differs: --demo writes no file, so
// the drop-in lives in a map and the path it would have been written to is a
// name.
func (f *Fake) sshdPlan(name string) (posture.Plan, error) {
	key, ok := sshdKey(name)
	if !ok {
		return posture.Plan{}, fmt.Errorf(
			"host: %q is not a keyword this tool sets", name)
	}
	input := SSHDPlanInput{
		Key:       key.Key,
		Effective: ParseSSHDConfig(f.sshdOutput()),
		Existing:  f.staged[SSHDDropInPath],
		Unit:      "sshd",
		Paths:     demoLoginPaths,
	}
	content, err := RenderSSHDDropIn(input.Existing, key.Key, key.Want)
	if err != nil {
		return posture.Plan{}, err
	}
	f.staged[SSHDDropInPath] = content
	return SSHDPlan(input, "/tmp/tui-secure/"+SSHDDropInName)
}

// sshdOutput is what `sshd -T` would print on the sample machine now.
func (f *Fake) sshdOutput() string {
	return strings.Replace(demoSSHD,
		"passwordauthentication yes",
		"passwordauthentication "+f.state.passwordAuth, 1)
}

// portUnits maps the sample machine's network-reachable ports onto the units
// behind them, skipping the ones this tool refuses to stop.
func (f *Fake) portUnits() map[string]string {
	units := map[string]string{}
	for _, listener := range ParseSS(f.ssOutput()) {
		unit := demoUnits[listener.PID]
		if !listener.Global || unit == "" || protectedUnits[unit] {
			continue
		}
		if _, seen := units[listener.Port]; !seen {
			units[listener.Port] = unit
		}
	}
	return units
}

// ssOutput is what `ss -tulpnH` would print on the sample machine now.
func (f *Fake) ssOutput() string {
	if f.state.nginxRunning {
		return demoSS
	}
	var kept []string
	for _, line := range splitLines(demoSS) {
		if !strings.Contains(line, "nginx") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// probe renders one probe of the sample machine from the current state.
func (f *Fake) probe(id string) (posture.Probe, error) {
	switch id {
	case posture.ProbeSecureBoot:
		return f.secureBoot(), nil
	case posture.ProbeMAC:
		return f.mac(), nil
	case posture.ProbeFirewall:
		return f.firewall(), nil
	case posture.ProbeSSH:
		return f.ssh(), nil
	case posture.ProbeUpdates:
		return f.updates(), nil
	case posture.ProbeAccounts:
		return f.accounts(), nil
	case posture.ProbeKernel:
		return f.kernel(), nil
	case posture.ProbePorts:
		return f.ports(), nil
	}
	return posture.Probe{}, fmt.Errorf("host: no probe called %q", id)
}

// The sample machine's outputs, written the way the real tools write them so
// the parsers in this package could read them back.
const (
	demoBootctl = `System:
      Firmware: UEFI 2.70 (EDK II 1.00)
 Firmware Arch: x64
   Secure Boot: enabled (deployed)
  TPM2 Support: yes
   Setup Mode: user`

	demoGetenforce = "Enforcing"

	demoSestatus = `SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
Current mode:                   enforcing
Loaded policy name:             targeted`

	demoDenials = `Aug 30 08:41:02 demo kernel: audit: type=1400 audit(1756...): avc:  denied  { read } for  pid=1841 comm="nginx" name="secret.conf"
Aug 30 09:02:55 demo kernel: audit: type=1400 audit(1756...): avc:  denied  { write } for  pid=1902 comm="backup" name="spool"
Aug 30 11:17:31 demo kernel: audit: type=1400 audit(1756...): avc:  denied  { open } for  pid=2044 comm="nginx" name="index.html"`

	demoUfwActive = `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
22/tcp (v6)                ALLOW IN    Anywhere (v6)`

	demoUfwInactive = "Status: inactive"

	demoSSHD = `port 22
permitrootlogin no
pubkeyauthentication yes
passwordauthentication yes
maxauthtries 6
x11forwarding no`

	demoFailedLogins = `Aug 30 03:14:09 demo sshd[1201]: Failed password for invalid user admin from 198.51.100.7 port 51022 ssh2
Aug 30 03:14:12 demo sshd[1203]: Invalid user oracle from 198.51.100.7 port 51044
Aug 30 04:52:41 demo sshd[1288]: Failed password for root from 203.0.113.9 port 40122 ssh2`

	demoUpdates = `linux 6.16.3.arch1-1 -> 6.16.5.arch1-1
openssl 3.5.2-1 -> 3.5.3-1
curl 8.16.0-1 -> 8.16.1-1
systemd 257.8-1 -> 257.9-1
git 2.51.0-1 -> 2.51.1-1
sudo 1.9.17.p2-1 -> 1.9.17.p3-1
nginx 1.29.1-1 -> 1.29.2-1
python 3.13.7-1 -> 3.13.8-1
glibc 2.42-3 -> 2.42-4
btrfs-progs 6.16-1 -> 6.17-1
zstd 1.5.7-2 -> 1.5.7-3
vim 9.1.1700-1 -> 9.1.1750-1`

	//nolint:gosec // an /etc/passwd sample: the x is the placeholder that says
	// the hash lives in /etc/shadow, so there is no credential here
	demoPasswd = `root:x:0:0:Super User:/root:/bin/bash
backup:x:0:0:Backup operator:/var/backups:/bin/bash`

	demoSS = `tcp   LISTEN 0 4096   0.0.0.0:22    0.0.0.0:* users:(("sshd",pid=901,fd=3))
tcp   LISTEN 0 511    0.0.0.0:80    0.0.0.0:* users:(("nginx",pid=1841,fd=6))
tcp   LISTEN 0 4096 127.0.0.1:5432  0.0.0.0:* users:(("postgres",pid=1122,fd=5))
tcp   LISTEN 0 4096 127.0.0.1:6379  0.0.0.0:* users:(("redis-server",pid=1180,fd=6))
udp   UNCONN 0 0    127.0.0.1:323   0.0.0.0:* users:(("chronyd",pid=804,fd=5))
tcp   LISTEN 0 4096     [::1]:631      [::]:* users:(("cupsd",pid=712,fd=8))`
)

// secureBoot: the firmware verified what it booted.
func (f *Fake) secureBoot() posture.Probe {
	return posture.Probe{
		ID: posture.ProbeSecureBoot, Title: titleFor(posture.ProbeSecureBoot),
		Status:  posture.StatusOK,
		Summary: "Secure Boot is enabled (deployed)",
		Findings: []posture.Finding{
			{Label: "Secure Boot", Value: "enabled (deployed)", Status: posture.StatusOK},
			{Label: "setup mode", Value: "user", Status: posture.StatusOK},
			{Label: "TPM2", Value: "yes", Status: posture.StatusOK},
			stack("SB: on"),
		},
		Evidence: []posture.Evidence{
			{Command: "bootctl status", Line: "Secure Boot: enabled (deployed)"},
		},
		Raw: "$ bootctl status\n" + demoBootctl + "\n",
	}
}

// mac: SELinux, enforcing, with a handful of denials worth reading.
func (f *Fake) mac() posture.Probe {
	return posture.Probe{
		ID: posture.ProbeMAC, Title: titleFor(posture.ProbeMAC),
		Status:  posture.StatusOK,
		Summary: "SELinux is enforcing, 3 denial(s) in the last 24h",
		Findings: []posture.Finding{
			{Label: "mode", Value: "Enforcing", Status: posture.StatusOK},
			{Label: "policy", Value: "targeted", Status: posture.StatusOK},
			{Label: "denials (24h)", Value: "3", Status: posture.StatusOK,
				Note: "from the kernel journal"},
			stack("MAC: SELinux enforcing"),
		},
		Evidence: []posture.Evidence{
			{Command: "getenforce", Line: "Enforcing"},
			{Command: `journalctl -k --since -24h --grep avc:  denied`,
				Line: firstMatch(demoDenials, "avc")},
		},
		Raw: "$ getenforce\n" + demoGetenforce + "\n\n$ sestatus\n" + demoSestatus +
			"\n\n$ journalctl -k --since -24h --grep 'avc:  denied'\n" + demoDenials + "\n",
	}
}

// firewall: ufw, active by default, and turnable back on when the demo has
// been played with.
func (f *Fake) firewall() posture.Probe {
	probe := posture.Probe{
		ID: posture.ProbeFirewall, Title: titleFor(posture.ProbeFirewall),
		Fix: posture.Fix{Tool: "tui-firewall"},
	}
	if !f.state.ufwActive {
		probe.Status = posture.StatusBad
		probe.Summary = "ufw is installed but inactive: nothing is filtered"
		probe.Fix.Hint = "Enable ufw. Check your ssh rule first if you are " +
			"connected over the network."
		probe.Actions = []posture.Action{
			{ID: ActionUfwEnable, Label: "Enable ufw", Danger: true},
		}
		probe.Findings = []posture.Finding{
			{Label: "state", Value: "inactive", Status: posture.StatusBad},
			stack("firewall: ufw"),
		}
		probe.Evidence = []posture.Evidence{
			{Command: "sudo -n ufw status verbose", Line: "Status: inactive"},
		}
		probe.Raw = "$ sudo -n ufw status verbose\n" + demoUfwInactive + "\n"
		return probe
	}

	probe.Status = posture.StatusOK
	probe.Summary = "ufw is active with 4 rule(s)"
	probe.Findings = []posture.Finding{
		{Label: "state", Value: "active", Status: posture.StatusOK},
		{Label: "incoming", Value: "deny", Status: posture.StatusOK},
		{Label: "outgoing", Value: "allow", Status: posture.StatusOK},
		{Label: "rules", Value: "4", Status: posture.StatusOK},
		stack("firewall: ufw"),
	}
	probe.Evidence = []posture.Evidence{
		{Command: "sudo -n ufw status verbose", Line: "Status: active"},
	}
	probe.Raw = "$ sudo -n ufw status verbose\n" + demoUfwActive + "\n"
	return probe
}

// ssh: running, keys allowed, and passwords still allowed too — until the sshd
// action turns them off, at which point the row goes green like the real one
// would after the reload.
func (f *Fake) ssh() posture.Probe {
	settings := ParseSSHDConfig(f.sshdOutput())
	passwords := f.state.passwordAuth == "yes"

	probe := posture.Probe{
		ID: posture.ProbeSSH, Title: titleFor(posture.ProbeSSH),
		Status:  boolStatus(!passwords),
		Summary: "sshd is running with keys only and root login off",
		Findings: []posture.Finding{
			{Label: "PermitRootLogin", Value: "no", Status: posture.StatusOK},
			{Label: "PasswordAuthentication", Value: f.state.passwordAuth,
				Status: boolStatus(!passwords),
				Note:   "passwords are guessable; keys are not"},
			{Label: "PermitEmptyPasswords", Value: "no", Status: posture.StatusOK},
			{Label: "PubkeyAuthentication", Value: "yes", Status: posture.StatusOK},
			{Label: "MaxAuthTries", Value: "6", Status: posture.StatusOK},
			{Label: "X11Forwarding", Value: "no", Status: posture.StatusOK},
			{Label: "Port", Value: "22", Status: posture.StatusOK},
			{Label: "running", Value: "sshd is active", Status: posture.StatusOK},
			{Label: "failed logins (24h)", Value: "3", Status: posture.StatusOK,
				Note: "from the sshd journal"},
			{Label: "read from", Value: "`sshd -T`", Status: posture.StatusOK},
			stack("sshd: running"),
		},
		Evidence: []posture.Evidence{
			{Command: "sudo -n sshd -T",
				Line: "passwordauthentication " + f.state.passwordAuth},
			{Command: `journalctl -u sshd -u ssh --since -24h --grep Failed password|Invalid user`,
				Line: firstMatch(demoFailedLogins, "Failed password")},
		},
		Raw: "$ sudo -n sshd -T\n" + f.sshdOutput() +
			"\n\n$ journalctl -u sshd -u ssh --since -24h --grep 'Failed password|Invalid user'\n" +
			demoFailedLogins + "\n",
	}
	if passwords {
		probe.Summary = "sshd is running with password authentication on"
		probe.Fix = posture.Fix{
			Tool: "tui-ssh (planned)",
			Hint: "Each keyword below can be set in " + SSHDDropInPath +
				", checked with `sshd -t -f` and reloaded. Press a to do it " +
				"one keyword at a time, previewed first.",
			Command: "sudo sshd -t && sudo systemctl reload sshd",
		}
	}
	probe.Actions = sshdActions(settings)
	return probe
}

// updates: a dozen pending, a reboot owed, and nothing applying them.
func (f *Fake) updates() posture.Probe {
	pending := ParsePacmanUpdates(demoUpdates)
	timerState := "disabled"
	if f.state.timerEnabled {
		timerState = "enabled"
	}
	probe := posture.Probe{
		ID: posture.ProbeUpdates, Title: titleFor(posture.ProbeUpdates),
		Status: posture.StatusWarn,
		Summary: fmt.Sprintf("%d update(s) pending, and a reboot is needed",
			len(pending)),
		Findings: []posture.Finding{
			{Label: "pending", Value: fmt.Sprint(len(pending)), Status: posture.StatusWarn},
			{Label: "first few", Value: strings.Join(firstN(pending, 5), " "),
				Status: posture.StatusOK},
			{Label: "reboot needed", Value: "yes", Status: posture.StatusWarn,
				Note: "the installed kernel is 6.16.5.arch1-1, running 6.16.3-demo"},
			{Label: demoTimer, Value: timerState,
				Status: boolStatus(f.state.timerEnabled)},
			stack("updates: arch"),
		},
		Evidence: []posture.Evidence{
			{Command: "checkupdates", Line: "12 package(s) listed"},
			{Command: "systemctl is-enabled " + demoTimer,
				Line: demoTimer + ": " + timerState},
		},
		Fix: posture.Fix{
			Tool:    "tui-update (planned)",
			Hint:    "Apply the updates, and reboot if the kernel or a core library moved.",
			Command: "sudo pacman -Syu",
		},
		Raw: "$ checkupdates\n" + demoUpdates + "\n\n$ systemctl is-enabled " +
			demoTimer + "\n" + timerState + "\n",
	}
	if !f.state.timerEnabled {
		probe.Actions = []posture.Action{
			{ID: ActionEnableTimer + ":" + demoTimer, Label: "Enable " + demoTimer},
		}
	}
	return probe
}

// accounts: a second account with UID 0, which is a second root.
func (f *Fake) accounts() posture.Probe {
	roots := ParsePasswdRootAccounts(demoPasswd)
	return posture.Probe{
		ID: posture.ProbeAccounts, Title: titleFor(posture.ProbeAccounts),
		Status:  posture.StatusBad,
		Summary: "an account can reach root without proving who it is",
		Findings: []posture.Finding{
			{Label: "UID 0 accounts", Value: strings.Join(roots, " "),
				Status: posture.StatusBad,
				Note:   "a second account with UID 0 is a second root under another name"},
			{Label: "empty passwords", Value: "none", Status: posture.StatusOK},
			{Label: "NOPASSWD (this user)", Value: "1 entry(ies)",
				Status: posture.StatusWarn,
				Note:   "(demo) ALL=(ALL) NOPASSWD: /usr/bin/pacman"},
		},
		Evidence: []posture.Evidence{
			{Command: "awk -F: '$3==0' /etc/passwd", Line: strings.Join(roots, " ")},
			{Command: "sudo -n -l", Line: "(demo) ALL=(ALL) NOPASSWD: /usr/bin/pacman"},
		},
		Fix: posture.Fix{
			Tool: "tui-users (planned)",
			Hint: "Remove the second UID 0 account, or lock the accounts with no password.",
		},
		Raw: "$ awk -F: '$3==0' /etc/passwd\n" + demoPasswd +
			"\n\n$ sudo -n -l\nUser demo may run the following commands on demo:\n" +
			"    (ALL) NOPASSWD: /usr/bin/pacman\n",
	}
}

// kernel: the hardening basics, with one key left at zero.
func (f *Fake) kernel() posture.Probe {
	values := map[string]string{
		"kernel.kptr_restrict":   f.state.kptrRestrict,
		"kernel.dmesg_restrict":  "1",
		"fs.protected_hardlinks": "1",
		"fs.protected_symlinks":  "1",
		"fs.protected_fifos":     "1",
		"fs.protected_regular":   "2",
		"fs.suid_dumpable":       "0",
		"net.ipv4.ip_forward":    "0",
		"kernel.core_pattern":    "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h",
	}

	probe := posture.Probe{
		ID: posture.ProbeKernel, Title: titleFor(posture.ProbeKernel),
	}
	var raw strings.Builder
	weak := 0
	statuses := []posture.Status{posture.StatusOK}
	for _, key := range HardeningKeys {
		value := values[key.Key]
		fmt.Fprintf(&raw, "$ sysctl -n %s\n%s\n\n", key.Key, value)
		status := posture.StatusOK
		if !key.Satisfied(value) {
			status, weak = posture.StatusWarn, weak+1
			statuses = append(statuses, status)
			probe.Evidence = append(probe.Evidence, posture.Evidence{
				Command: "sysctl -n " + key.Key, Line: key.Key + " = " + value})
			if key.Fixable {
				probe.Actions = append(probe.Actions, posture.Action{
					ID: ActionSysctl + ":" + key.Key,
					Label: fmt.Sprintf("Set %s=%s, now and on every boot",
						key.Key, key.Want),
				})
			}
		}
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: key.Key, Value: value, Status: status, Note: key.Why})
	}
	probe.Status = posture.Worst(statuses...)
	if weak == 0 {
		probe.Summary = "the hardening basics are set"
	} else {
		probe.Summary = fmt.Sprintf("%d hardening key(s) below the recommended value", weak)
		probe.Fix.Hint = "Each key can be set now and made persistent in " +
			DropInPath + ". Press a to do it one key at a time, previewed first."
	}
	probe.Raw = strings.TrimSuffix(raw.String(), "\n")
	return probe
}

// ports: six sockets, two of them reachable from another machine.
func (f *Fake) ports() posture.Probe {
	out := f.ssOutput()
	listeners := ParseSS(out)
	probe := posture.Probe{
		ID: posture.ProbePorts, Title: titleFor(posture.ProbePorts),
		Status: posture.StatusWarn,
		Fix: posture.Fix{
			Tool: "tui-firewall",
			Hint: "Bind what does not need the network to localhost, and let " +
				"the firewall decide about the rest.",
		},
		Evidence: []posture.Evidence{
			{Command: "sudo -n ss -tulpnH", Line: firstGlobal(listeners)},
		},
		Raw: "$ sudo -n ss -tulpnH\n" + out + "\n",
	}
	offered := map[string]bool{}
	global := 0
	for _, listener := range listeners {
		if !listener.Global {
			continue
		}
		global++
		unit := demoUnits[listener.PID]
		if unit != "" && !protectedUnits[unit] && !offered[listener.Port] {
			offered[listener.Port] = true
			probe.Actions = append(probe.Actions, posture.Action{
				ID: ActionDisablePort + ":" + listener.Port,
				Label: "Stop " + unit + " (" + listener.Proto + " port " +
					listener.Port + ")",
				Danger: true,
			})
		}
		probe.Findings = append(probe.Findings, posture.Finding{
			Label:  listener.Proto + " " + listener.Address + ":" + listener.Port,
			Value:  orUnknown(listener.Process),
			Status: posture.StatusWarn,
			Note:   unit,
		})
	}
	probe.Summary = fmt.Sprintf(
		"%d listening socket(s), %d reachable from the network",
		len(listeners), global)
	return probe
}
