package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// The eight probes. Each one answers a single question about the machine,
// records the command it asked and the line it read, and grades what came
// back. None of them changes anything.
//
// The grading rules are written out here rather than hidden in a table,
// because a security verdict that cannot be read as a sentence is a verdict
// nobody can argue with — and being argued with is the point.

// journalWindow is how far back the journal reads look. A day is short enough
// that a count means "now" and long enough to survive a machine that was off
// overnight.
const journalWindow = "-24h"

// journalLines bounds what a journal read pulls into memory, since the raw
// output ends up on the detail screen.
const journalLines = "500"

// probeSecureBoot asks whether the firmware verified what it booted.
func (r *Real) probeSecureBoot(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbeSecureBoot, Title: titleFor(posture.ProbeSecureBoot),
	}
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	out, preview, err := r.read(ctx, c, "bootctl", "status")
	if err != nil && !strings.Contains(out, "Secure Boot") {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the Secure Boot state"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("SB: unknown"))
		return probe
	}

	info := ParseBootctl(out)
	if !info.EFI {
		probe.Status = posture.StatusUnknown
		probe.Summary = "this machine did not boot through EFI"
		probe.Reason = "Secure Boot is an EFI feature, and `bootctl status` " +
			"reports no EFI firmware here"
		probe.Findings = append(probe.Findings, stack("SB: no EFI"))
		return probe
	}
	c.judged(preview, info.SecureBootLine)

	switch {
	case info.InSetupMode():
		probe.Status = posture.StatusBad
		probe.Summary = "the firmware is in setup mode: it will accept any key"
		probe.Fix = posture.Fix{
			Hint: "Leave setup mode in the firmware once the keys you want are " +
				"enrolled; on a machine with custom keys that is `sbctl enroll-keys`.",
		}
	case info.Enabled():
		probe.Status = posture.StatusOK
		probe.Summary = "Secure Boot is " + info.SecureBoot
	default:
		probe.Status = posture.StatusWarn
		probe.Summary = "Secure Boot is off, so the firmware boots anything"
		probe.Fix = posture.Fix{
			Hint: "Turn Secure Boot on in the firmware setup. A machine with " +
				"out-of-tree kernel modules needs its own keys enrolled first, " +
				"which is what sbctl is for.",
		}
	}

	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "Secure Boot", Value: orUnknown(info.SecureBoot),
			Status: probe.Status})
	if info.SetupMode != "" {
		probe.Findings = append(probe.Findings,
			posture.Finding{Label: "setup mode", Value: info.SetupMode,
				Status: boolStatus(!info.InSetupMode())})
	}
	if info.TPM2 != "" {
		probe.Findings = append(probe.Findings,
			posture.Finding{Label: "TPM2", Value: info.TPM2,
				Status: posture.StatusOK})
	}

	// sbctl is optional, and only it can say whether the keys on this machine
	// are the ones the administrator enrolled.
	if r.available("sbctl") {
		sbOut, sbPreview, sbErr := r.read(ctx, c, "sbctl", "status")
		if sbErr == nil {
			sb := ParseSbctlStatus(sbOut)
			if len(sb.Lines) > 0 {
				c.judged(sbPreview, sb.Lines[0])
			}
			probe.Findings = append(probe.Findings,
				posture.Finding{Label: "sbctl keys",
					Value:  yesNo(sb.Installed, "installed", "not installed"),
					Status: boolStatus(sb.Installed)})
		}
	}
	probe.Findings = append(probe.Findings, stack("SB: "+shortBoot(info)))
	return probe
}

// shortBoot names the Secure Boot state for the header.
func shortBoot(info BootInfo) string {
	if info.Enabled() {
		return "on"
	}
	return "off"
}

// probeMAC asks which mandatory access control layer is active, in which mode,
// and what it has been refusing.
func (r *Real) probeMAC(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{ID: posture.ProbeMAC, Title: titleFor(posture.ProbeMAC)}
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	switch {
	case r.available("getenforce"):
		r.selinux(ctx, c, &probe)
	case r.available("aa-status"):
		r.apparmor(ctx, c, &probe)
	default:
		probe.Status = posture.StatusWarn
		probe.Summary = "neither SELinux nor AppArmor is installed"
		probe.Fix = posture.Fix{
			Hint: "Install and enable the MAC layer your distribution ships: " +
				"SELinux on Fedora and RHEL, AppArmor on Debian, Ubuntu and " +
				"openSUSE. Without one, a compromised service is bounded only " +
				"by file permissions.",
		}
		probe.Findings = append(probe.Findings, stack("MAC: none"))
	}
	return probe
}

// selinux fills in the MAC probe from SELinux.
func (r *Real) selinux(ctx context.Context, c *collector, probe *posture.Probe) {
	out, preview, err := r.read(ctx, c, "getenforce")
	if err != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the SELinux mode"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("MAC: SELinux"))
		return
	}
	mode := strings.TrimSpace(out)
	c.judged(preview, mode)

	switch strings.ToLower(mode) {
	case "enforcing":
		probe.Status = posture.StatusOK
		probe.Summary = "SELinux is enforcing"
	case "permissive":
		probe.Status = posture.StatusWarn
		probe.Summary = "SELinux is permissive: it logs violations and allows them"
		probe.Fix = posture.Fix{
			Hint:    "Switch to enforcing once the denials below are clean.",
			Command: "sudo setenforce 1  # and SELINUX=enforcing in /etc/selinux/config",
		}
	default:
		probe.Status = posture.StatusWarn
		probe.Summary = "SELinux is disabled"
		probe.Fix = posture.Fix{
			Hint: "Re-enabling SELinux needs a full filesystem relabel and a " +
				"reboot, so it is a deliberate maintenance job rather than a " +
				"command to paste.",
			Command: "sudo touch /.autorelabel  # then set SELINUX=enforcing and reboot",
		}
	}
	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "mode", Value: mode, Status: probe.Status})

	if r.available("sestatus") {
		if statusOut, _, statusErr := r.read(ctx, c, "sestatus"); statusErr == nil {
			info := ParseSestatus(statusOut)
			if info.Policy != "" {
				probe.Findings = append(probe.Findings,
					posture.Finding{Label: "policy", Value: info.Policy,
						Status: posture.StatusOK})
			}
		}
	}

	denials, denialNote := r.denials(ctx, c, "avc:  denied", "avc")
	if denials >= 0 {
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "denials (24h)", Value: strconv.Itoa(denials),
			Status: posture.StatusOK, Note: denialNote})
		if denials > 0 {
			probe.Summary += fmt.Sprintf(", %d denial(s) in the last 24h", denials)
		}
	}
	probe.Findings = append(probe.Findings, stack("MAC: SELinux "+strings.ToLower(mode)))
}

// apparmor fills in the MAC probe from AppArmor.
func (r *Real) apparmor(ctx context.Context, c *collector, probe *posture.Probe) {
	out, preview, err := r.read(ctx, c, "aa-status", "--json")
	if err != nil && strings.TrimSpace(out) == "" {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the AppArmor profiles"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("MAC: AppArmor"))
		return
	}
	info, parseErr := ParseAAStatusJSON(out)
	if parseErr != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the AppArmor profiles"
		probe.Reason = "`aa-status --json` printed something this probe " +
			"could not parse: " + parseErr.Error()
		probe.Findings = append(probe.Findings, stack("MAC: AppArmor"))
		return
	}
	c.judged(preview, fmt.Sprintf("%d profiles: %d enforce, %d complain",
		info.Total, info.Enforce, info.Complain))

	switch {
	case info.Enforce > 0:
		probe.Status = posture.StatusOK
		probe.Summary = fmt.Sprintf("AppArmor is enforcing %d profile(s)", info.Enforce)
	case info.Complain > 0:
		probe.Status = posture.StatusWarn
		probe.Summary = fmt.Sprintf(
			"AppArmor loads %d profile(s), all in complain mode", info.Complain)
		probe.Fix = posture.Fix{
			Hint:    "A complain profile logs and allows. Put the ones you trust into enforce.",
			Command: "sudo aa-enforce /etc/apparmor.d/<profile>",
		}
	default:
		probe.Status = posture.StatusWarn
		probe.Summary = "AppArmor is installed but no profile is loaded"
		probe.Fix = posture.Fix{
			Hint:    "Install the profile set your distribution ships and load it.",
			Command: "sudo systemctl enable --now apparmor.service",
		}
	}
	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "enforce", Value: strconv.Itoa(info.Enforce),
			Status: boolStatus(info.Enforce > 0)},
		posture.Finding{Label: "complain", Value: strconv.Itoa(info.Complain),
			Status: posture.StatusOK},
		posture.Finding{Label: "profiles", Value: strconv.Itoa(info.Total),
			Status: posture.StatusOK})

	denials, denialNote := r.denials(ctx, c, `apparmor="DENIED"`, "apparmor")
	if denials >= 0 {
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "denials (24h)", Value: strconv.Itoa(denials),
			Status: posture.StatusOK, Note: denialNote})
		if denials > 0 {
			probe.Summary += fmt.Sprintf(", %d denial(s) in the last 24h", denials)
		}
	}
	probe.Findings = append(probe.Findings, stack("MAC: AppArmor"))
}

// denials counts the MAC denials in the kernel journal over the last day. It
// returns -1 when neither the journal nor the audit log could be read, so the
// caller can leave the finding out rather than print a zero it cannot stand
// behind.
//
// The journal is asked first because it needs no privileges on most machines.
// `ausearch` is the fallback, and only where auditd is actually running: it
// reads /var/log/audit, which needs root, so it goes through `sudo -n` and is
// allowed to come back empty-handed.
func (r *Real) denials(ctx context.Context, c *collector,
	pattern, kind string) (int, string) {
	out, preview, err := r.read(ctx, c, "journalctl", "-k",
		"--since", journalWindow, "--no-pager", "-n", journalLines,
		"--grep", pattern)
	if err == nil {
		count := CountMatches(out, kind)
		if count > 0 {
			c.judged(preview, firstMatch(out, kind))
		}
		return count, "from the kernel journal"
	}

	if kind != "avc" || !r.unitActive(ctx, c, "auditd") {
		return -1, ""
	}
	auditOut, auditPreview, auditErr := r.readPrivileged(ctx, c,
		"ausearch", "-m", "avc", "-ts", "recent")
	if auditErr != nil {
		return -1, ""
	}
	count := CountMatches(auditOut, "avc")
	if count > 0 {
		c.judged(auditPreview, firstMatch(auditOut, "avc"))
	}
	return count, "from the audit log"
}

// firstMatch returns the first line containing a needle, which is the line a
// count is worth showing next to.
func firstMatch(out, needle string) string {
	lower := strings.ToLower(needle)
	for _, line := range splitLines(out) {
		if strings.Contains(strings.ToLower(line), lower) {
			return line
		}
	}
	return ""
}

// probeFirewall asks whether anything is filtering what reaches this machine.
func (r *Real) probeFirewall(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbeFirewall, Title: titleFor(posture.ProbeFirewall),
	}
	probe.Fix.Tool = "tui-firewall"
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	switch {
	case r.available("ufw"):
		r.ufw(ctx, c, &probe)
	case r.available("firewall-cmd"):
		r.firewalld(ctx, c, &probe)
	case r.available("nft"):
		r.nftables(ctx, c, &probe)
	default:
		probe.Status = posture.StatusBad
		probe.Summary = "no firewall is installed on this machine"
		probe.Fix.Hint = "Install the firewall your distribution ships — ufw on " +
			"Debian and Ubuntu, firewalld on Fedora — and let it deny incoming " +
			"traffic by default."
		probe.Findings = append(probe.Findings, stack("firewall: none"))
	}
	return probe
}

// ufw fills in the firewall probe from ufw, whose status needs root.
func (r *Real) ufw(ctx context.Context, c *collector, probe *posture.Probe) {
	out, preview, err := r.readPrivileged(ctx, c, "ufw", "status", "verbose")
	if err != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "ufw is installed, but its status could not be read"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("firewall: ufw"))
		return
	}
	status := ParseUfwStatus(out)
	c.judged(preview, status.StatusLine)

	if status.Active {
		probe.Status = posture.StatusOK
		probe.Summary = fmt.Sprintf("ufw is active with %d rule(s)", status.Rules)
		if status.Incoming != "" && status.Incoming != "deny" &&
			status.Incoming != "reject" {
			probe.Status = posture.StatusWarn
			probe.Summary = "ufw is active but its default for incoming traffic is " +
				status.Incoming
			probe.Fix.Hint = "Deny incoming by default and allow only what you need."
			probe.Fix.Command = "sudo ufw default deny incoming"
		}
	} else {
		probe.Status = posture.StatusBad
		probe.Summary = "ufw is installed but inactive: nothing is filtered"
		probe.Fix.Hint = "Enable ufw. Check your ssh rule first if you are " +
			"connected over the network."
		probe.Actions = append(probe.Actions, posture.Action{
			ID: ActionUfwEnable, Label: "Enable ufw", Danger: true})
	}

	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "state", Value: yesNo(status.Active, "active", "inactive"),
			Status: boolStatus(status.Active)},
		posture.Finding{Label: "incoming", Value: orUnknown(status.Incoming),
			Status: policyStatus(status.Incoming)},
		posture.Finding{Label: "outgoing", Value: orUnknown(status.Outgoing),
			Status: posture.StatusOK},
		posture.Finding{Label: "rules", Value: strconv.Itoa(status.Rules),
			Status: posture.StatusOK},
		stack("firewall: ufw"))
}

// firewalld fills in the firewall probe from firewalld, whose state and zones
// any user may read.
func (r *Real) firewalld(ctx context.Context, c *collector, probe *posture.Probe) {
	out, preview, err := r.read(ctx, c, "firewall-cmd", "--state")
	state := strings.TrimSpace(out)
	c.judged(preview, state)
	if err != nil && state == "" {
		probe.Status = posture.StatusUnknown
		probe.Summary = "firewalld is installed, but its state could not be read"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("firewall: firewalld"))
		return
	}
	if state != "running" {
		probe.Status = posture.StatusBad
		probe.Summary = "firewalld is installed but not running: nothing is filtered"
		probe.Fix.Hint = "Start firewalld, or use the firewall you replaced it with."
		probe.Fix.Command = "sudo systemctl enable --now firewalld"
		probe.Findings = append(probe.Findings,
			posture.Finding{Label: "state", Value: orUnknown(state),
				Status: posture.StatusBad},
			stack("firewall: firewalld"))
		return
	}

	probe.Status = posture.StatusOK
	zoneName := ""
	if zoneOut, _, zoneErr := r.read(ctx, c, "firewall-cmd", "--get-default-zone"); zoneErr == nil {
		zoneName = strings.TrimSpace(zoneOut)
	}
	probe.Summary = "firewalld is running"
	if zoneName != "" {
		probe.Summary += ", default zone " + zoneName
	}
	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "state", Value: state, Status: posture.StatusOK},
		posture.Finding{Label: "default zone", Value: orUnknown(zoneName),
			Status: posture.StatusOK})

	if listOut, listPreview, listErr := r.read(ctx, c, "firewall-cmd", "--list-all"); listErr == nil {
		zone := ParseFirewalldZone(listOut)
		c.judged(listPreview, "services: "+strings.Join(zone.Services, " "))
		probe.Findings = append(probe.Findings,
			posture.Finding{Label: "services", Value: orUnknown(strings.Join(zone.Services, " ")),
				Status: posture.StatusOK},
			posture.Finding{Label: "ports", Value: orUnknown(strings.Join(zone.Ports, " ")),
				Status: posture.StatusOK})
		if len(zone.Ports) > 0 {
			probe.Status = posture.StatusWarn
			probe.Summary += fmt.Sprintf(", %d port range(s) open in it", len(zone.Ports))
			probe.Fix.Hint = "Close the port ranges the default zone opens, or " +
				"move the machine to a stricter zone."
		}
	}
	probe.Findings = append(probe.Findings, stack("firewall: firewalld"))
}

// nftables fills in the firewall probe from a bare nftables ruleset, which is
// what a machine without a front end has.
func (r *Real) nftables(ctx context.Context, c *collector, probe *posture.Probe) {
	out, preview, err := r.readPrivileged(ctx, c, "nft", "list", "ruleset")
	if err != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "nftables is installed, but its ruleset could not be read"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("firewall: nftables"))
		return
	}
	rules := ParseNftRuleCount(out)
	c.judged(preview, fmt.Sprintf("%d rule(s) in the ruleset", rules))
	if rules == 0 {
		probe.Status = posture.StatusBad
		probe.Summary = "the nftables ruleset is empty: nothing is filtered"
		probe.Fix.Hint = "Load a ruleset, or install a front end that manages one."
	} else {
		probe.Status = posture.StatusOK
		probe.Summary = fmt.Sprintf("a bare nftables ruleset with %d rule(s)", rules)
	}
	probe.Findings = append(probe.Findings,
		posture.Finding{Label: "rules", Value: strconv.Itoa(rules),
			Status: boolStatus(rules > 0)},
		stack("firewall: nftables"))
}

// sshdConfigPaths are the files the fallback read parses, in the order sshd
// itself reads them.
var sshdConfigPaths = []string{"/etc/ssh/sshd_config"}

// sshdDropInDir holds the drop-ins a distribution and its packages add.
const sshdDropInDir = "/etc/ssh/sshd_config.d"

// probeSSH asks how the one service the internet talks to is configured.
func (r *Real) probeSSH(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{ID: posture.ProbeSSH, Title: titleFor(posture.ProbeSSH)}
	probe.Fix.Tool = "tui-ssh (planned)"
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	active, unit := r.sshdActive(ctx, c)
	settings, source, err := r.sshdSettings(ctx, c)
	if settings == nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the sshd configuration"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings,
			posture.Finding{Label: "running", Value: yesNo(active, "yes", "no"),
				Status: posture.StatusOK},
			stack("sshd: "+yesNo(active, "running", "stopped")))
		return probe
	}

	statuses := []posture.Status{}
	add := func(label, key string, judge func(string) (posture.Status, string)) {
		value := settings[key]
		status, note := judge(value)
		statuses = append(statuses, status)
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: label, Value: orUnknown(value), Status: status, Note: note})
	}

	add("PermitRootLogin", "permitrootlogin", func(v string) (posture.Status, string) {
		switch strings.ToLower(v) {
		case "yes":
			return posture.StatusBad, "root can log in over ssh with a password"
		case "prohibit-password", "without-password":
			return posture.StatusWarn, "root can log in with a key"
		case "":
			return posture.StatusUnknown, "sshd did not report this keyword"
		default:
			return posture.StatusOK, ""
		}
	})
	add("PasswordAuthentication", "passwordauthentication", func(v string) (posture.Status, string) {
		if strings.EqualFold(v, "yes") {
			return posture.StatusWarn, "passwords are guessable; keys are not"
		}
		return posture.StatusOK, ""
	})
	add("PubkeyAuthentication", "pubkeyauthentication", func(v string) (posture.Status, string) {
		if strings.EqualFold(v, "no") {
			return posture.StatusWarn, "key authentication is off, leaving passwords"
		}
		return posture.StatusOK, ""
	})
	add("MaxAuthTries", "maxauthtries", func(v string) (posture.Status, string) {
		tries, convErr := strconv.Atoi(v)
		if convErr != nil {
			return posture.StatusOK, ""
		}
		if tries > 6 {
			return posture.StatusWarn, "each connection may guess " + v + " times"
		}
		return posture.StatusOK, ""
	})
	add("X11Forwarding", "x11forwarding", func(v string) (posture.Status, string) {
		if strings.EqualFold(v, "yes") {
			return posture.StatusWarn, "X11 forwarding exposes the client's display"
		}
		return posture.StatusOK, ""
	})
	probe.Findings = append(probe.Findings, posture.Finding{
		Label: "Port", Value: orUnknown(settings["port"]), Status: posture.StatusOK})
	probe.Findings = append(probe.Findings, posture.Finding{
		Label: "running", Value: yesNo(active, unit+" is active", "not running"),
		Status: posture.StatusOK})

	if failed, failedNote := r.failedLogins(ctx, c); failed >= 0 {
		status := posture.StatusOK
		if failed >= 10 {
			status = posture.StatusWarn
			statuses = append(statuses, status)
		}
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "failed logins (24h)", Value: strconv.Itoa(failed),
			Status: status, Note: failedNote})
	}

	probe.Status = posture.Worst(statuses...)
	if !active {
		// Nothing is listening, so the settings are what sshd *would* apply.
		// They are still worth showing, and still worth grading, but a stopped
		// server is not an exposure today.
		probe.Status = posture.StatusOK
		probe.Summary = "the ssh server is not running"
	} else {
		probe.Summary = sshSummary(settings, probe.Status)
	}
	probe.Findings = append(probe.Findings, stack("sshd: "+
		yesNo(active, "running", "stopped")))

	if probe.Status != posture.StatusOK {
		probe.Fix.Hint = "Set the keywords above in a drop-in under " +
			sshdDropInDir + ", check it with `sshd -t`, then reload sshd."
		probe.Fix.Command = "sudo sshd -t && sudo systemctl reload " + unit
	}
	probe.Findings = append(probe.Findings, posture.Finding{
		Label: "read from", Value: source, Status: posture.StatusOK})
	return probe
}

// sshSummary is the one line the sshd row shows.
func sshSummary(settings map[string]string, status posture.Status) string {
	if status == posture.StatusOK {
		return "sshd is running with keys only and root login off"
	}
	var flags []string
	if strings.EqualFold(settings["permitrootlogin"], "yes") {
		flags = append(flags, "root login enabled")
	}
	if strings.EqualFold(settings["passwordauthentication"], "yes") {
		flags = append(flags, "password authentication on")
	}
	if strings.EqualFold(settings["pubkeyauthentication"], "no") {
		flags = append(flags, "public keys off")
	}
	if len(flags) == 0 {
		return "sshd is running, with settings worth a look"
	}
	return "sshd is running with " + strings.Join(flags, " and ")
}

// sshdActive reports whether the ssh server is running, and under which unit
// name — Debian calls it ssh, everyone else calls it sshd.
func (r *Real) sshdActive(ctx context.Context, c *collector) (bool, string) {
	for _, unit := range []string{"sshd", "ssh"} {
		out, preview, err := r.read(ctx, c, "systemctl", "is-active", unit)
		state := strings.TrimSpace(out)
		if err == nil && state == "active" {
			c.judged(preview, unit+": "+state)
			return true, unit
		}
	}
	return false, "sshd"
}

// sshdSettings reads the effective configuration.
//
// `sshd -T` is the right answer — it is sshd resolving its own files, drop-ins
// and defaults — and it needs root, which this process may not have. The
// fallback parses the files directly: less accurate, since it cannot resolve a
// Match block, and honest about which one was used through the source string.
func (r *Real) sshdSettings(ctx context.Context, c *collector) (
	settings map[string]string, source string, err error) {
	out, preview, testErr := r.readPrivileged(ctx, c, "sshd", "-T")
	if testErr == nil {
		settings = ParseSSHDConfig(out)
		if line := settingLine(out, "permitrootlogin"); line != "" {
			c.judged(preview, line)
		}
		return settings, "`sshd -T`", nil
	}

	var text strings.Builder
	var readErr error
	for _, path := range sshdConfigPaths {
		raw, fileErr := os.ReadFile(path) //nolint:gosec // a fixed path, not user input
		if fileErr != nil {
			readErr = fileErr
			continue
		}
		text.WriteString(string(raw) + "\n")
	}
	if entries, dirErr := os.ReadDir(sshdDropInDir); dirErr == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			path := filepath.Join(sshdDropInDir, entry.Name())
			raw, fileErr := os.ReadFile(path) //nolint:gosec // sshd's own drop-in directory
			if fileErr != nil {
				continue
			}
			// A drop-in wins over sshd_config, the way sshd's Include at the
			// top of the file arranges it, so it goes first.
			text.WriteString(string(raw) + "\n")
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		if readErr == nil {
			readErr = testErr
		}
		return nil, "", readErr
	}
	c.record("cat "+strings.Join(sshdConfigPaths, " ")+" "+sshdDropInDir+"/*.conf",
		text.String())
	return ParseSSHDConfig(text.String()), "sshd_config (sshd -T needs root)", nil
}

// settingLine finds the line of `sshd -T` output that carries a keyword, which
// is the line the verdict on that keyword rests on.
func settingLine(out, key string) string {
	for _, line := range splitLines(out) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), key+" ") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// failedLogins counts the rejected ssh authentications of the last day. It
// returns -1 when the journal could not be read.
func (r *Real) failedLogins(ctx context.Context, c *collector) (int, string) {
	out, preview, err := r.read(ctx, c, "journalctl", "-u", "sshd", "-u", "ssh",
		"--since", journalWindow, "--no-pager", "-n", journalLines,
		"--grep", "Failed password|Invalid user")
	if err != nil {
		return -1, ""
	}
	count := 0
	for _, line := range splitLines(out) {
		if strings.Contains(line, "Failed password") ||
			strings.Contains(line, "Invalid user") {
			count++
		}
	}
	if count > 0 {
		c.judged(preview, firstMatch(out, "Failed password"))
	}
	return count, "from the sshd journal"
}

// probeUpdates asks what is pending, whether a reboot is owed, and whether
// anything applies updates without being asked.
func (r *Real) probeUpdates(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbeUpdates, Title: titleFor(posture.ProbeUpdates),
	}
	probe.Fix.Tool = "tui-update (planned)"
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	family := distroFamily()
	if family == "" {
		probe.Status = posture.StatusUnknown
		probe.Summary = "no package manager this probe knows"
		probe.Reason = "the ID and ID_LIKE in " + osReleasePath +
			" name no distribution family tui-secure has an update command for"
		probe.Findings = append(probe.Findings, stack("updates: unknown"))
		return probe
	}

	pending, upgradeCmd, err := r.pendingUpdates(ctx, c, family)
	if err != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not read the pending updates"
		probe.Reason = reason(err)
		probe.Findings = append(probe.Findings, stack("updates: "+family))
		return probe
	}

	statuses := []posture.Status{posture.StatusOK}
	if len(pending) > 0 {
		statuses = append(statuses, posture.StatusWarn)
	}
	probe.Findings = append(probe.Findings, posture.Finding{
		Label: "pending", Value: strconv.Itoa(len(pending)),
		Status: boolStatus(len(pending) == 0)})
	if len(pending) > 0 {
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "first few", Value: strings.Join(firstN(pending, 5), " "),
			Status: posture.StatusOK})
	}

	rebootNeeded, rebootNote := r.rebootNeeded(ctx, c, family)
	if rebootNeeded {
		statuses = append(statuses, posture.StatusWarn)
	}
	probe.Findings = append(probe.Findings, posture.Finding{
		Label: "reboot needed", Value: yesNo(rebootNeeded, "yes", "no"),
		Status: boolStatus(!rebootNeeded), Note: rebootNote})

	timer, timerState := r.updateTimer(ctx, c, family)
	if timer != "" {
		enabled := timerState == "enabled"
		if !enabled && timerState != "not-found" {
			statuses = append(statuses, posture.StatusWarn)
			probe.Actions = append(probe.Actions, posture.Action{
				ID:    ActionEnableTimer + ":" + timer,
				Label: "Enable " + timer,
			})
		}
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: timer, Value: timerState, Status: boolStatus(enabled)})
	}

	probe.Status = posture.Worst(statuses...)
	switch {
	case len(pending) == 0 && !rebootNeeded:
		probe.Summary = "nothing pending"
	case len(pending) == 0:
		probe.Summary = "up to date, but a reboot is needed"
	case rebootNeeded:
		probe.Summary = fmt.Sprintf("%d update(s) pending, and a reboot is needed",
			len(pending))
	default:
		probe.Summary = fmt.Sprintf("%d update(s) pending", len(pending))
	}
	if probe.Status != posture.StatusOK {
		probe.Fix.Hint = "Apply the updates, and reboot if the kernel or a core " +
			"library moved."
		probe.Fix.Command = upgradeCmd
	}
	probe.Findings = append(probe.Findings, stack("updates: "+family))
	return probe
}

// pendingUpdates asks the distribution's own package manager what is waiting,
// and returns the command a user would run to apply it.
//
// Every one of these reads is a simulation or a query: none of them installs
// anything, and none of them takes a package manager lock for writing.
func (r *Real) pendingUpdates(ctx context.Context, c *collector,
	family string) (pending []string, upgrade string, err error) {
	switch family {
	case "arch":
		if r.available("checkupdates") {
			out, preview, checkErr := r.read(ctx, c, "checkupdates")
			// checkupdates exits 2 when there is nothing to report, which is
			// an answer rather than a failure.
			if checkErr != nil && strings.TrimSpace(out) != "" {
				return nil, "", checkErr
			}
			pending = ParsePacmanUpdates(out)
			judgeCount(c, preview, pending)
			return pending, "sudo pacman -Syu", nil
		}
		out, preview, queryErr := r.read(ctx, c, "pacman", "-Qu")
		if queryErr != nil && strings.TrimSpace(out) != "" {
			return nil, "", queryErr
		}
		pending = ParsePacmanUpdates(out)
		judgeCount(c, preview, pending)
		return pending, "sudo pacman -Syu", nil

	case "debian":
		out, preview, aptErr := r.read(ctx, c, "apt-get", "-s", "upgrade")
		if aptErr != nil && !strings.Contains(out, "Inst ") {
			return nil, "", aptErr
		}
		pending = ParseAptUpdates(out)
		judgeCount(c, preview, pending)
		return pending, "sudo apt-get update && sudo apt-get upgrade", nil

	case "fedora":
		// `dnf check-update` exits 100 when updates exist, 0 when none do.
		// --assumeno keeps it from stopping on a repository key it would
		// otherwise offer to import.
		out, preview, dnfErr := r.read(ctx, c, "dnf", "check-update", "-q", "--assumeno")
		pending = ParseDnfUpdates(out)
		if dnfErr != nil && len(pending) == 0 && strings.Contains(out, "Error") {
			return nil, "", dnfErr
		}
		judgeCount(c, preview, pending)
		return pending, "sudo dnf upgrade", nil
	}
	return nil, "", fmt.Errorf("host: no update command for %q", family)
}

// judgeCount records the count a pending-updates verdict rests on.
func judgeCount(c *collector, preview string, pending []string) {
	c.judged(preview, fmt.Sprintf("%d package(s) listed", len(pending)))
}

// rebootNeeded asks whether the running kernel and libraries are the installed
// ones, in whichever way this distribution answers that.
func (r *Real) rebootNeeded(ctx context.Context, c *collector,
	family string) (bool, string) {
	switch family {
	case "debian":
		if _, err := os.Stat("/var/run/reboot-required"); err == nil {
			return true, "/var/run/reboot-required exists"
		}
		return false, "/var/run/reboot-required does not exist"

	case "fedora":
		if !r.available("needs-restarting") {
			return false, "needs-restarting is not installed (dnf-utils)"
		}
		out, preview, err := r.read(ctx, c, "needs-restarting", "-r")
		// It exits 1 when a reboot is needed, which is the answer, not a
		// failure to answer.
		needed := err != nil || strings.Contains(out, "Reboot is required")
		c.judged(preview, firstLine(out))
		return needed, "from `needs-restarting -r`"

	case "arch":
		out, preview, err := r.read(ctx, c, "pacman", "-Q", "linux")
		if err != nil {
			return false, ""
		}
		installed := strings.TrimSpace(out)
		running := kernel()
		c.judged(preview, installed+" vs running "+running)
		fields := strings.Fields(installed)
		if len(fields) < 2 {
			return false, ""
		}
		// pacman's version is 6.16.3.arch1-1 and uname's is 6.16.3-arch1-1:
		// comparing the digits of the leading release is enough to catch a
		// kernel that was replaced under a running system.
		return !strings.HasPrefix(running, versionPrefix(fields[1])),
			"the installed kernel is " + fields[1] + ", running " + running
	}
	return false, ""
}

// versionPrefix is the dotted numeric head of a package version, which is the
// part a running kernel release starts with.
func versionPrefix(version string) string {
	for i, r := range version {
		if (r < '0' || r > '9') && r != '.' {
			return strings.TrimSuffix(version[:i], ".")
		}
	}
	return version
}

// updateTimers names the unit that applies updates unattended on each family,
// in the order they are looked for.
var updateTimers = map[string][]string{
	"arch":   {"omarchy-server-update.timer"},
	"debian": {"unattended-upgrades.service", "apt-daily-upgrade.timer"},
	"fedora": {"dnf-automatic.timer", "dnf5-automatic.timer"},
}

// updateTimer reports which unattended update unit this machine has, and
// whether it is enabled. An empty name means none of the candidates exists.
func (r *Real) updateTimer(ctx context.Context, c *collector,
	family string) (unit, state string) {
	for _, candidate := range updateTimers[family] {
		out, preview, err := r.read(ctx, c, "systemctl", "is-enabled", candidate)
		state = strings.TrimSpace(firstLine(out))
		if state == "" {
			continue
		}
		if err != nil && state == "not-found" {
			continue
		}
		c.judged(preview, candidate+": "+state)
		return candidate, state
	}
	return "", ""
}

// probeAccounts asks who can become root on this machine, and how easily.
func (r *Real) probeAccounts(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbeAccounts, Title: titleFor(posture.ProbeAccounts),
	}
	probe.Fix.Tool = "tui-users (planned)"
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	statuses := []posture.Status{posture.StatusOK}

	// /etc/passwd is world-readable everywhere, so this one always answers.
	roots, passwdErr := rootAccounts()
	switch {
	case passwdErr != nil:
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "UID 0 accounts", Value: "unknown", Status: posture.StatusUnknown,
			Note: reason(passwdErr)})
		statuses = append(statuses, posture.StatusUnknown)
	case len(roots) > 1:
		statuses = append(statuses, posture.StatusBad)
		c.record("awk -F: '$3==0' /etc/passwd", strings.Join(roots, "\n"))
		c.judged("awk -F: '$3==0' /etc/passwd", strings.Join(roots, " "))
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "UID 0 accounts", Value: strings.Join(roots, " "),
			Status: posture.StatusBad,
			Note:   "a second account with UID 0 is a second root under another name"})
	default:
		c.record("awk -F: '$3==0' /etc/passwd", strings.Join(roots, "\n"))
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "UID 0 accounts", Value: strings.Join(roots, " "),
			Status: posture.StatusOK})
	}

	// /etc/shadow needs root. Without it the question stays open rather than
	// being answered optimistically.
	empty, shadowErr := r.emptyPasswords(ctx, c)
	switch {
	case shadowErr != nil:
		statuses = append(statuses, posture.StatusUnknown)
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "empty passwords", Value: "unknown",
			Status: posture.StatusUnknown, Note: reason(shadowErr)})
	case len(empty) > 0:
		statuses = append(statuses, posture.StatusBad)
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "empty passwords", Value: strings.Join(empty, " "),
			Status: posture.StatusBad,
			Note:   "these accounts can be logged into with no password at all"})
	default:
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "empty passwords", Value: "none", Status: posture.StatusOK})
	}

	// `sudo -n -l` answers for this user only, which is the honest scope: a
	// tool that read every user's sudo rights would have to read the whole
	// sudoers tree as root.
	nopasswd, sudoErr := r.sudoNoPasswd(ctx, c)
	switch {
	case sudoErr != nil:
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "NOPASSWD (this user)", Value: "unknown",
			Status: posture.StatusUnknown, Note: reason(sudoErr)})
	case len(nopasswd) > 0:
		statuses = append(statuses, posture.StatusWarn)
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "NOPASSWD (this user)", Value: strconv.Itoa(len(nopasswd)) + " entry(ies)",
			Status: posture.StatusWarn, Note: firstLine(strings.Join(nopasswd, "; "))})
	default:
		probe.Findings = append(probe.Findings, posture.Finding{
			Label: "NOPASSWD (this user)", Value: "none", Status: posture.StatusOK})
	}

	probe.Status = posture.Worst(statuses...)
	switch probe.Status {
	case posture.StatusBad:
		probe.Summary = "an account can reach root without proving who it is"
		probe.Fix.Hint = "Remove the second UID 0 account, or lock the accounts " +
			"with no password."
	case posture.StatusWarn:
		probe.Summary = "sudo runs without a password for this user"
		probe.Fix.Hint = "Drop the NOPASSWD entries you do not need from " +
			"/etc/sudoers.d; anything left is a shell away from root."
	case posture.StatusUnknown:
		probe.Summary = "one account check needs a root this process does not have"
	default:
		probe.Summary = "one root account, no empty passwords, sudo asks"
	}
	return probe
}

// rootAccounts lists the accounts with UID 0.
func rootAccounts() ([]string, error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	return ParsePasswdRootAccounts(string(raw)), nil
}

// emptyPasswords lists the accounts whose password field is empty, escalating
// to read /etc/shadow because there is no unprivileged way to see it.
func (r *Real) emptyPasswords(ctx context.Context, c *collector) ([]string, error) {
	if raw, err := os.ReadFile("/etc/shadow"); err == nil {
		c.record("cat /etc/shadow", "(read directly; not shown)")
		return ParseShadowEmptyPasswords(string(raw)), nil
	}
	out, preview, err := r.readPrivileged(ctx, c, "cat", "/etc/shadow")
	if err != nil {
		return nil, err
	}
	users := ParseShadowEmptyPasswords(out)
	// The hashes are not something to leave on a screen or in --check output,
	// so the raw block keeps the verdict and drops the file.
	c.raw.Reset()
	c.record(preview, fmt.Sprintf(
		"(%d accounts read; hashes withheld) %d with an empty password",
		len(splitLines(out)), len(users)))
	if len(users) > 0 {
		c.judged(preview, "empty password: "+strings.Join(users, " "))
	}
	return users, nil
}

// sudoNoPasswd lists this user's NOPASSWD sudo rules.
func (r *Real) sudoNoPasswd(ctx context.Context, c *collector) ([]string, error) {
	// The argv is `sudo -n -l` in full: this is sudo asking about itself, not
	// a command run through sudo, so the runner's escalation prefix would put
	// a second sudo in front of it.
	out, preview, err := r.read(ctx, c, "sudo", "-n", "-l")
	if err != nil {
		return nil, err
	}
	entries := ParseSudoNoPasswd(out)
	if len(entries) > 0 {
		c.judged(preview, entries[0])
	}
	return entries, nil
}

// probeKernel asks whether the kernel hardening basics are set, and what
// happens to a crashing process's memory.
func (r *Real) probeKernel(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbeKernel, Title: titleFor(posture.ProbeKernel),
	}
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	statuses := []posture.Status{posture.StatusOK}
	weak := 0
	for _, key := range HardeningKeys {
		out, preview, err := r.read(ctx, c, "sysctl", "-n", key.Key)
		value := strings.TrimSpace(firstLine(out))
		if err != nil || value == "" {
			probe.Findings = append(probe.Findings, posture.Finding{
				Label: key.Key, Value: "unknown", Status: posture.StatusUnknown,
				Note: reason(err)})
			continue
		}
		ok := key.Satisfied(value)
		status := posture.StatusOK
		if !ok {
			status = posture.StatusWarn
			statuses = append(statuses, status)
			weak++
			c.judged(preview, key.Key+" = "+value)
			if key.Fixable {
				probe.Actions = append(probe.Actions, posture.Action{
					ID:    ActionSysctl + ":" + key.Key,
					Label: fmt.Sprintf("Set %s=%s, now and on every boot", key.Key, key.Want),
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
	return probe
}

// probePorts asks what is listening, and which of it is reachable from another
// machine.
func (r *Real) probePorts(ctx context.Context) posture.Probe {
	c := &collector{}
	probe := posture.Probe{
		ID: posture.ProbePorts, Title: titleFor(posture.ProbePorts),
	}
	probe.Fix.Tool = "tui-firewall"
	defer func() { probe.Evidence, probe.Raw = c.evidence, c.raw.String() }()

	// The escalated read is tried first only because it can name the process
	// behind every socket; the unprivileged one sees the same sockets and only
	// its own processes.
	out, preview, err := r.readPrivileged(ctx, c, "ss", "-tulpnH")
	if err != nil {
		out, preview, err = r.read(ctx, c, "ss", "-tulpnH")
	}
	if err != nil {
		probe.Status = posture.StatusUnknown
		probe.Summary = "could not list the listening sockets"
		probe.Reason = reason(err)
		return probe
	}

	listeners := ParseSS(out)
	global := 0
	for _, listener := range listeners {
		if listener.Global {
			global++
		}
	}
	if global > 0 {
		c.judged(preview, firstGlobal(listeners))
		probe.Status = posture.StatusWarn
		probe.Summary = fmt.Sprintf(
			"%d listening socket(s), %d reachable from the network",
			len(listeners), global)
		probe.Fix.Hint = "Bind what does not need the network to localhost, and " +
			"let the firewall decide about the rest."
	} else {
		probe.Status = posture.StatusOK
		probe.Summary = fmt.Sprintf(
			"%d listening socket(s), all on loopback", len(listeners))
	}

	for _, listener := range listeners {
		if !listener.Global {
			continue
		}
		probe.Findings = append(probe.Findings, posture.Finding{
			Label:  listener.Proto + " " + listener.Address + ":" + listener.Port,
			Value:  orUnknown(listener.Process),
			Status: posture.StatusWarn,
		})
	}
	return probe
}

// firstGlobal is the first network-reachable socket, as evidence.
func firstGlobal(listeners []Listener) string {
	for _, listener := range listeners {
		if listener.Global {
			return listener.Line
		}
	}
	return ""
}

// unitActive reports whether a systemd unit is running.
func (r *Real) unitActive(ctx context.Context, c *collector, unit string) bool {
	out, _, err := r.read(ctx, c, "systemctl", "is-active", unit)
	return err == nil && strings.TrimSpace(out) == "active"
}

// boolStatus maps a yes/no answer onto a verdict.
func boolStatus(good bool) posture.Status {
	if good {
		return posture.StatusOK
	}
	return posture.StatusWarn
}

// policyStatus grades a firewall default policy.
func policyStatus(policy string) posture.Status {
	switch policy {
	case "deny", "reject":
		return posture.StatusOK
	case "":
		return posture.StatusUnknown
	default:
		return posture.StatusWarn
	}
}

// yesNo picks one of two words.
func yesNo(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

// orUnknown renders an empty value as a visible placeholder, so a blank is
// never mistaken for a value that was read.
func orUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "—"
	}
	return value
}

// firstN keeps a list short enough for one line.
func firstN(values []string, n int) []string {
	if len(values) <= n {
		return values
	}
	return append(append([]string{}, values[:n]...),
		fmt.Sprintf("… +%d", len(values)-n))
}

// firstLine keeps a value to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
