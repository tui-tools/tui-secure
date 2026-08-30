package host

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file is the whole translation layer between what the system's tools
// print and what tui-secure judges. Every function here is pure: it takes the
// text of one command and returns a struct. That is what makes the verdicts
// testable against captured output from real machines (see testdata), and it
// is why nothing in this file knows how to start a process.

// BootInfo is what `bootctl status` says about the firmware's trust in what it
// booted.
type BootInfo struct {
	// SecureBoot is systemd's own wording: "enabled (deployed)", "disabled".
	SecureBoot string
	// SetupMode is "setup" when the firmware will accept new keys from
	// anybody, "user" once keys are enrolled. Empty when bootctl did not say.
	SetupMode string
	// TPM2 is the TPM2 support line, reported but not judged.
	TPM2 string
	// EFI reports whether the machine booted through EFI at all. A BIOS
	// machine has no Secure Boot to have an opinion about.
	EFI bool
	// SecureBootLine is the line the verdict rests on.
	SecureBootLine string
}

// Enabled reports whether Secure Boot is on, whatever qualifier systemd added.
func (b BootInfo) Enabled() bool {
	return strings.HasPrefix(strings.ToLower(b.SecureBoot), "enabled")
}

// InSetupMode reports whether the firmware is still accepting keys.
func (b BootInfo) InSetupMode() bool {
	return strings.Contains(strings.ToLower(b.SetupMode), "setup") ||
		strings.Contains(strings.ToLower(b.SecureBoot), "setup")
}

// ParseBootctl reads `bootctl status`.
//
// The command prints permission errors for the ESP when run unprivileged and
// still reports the System block, which is the part that matters here: Secure
// Boot is read from an EFI variable that any user can read.
func ParseBootctl(out string) BootInfo {
	info := BootInfo{}
	for _, line := range splitLines(out) {
		key, value, ok := keyValue(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "secure boot":
			info.SecureBoot, info.SecureBootLine = value, strings.TrimSpace(line)
			info.EFI = true
		case "setup mode":
			info.SetupMode = value
		case "tpm2 support":
			info.TPM2 = value
		case "firmware arch", "firmware":
			info.EFI = true
		}
	}
	if strings.Contains(out, "not booted with EFI") {
		info.EFI = false
	}
	return info
}

// SbctlInfo is what `sbctl status` adds when sbctl manages the machine's keys:
// whether its own keys are installed, and whether the firmware is in setup
// mode. sbctl marks each answer with ✓ or ✗.
type SbctlInfo struct {
	Installed  bool
	SecureBoot bool
	SetupMode  bool
	// Lines are the status lines, kept as evidence.
	Lines []string
}

// ParseSbctlStatus reads `sbctl status`.
func ParseSbctlStatus(out string) SbctlInfo {
	info := SbctlInfo{}
	for _, line := range splitLines(out) {
		key, value, ok := keyValue(line)
		if !ok {
			continue
		}
		positive := strings.Contains(value, "✓") ||
			strings.Contains(strings.ToLower(value), "enabled") ||
			strings.Contains(strings.ToLower(value), "installed")
		switch strings.ToLower(key) {
		case "installed":
			info.Installed = positive
			info.Lines = append(info.Lines, strings.TrimSpace(line))
		case "secure boot":
			info.SecureBoot = positive
			info.Lines = append(info.Lines, strings.TrimSpace(line))
		case "setup mode":
			// sbctl phrases this one the other way round: "✓ Disabled" is the
			// good answer, so a positive mark means *not* in setup mode.
			info.SetupMode = strings.Contains(strings.ToLower(value), "enabled")
			info.Lines = append(info.Lines, strings.TrimSpace(line))
		}
	}
	return info
}

// SELinuxInfo is the SELinux half of the MAC probe.
type SELinuxInfo struct {
	// Enforce is what `getenforce` printed: "Enforcing", "Permissive",
	// "Disabled".
	Enforce string
	// Status is sestatus's "SELinux status" line ("enabled", "disabled").
	Status string
	// Policy is the loaded policy name, when sestatus reported one.
	Policy string
}

// ParseSestatus reads `sestatus`.
func ParseSestatus(out string) SELinuxInfo {
	info := SELinuxInfo{}
	for _, line := range splitLines(out) {
		key, value, ok := keyValue(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "selinux status":
			info.Status = value
		case "current mode":
			info.Enforce = value
		case "loaded policy name":
			info.Policy = value
		}
	}
	return info
}

// AppArmorInfo is the AppArmor half of the MAC probe: how many profiles are
// loaded, and in which mode.
type AppArmorInfo struct {
	Enforce    int
	Complain   int
	Kill       int
	Unconfined int
	// Total is every profile, whatever its mode.
	Total int
}

// aaStatus mirrors the part of `aa-status --json` this tool reads. The rest of
// the document (processes, per-profile detail) is deliberately ignored.
type aaStatus struct {
	Profiles map[string]string `json:"profiles"`
}

// ParseAAStatusJSON reads `aa-status --json`, counting the profiles by mode.
func ParseAAStatusJSON(out string) (AppArmorInfo, error) {
	var doc aaStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &doc); err != nil {
		return AppArmorInfo{}, err
	}
	info := AppArmorInfo{Total: len(doc.Profiles)}
	for _, mode := range doc.Profiles {
		switch strings.ToLower(mode) {
		case "enforce":
			info.Enforce++
		case "complain":
			info.Complain++
		case "kill":
			info.Kill++
		case "unconfined":
			info.Unconfined++
		}
	}
	return info, nil
}

// UfwStatus is what `ufw status verbose` says.
type UfwStatus struct {
	Active bool
	// Incoming, Outgoing and Routed are the default policies, empty on a ufw
	// too old to print the Default line.
	Incoming string
	Outgoing string
	Routed   string
	// Rules is how many rules the table lists.
	Rules int
	// StatusLine is the line the verdict rests on.
	StatusLine string
}

// ParseUfwStatus reads `ufw status verbose`.
func ParseUfwStatus(out string) UfwStatus {
	status := UfwStatus{}
	inTable := false
	for _, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Status:"):
			status.StatusLine = trimmed
			// Not a substring test: "inactive" contains "active".
			status.Active = strings.EqualFold(
				strings.TrimSpace(strings.TrimPrefix(trimmed, "Status:")), "active")
		case strings.HasPrefix(trimmed, "Default:"):
			status.Incoming, status.Outgoing, status.Routed =
				parseUfwDefaults(strings.TrimPrefix(trimmed, "Default:"))
		case strings.HasPrefix(trimmed, "--"):
			inTable = true
		case inTable && trimmed != "":
			status.Rules++
		}
	}
	return status
}

// parseUfwDefaults splits "deny (incoming), allow (outgoing), disabled
// (routed)" into its three policies, keyed by the direction in the brackets so
// the order ufw prints them in does not matter.
func parseUfwDefaults(value string) (incoming, outgoing, routed string) {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		open := strings.IndexByte(part, '(')
		if open < 0 {
			continue
		}
		policy := strings.TrimSpace(part[:open])
		direction := strings.Trim(part[open:], "()")
		switch direction {
		case "incoming":
			incoming = policy
		case "outgoing":
			outgoing = policy
		case "routed":
			routed = policy
		}
	}
	return incoming, outgoing, routed
}

// FirewalldZone is what `firewall-cmd --list-all` says about the default zone.
type FirewalldZone struct {
	Name string
	// Target is the zone's default action ("default", "ACCEPT", "DROP").
	Target string
	// Services and Ports are what the zone lets through.
	Services []string
	Ports    []string
}

// ParseFirewalldZone reads `firewall-cmd --list-all`.
func ParseFirewalldZone(out string) FirewalldZone {
	zone := FirewalldZone{}
	for i, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		if i == 0 && trimmed != "" && !strings.Contains(trimmed, ":") {
			// The first line names the zone: "FedoraWorkstation (default,
			// active)".
			zone.Name = strings.Fields(trimmed)[0]
			continue
		}
		key, value, ok := keyValue(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "target":
			zone.Target = value
		case "services":
			zone.Services = strings.Fields(value)
		case "ports":
			zone.Ports = strings.Fields(value)
		}
	}
	return zone
}

// ParseNftRuleCount counts the rules in an `nft list ruleset` dump. It is a
// crude measure on purpose: the probe only asks whether the machine has a
// ruleset at all, and counting rules is the cheapest honest answer.
func ParseNftRuleCount(out string) int {
	count := 0
	for _, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "table ") ||
			strings.HasPrefix(trimmed, "chain ") ||
			trimmed == "}" || strings.HasPrefix(trimmed, "type ") {
			continue
		}
		count++
	}
	return count
}

// ParseSSHDConfig reads the settings out of `sshd -T`, which prints every
// effective keyword, lower-cased, one per line.
//
// It also parses a plain sshd_config, which is the fallback when sshd -T needs
// a root this process does not have: the syntax is the same, minus the
// comments. Settings inside a Match block are skipped, because they apply
// conditionally and reporting them as the machine's answer would be wrong.
// The first occurrence of a keyword wins, which is how sshd itself resolves a
// keyword given twice.
func ParseSSHDConfig(out string) map[string]string {
	settings := map[string]string{}
	for _, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		key := strings.ToLower(fields[0])
		if key == "match" {
			break
		}
		value := ""
		if len(fields) > 1 {
			value = strings.TrimSpace(strings.Join(fields[1:], " "))
		}
		if _, seen := settings[key]; !seen {
			settings[key] = value
		}
	}
	return settings
}

// Listener is one socket something is listening on.
type Listener struct {
	// Proto is "tcp" or "udp".
	Proto string
	// Address is the local address as ss printed it.
	Address string
	// Port is the local port.
	Port string
	// Process is the process name ss attributed it to, empty when ss could
	// not see it — which is what an unprivileged read gets for other users'
	// sockets.
	Process string
	// Global reports that the socket is reachable from outside this machine:
	// it is not bound to a loopback address.
	Global bool
	// Line is the raw ss line, kept as evidence.
	Line string
}

// ParseSS reads `ss -tulpnH`: no header, so every line is a socket.
func ParseSS(out string) []Listener {
	var listeners []Listener
	for _, line := range splitLines(out) {
		fields := strings.Fields(line)
		// netid state recv-q send-q local peer [process]
		if len(fields) < 5 {
			continue
		}
		local := fields[4]
		address, port := splitAddressPort(local)
		listener := Listener{
			Proto:   fields[0],
			Address: address,
			Port:    port,
			Global:  globalAddress(address),
			Line:    strings.Join(fields, " "),
		}
		if len(fields) >= 7 {
			listener.Process = processName(fields[6])
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

// splitAddressPort splits ss's "address:port", which is not a simple last-colon
// split: an IPv6 address is bracketed, and an interface-scoped wildcard is
// written "0.0.0.0%virbr0:67".
func splitAddressPort(local string) (address, port string) {
	i := strings.LastIndexByte(local, ':')
	if i < 0 {
		return local, ""
	}
	address, port = local[:i], local[i+1:]
	address = strings.Trim(address, "[]")
	if scope := strings.IndexByte(address, '%'); scope >= 0 {
		address = address[:scope]
	}
	return address, port
}

// globalAddress reports whether a listening address can be reached from
// another machine.
func globalAddress(address string) bool {
	switch address {
	case "127.0.0.1", "::1", "localhost":
		return false
	}
	return !strings.HasPrefix(address, "127.")
}

// processName pulls the program name out of ss's users:(("sshd",pid=1,fd=3))
// field.
func processName(field string) string {
	start := strings.IndexByte(field, '"')
	if start < 0 {
		return ""
	}
	rest := field[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// ParsePacmanUpdates counts the lines of `checkupdates` or `pacman -Qu`, which
// print one package per line as "name old -> new".
func ParsePacmanUpdates(out string) []string {
	var packages []string
	for _, line := range splitLines(out) {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(line, "->") {
			continue
		}
		packages = append(packages, fields[0])
	}
	return packages
}

// ParseAptUpdates counts the "Inst" lines of `apt-get -s upgrade`, which is the
// simulation of the upgrade rather than a claim about the cache.
func ParseAptUpdates(out string) []string {
	var packages []string
	for _, line := range splitLines(out) {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			packages = append(packages, fields[1])
		}
	}
	return packages
}

// ParseDnfUpdates reads `dnf check-update -q`, whose body is one package per
// line as "name.arch version repo". The obsoletes section at the end is
// skipped: an obsoleted package is not an update to install.
func ParseDnfUpdates(out string) []string {
	var packages []string
	for _, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Obsoleting") ||
			strings.HasPrefix(trimmed, "Last metadata") ||
			strings.HasPrefix(trimmed, "Security:") {
			break
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || !strings.Contains(fields[0], ".") {
			continue
		}
		packages = append(packages, fields[0])
	}
	return packages
}

// ParsePasswdRootAccounts returns every account in /etc/passwd whose UID is 0.
// More than one is a second root under another name, which is the finding.
func ParsePasswdRootAccounts(text string) []string {
	var users []string
	for _, line := range splitLines(text) {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if uid, err := strconv.Atoi(fields[2]); err == nil && uid == 0 {
			users = append(users, fields[0])
		}
	}
	return users
}

// ParseShadowEmptyPasswords returns every account in /etc/shadow whose password
// field is empty, meaning it can be logged into with no password at all. A
// locked account ("!" or "*") is not empty and is not reported.
func ParseShadowEmptyPasswords(text string) []string {
	var users []string
	for _, line := range splitLines(text) {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if strings.TrimSpace(fields[1]) == "" {
			users = append(users, fields[0])
		}
	}
	return users
}

// ParseSudoNoPasswd returns the NOPASSWD entries `sudo -n -l` reported for the
// current user. Each one is a command this account can run as root without
// proving who it is.
func ParseSudoNoPasswd(out string) []string {
	var entries []string
	for _, line := range splitLines(out) {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "NOPASSWD") {
			continue
		}
		entries = append(entries, trimmed)
	}
	return entries
}

// CountMatches counts the lines containing a needle, which is how the journal
// reads — denials, failed logins — are turned into a number.
func CountMatches(out, needle string) int {
	count := 0
	lower := strings.ToLower(needle)
	for _, line := range splitLines(out) {
		if strings.Contains(strings.ToLower(line), lower) {
			count++
		}
	}
	return count
}

// keyValue splits a "Key: value" line, which is the shape almost every tool
// here prints. It returns ok=false for a line that is not one.
func keyValue(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, ':')
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// splitLines splits text into lines, dropping the empty element a trailing
// newline produces.
func splitLines(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}
