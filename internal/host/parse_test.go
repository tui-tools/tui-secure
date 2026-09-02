package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parsers are fed captured output rather than strings written next to the
// assertion. Half the fixtures come off a real Fedora 42 machine (the ones
// named after it) and half are written to match what the tool prints on a
// distribution this developer's machine is not — an Ubuntu with ufw and
// AppArmor, an Arch with checkupdates, a machine whose sshd still takes
// passwords. A parser is only worth anything against output nobody tidied.

// fixture reads a captured output file.
func fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the test above, and testdata is in the repository
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return string(raw)
}

func TestParseBootctlFedora(t *testing.T) {
	info := ParseBootctl(fixture(t, "bootctl-status-fedora42.txt"))
	if !info.EFI {
		t.Error("a machine that printed a Firmware Arch booted through EFI")
	}
	if !info.Enabled() {
		t.Errorf("Secure Boot = %q, want it read as enabled", info.SecureBoot)
	}
	if info.InSetupMode() {
		t.Error("`enabled (deployed)` is not setup mode")
	}
	if info.TPM2 != "yes" {
		t.Errorf("TPM2 = %q", info.TPM2)
	}
	if !strings.Contains(info.SecureBootLine, "Secure Boot") {
		t.Errorf("the evidence line is %q", info.SecureBootLine)
	}
}

func TestParseBootctlSetupMode(t *testing.T) {
	info := ParseBootctl("System:\n   Secure Boot: disabled\n    Setup Mode: setup\n")
	if info.Enabled() {
		t.Error("disabled must not read as enabled")
	}
	if !info.InSetupMode() {
		t.Error("setup mode must be detected")
	}
}

func TestParseBootctlNoEFI(t *testing.T) {
	info := ParseBootctl("System:\n      Firmware: n/a\nnot booted with EFI\n")
	if info.EFI {
		t.Error("a machine that says it did not boot with EFI has no Secure Boot")
	}
}

func TestParseSbctlStatus(t *testing.T) {
	info := ParseSbctlStatus(fixture(t, "sbctl-status.txt"))
	if !info.Installed {
		t.Error("sbctl reported its keys as installed")
	}
	if !info.SecureBoot {
		t.Error("sbctl reported Secure Boot as enabled")
	}
	if info.SetupMode {
		t.Error("sbctl's `✗ Disabled` for setup mode means not in setup mode")
	}
}

func TestParseSestatus(t *testing.T) {
	enforcing := ParseSestatus(fixture(t, "sestatus-enforcing.txt"))
	if enforcing.Enforce != "enforcing" || enforcing.Policy != "targeted" {
		t.Errorf("enforcing fixture parsed as %+v", enforcing)
	}
	disabled := ParseSestatus(fixture(t, "sestatus-fedora42.txt"))
	if disabled.Status != "disabled" {
		t.Errorf("a disabled machine parsed as %+v", disabled)
	}
}

func TestParseAAStatusJSON(t *testing.T) {
	info, err := ParseAAStatusJSON(fixture(t, "aa-status.json"))
	if err != nil {
		t.Fatalf("ParseAAStatusJSON: %v", err)
	}
	if info.Enforce != 3 || info.Complain != 1 || info.Unconfined != 1 {
		t.Errorf("counts = %+v", info)
	}
	if info.Total != 5 {
		t.Errorf("total = %d, want every profile counted", info.Total)
	}

	complain, err := ParseAAStatusJSON(fixture(t, "aa-status-complain.json"))
	if err != nil {
		t.Fatalf("ParseAAStatusJSON: %v", err)
	}
	if complain.Enforce != 0 || complain.Complain != 2 {
		t.Errorf("a complain-only machine parsed as %+v", complain)
	}

	if _, err := ParseAAStatusJSON("aa-status: not installed"); err == nil {
		t.Error("text that is not JSON must be an error, not an empty count")
	}
}

func TestParseUfwStatus(t *testing.T) {
	active := ParseUfwStatus(fixture(t, "ufw-status-verbose.txt"))
	if !active.Active {
		t.Error("the fixture says active")
	}
	if active.Incoming != "deny" || active.Outgoing != "allow" {
		t.Errorf("defaults = %+v", active)
	}
	if active.Rules != 4 {
		t.Errorf("rules = %d, want the four rows under the header", active.Rules)
	}

	inactive := ParseUfwStatus(fixture(t, "ufw-status-inactive.txt"))
	if inactive.Active || inactive.Rules != 0 {
		t.Errorf("inactive fixture parsed as %+v", inactive)
	}

	open := ParseUfwStatus(fixture(t, "ufw-status-allow-incoming.txt"))
	if open.Incoming != "allow" {
		t.Errorf("incoming = %q, want allow", open.Incoming)
	}
}

func TestParseFirewalldZone(t *testing.T) {
	zone := ParseFirewalldZone(fixture(t, "firewalld-list-all-fedora42.txt"))
	if zone.Name != "FedoraWorkstation" {
		t.Errorf("zone = %q", zone.Name)
	}
	if len(zone.Services) != 4 {
		t.Errorf("services = %v", zone.Services)
	}
	if len(zone.Ports) != 2 {
		t.Errorf("ports = %v, want the two ranges this zone opens", zone.Ports)
	}
}

func TestParseNftRuleCount(t *testing.T) {
	// Four rules: the three in input and none in forward, plus the policy
	// lines which are not counted.
	if got := ParseNftRuleCount(fixture(t, "nft-ruleset.txt")); got != 3 {
		t.Errorf("rules = %d, want 3", got)
	}
	if got := ParseNftRuleCount(""); got != 0 {
		t.Errorf("an empty ruleset counts %d rules", got)
	}
}

func TestParseSSHDConfigFromSSHDT(t *testing.T) {
	settings := ParseSSHDConfig(fixture(t, "sshd-t.txt"))
	for key, want := range map[string]string{
		"port":                   "22",
		"permitrootlogin":        "yes",
		"passwordauthentication": "yes",
		"pubkeyauthentication":   "yes",
		"maxauthtries":           "10",
		"x11forwarding":          "yes",
	} {
		if settings[key] != want {
			t.Errorf("%s = %q, want %q", key, settings[key], want)
		}
	}
}

// TestParseSSHDConfigStopsAtMatch: a setting inside a Match block applies to
// some connections and not others, so reporting it as the machine's answer
// would be wrong.
func TestParseSSHDConfigStopsAtMatch(t *testing.T) {
	settings := ParseSSHDConfig(fixture(t, "sshd-config-hardened.txt"))
	if settings["passwordauthentication"] != "no" {
		t.Errorf("passwordauthentication = %q, want the global no rather than "+
			"the Match block's yes", settings["passwordauthentication"])
	}
	if settings["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin = %q", settings["permitrootlogin"])
	}
	if settings["maxauthtries"] != "3" {
		t.Errorf("maxauthtries = %q", settings["maxauthtries"])
	}
}

// TestParseSSHDConfigFirstWins is how sshd itself resolves a keyword given
// twice.
func TestParseSSHDConfigFirstWins(t *testing.T) {
	settings := ParseSSHDConfig("PermitRootLogin no\nPermitRootLogin yes\n")
	if settings["permitrootlogin"] != "no" {
		t.Errorf("permitrootlogin = %q, want the first value",
			settings["permitrootlogin"])
	}
}

func TestParseSS(t *testing.T) {
	listeners := ParseSS(fixture(t, "ss-fedora42.txt"))
	if len(listeners) != 30 {
		t.Fatalf("parsed %d sockets, want the 30 lines of the fixture",
			len(listeners))
	}
	loopback, global, named := 0, 0, 0
	for _, listener := range listeners {
		if listener.Global {
			global++
		} else {
			loopback++
		}
		if listener.Process != "" {
			named++
		}
	}
	if loopback == 0 || global == 0 {
		t.Errorf("the fixture has both kinds: %d loopback, %d global",
			loopback, global)
	}
	if named == 0 {
		t.Error("the process column was not read")
	}
}

func TestParseSSAddresses(t *testing.T) {
	out := `tcp LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=1,fd=5))
tcp LISTEN 0 4096 [::1]:631 [::]:* users:(("cupsd",pid=2,fd=8))
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=3))
udp UNCONN 0 0 0.0.0.0%virbr0:67 0.0.0.0:*`
	listeners := ParseSS(out)
	if len(listeners) != 4 {
		t.Fatalf("parsed %d sockets", len(listeners))
	}
	if listeners[0].Global || listeners[1].Global {
		t.Error("127.0.0.1 and ::1 are not reachable from another machine")
	}
	if !listeners[2].Global || listeners[2].Process != "sshd" {
		t.Errorf("0.0.0.0:22 parsed as %+v", listeners[2])
	}
	if listeners[3].Address != "0.0.0.0" || listeners[3].Port != "67" {
		t.Errorf("an interface-scoped wildcard parsed as %+v", listeners[3])
	}
}

// TestParseSSMappedAddresses: a dual-stack socket bound to loopback is printed
// in IPv4-mapped form, and reading it as global would tell the operator a
// local-only port is exposed. The mapping itself says nothing about reach, so
// a mapped routable address is still global.
func TestParseSSMappedAddresses(t *testing.T) {
	out := `tcp LISTEN 0 4096 [::ffff:127.0.0.1]:8080 [::]:* users:(("java",pid=4,fd=9))
tcp LISTEN 0 4096 [::ffff:10.0.0.5]:8443 [::]:* users:(("java",pid=4,fd=10))`
	listeners := ParseSS(out)
	if len(listeners) != 2 {
		t.Fatalf("parsed %d sockets", len(listeners))
	}
	if listeners[0].Address != "::ffff:127.0.0.1" || listeners[0].Global {
		t.Errorf("an IPv4-mapped loopback socket parsed as %+v", listeners[0])
	}
	if listeners[1].Address != "::ffff:10.0.0.5" || !listeners[1].Global {
		t.Errorf("an IPv4-mapped routable socket parsed as %+v", listeners[1])
	}
}

func TestParseUpdates(t *testing.T) {
	pacman := ParsePacmanUpdates(fixture(t, "checkupdates.txt"))
	if len(pacman) != 3 || pacman[1] != "linux" {
		t.Errorf("pacman updates = %v", pacman)
	}
	apt := ParseAptUpdates(fixture(t, "apt-get-s-upgrade.txt"))
	if len(apt) != 3 || apt[0] != "libssl3" {
		t.Errorf("apt updates = %v", apt)
	}
	dnf := ParseDnfUpdates(fixture(t, "dnf-check-update.txt"))
	if len(dnf) != 3 || dnf[1] != "kernel.x86_64" {
		t.Errorf("dnf updates = %v, want the three before the obsoletes", dnf)
	}
}

func TestParseAccounts(t *testing.T) {
	one := ParsePasswdRootAccounts(fixture(t, "passwd-fedora42.txt"))
	if len(one) != 1 || one[0] != "root" {
		t.Errorf("UID 0 accounts = %v", one)
	}
	two := ParsePasswdRootAccounts(fixture(t, "passwd-two-roots.txt"))
	if len(two) != 2 || two[1] != "backup" {
		t.Errorf("UID 0 accounts = %v, want root and the second one", two)
	}

	empty := ParseShadowEmptyPasswords(fixture(t, "shadow.txt"))
	if len(empty) != 1 || empty[0] != "guest" {
		t.Errorf("empty passwords = %v; `*` and `!` are locked, not empty", empty)
	}

	nopasswd := ParseSudoNoPasswd(fixture(t, "sudo-l.txt"))
	if len(nopasswd) != 1 || !strings.Contains(nopasswd[0], "NOPASSWD") {
		t.Errorf("NOPASSWD entries = %v", nopasswd)
	}
}

func TestCountMatches(t *testing.T) {
	if got := CountMatches(fixture(t, "journal-avc.txt"), "avc"); got != 3 {
		t.Errorf("denials = %d, want 3", got)
	}
	if got := CountMatches("-- No entries --", "avc"); got != 0 {
		t.Errorf("an empty journal counted %d denials", got)
	}
}
