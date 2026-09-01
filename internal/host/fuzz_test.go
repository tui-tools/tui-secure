package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The parsers in this file's package are the one place where output tui-secure
// did not write becomes a verdict about somebody's machine: `bootctl status`,
// `sshd -T`, `ss -tulpnH` and the rest arrive as bytes and leave as the answer
// a probe shows and the fix it then offers. `go test` runs the seeds below on
// every commit, and `go test -fuzz=FuzzParseSS ./internal/host` explores past
// them locally — see tui-kit/templates/FUZZING.md for the family rule.
//
// The seeds are the captured fixtures the table tests use, so the corpus
// starts on the real line shapes and mutates from there instead of guessing
// them.

// seed adds every named testdata file to the corpus, plus the shapes a real
// capture never has: nothing, blank lines, a truncated line.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // the name is a literal in the tests, and testdata is in the repository
		if err != nil {
			f.Fatalf("read fixture %s: %v", name, err)
		}
		f.Add(string(raw))
	}
	f.Add("")
	f.Add("\n\n\n")
	f.Add(":")
	f.Add("Status:")
}

// trimmed asserts that a field the UI prints is one line: what the parser
// hands back is put on screen beside a verdict, so surrounding space or an
// embedded newline would break the layout of a probe rather than one string.
// A stray control character inside the line is left alone on purpose — the
// evidence a probe shows is the line the command printed, verbatim.
func trimmed(t *testing.T, what, value string) {
	t.Helper()
	if strings.TrimSpace(value) != value {
		t.Fatalf("%s is not trimmed: %q", what, value)
	}
	if strings.Contains(value, "\n") {
		t.Fatalf("%s spans lines: %q", what, value)
	}
}

// checkNames asserts what every caller of a package list is allowed to assume:
// a bare name, taken from the input rather than assembled, and printable on
// one line.
func checkNames(t *testing.T, out string, names []string) {
	t.Helper()
	for _, name := range names {
		if name == "" {
			t.Fatalf("blank package name in %v", names)
		}
		if strings.ContainsAny(name, " \t\n") {
			t.Fatalf("package name carries whitespace: %q", name)
		}
		if !strings.Contains(out, name) {
			t.Fatalf("package name %q is not in the input", name)
		}
	}
}

func FuzzParseBootctl(f *testing.F) {
	seed(f, "bootctl-status-fedora42.txt")
	f.Fuzz(func(t *testing.T, out string) {
		info := ParseBootctl(out)
		trimmed(t, "secure boot", info.SecureBoot)
		trimmed(t, "setup mode", info.SetupMode)
		trimmed(t, "tpm2", info.TPM2)
		trimmed(t, "secure boot line", info.SecureBootLine)
		if info.SecureBootLine != "" && !strings.Contains(info.SecureBootLine, ":") {
			t.Fatalf("evidence line is not a key/value line: %q", info.SecureBootLine)
		}
		// Both are read by the probe on every input, so they belong here.
		_, _ = info.Enabled(), info.InSetupMode()
	})
}

func FuzzParseSbctlStatus(f *testing.F) {
	seed(f, "sbctl-status.txt")
	f.Fuzz(func(t *testing.T, out string) {
		info := ParseSbctlStatus(out)
		for _, line := range info.Lines {
			trimmed(t, "evidence line", line)
			if line == "" {
				t.Fatal("blank evidence line")
			}
			if !strings.Contains(out, line) {
				t.Fatalf("evidence line %q is not in the input", line)
			}
		}
	})
}

func FuzzParseSestatus(f *testing.F) {
	seed(f, "sestatus-enforcing.txt", "sestatus-fedora42.txt")
	f.Fuzz(func(t *testing.T, out string) {
		info := ParseSestatus(out)
		trimmed(t, "status", info.Status)
		trimmed(t, "mode", info.Enforce)
		trimmed(t, "policy", info.Policy)
	})
}

// FuzzParseAAStatusJSON is the one target here whose parser can fail, so it
// asserts the family's error rule: an error means the caller gets nothing to
// read, not a half-filled count.
func FuzzParseAAStatusJSON(f *testing.F) {
	seed(f, "aa-status.json", "aa-status-complain.json")
	f.Fuzz(func(t *testing.T, out string) {
		info, err := ParseAAStatusJSON(out)
		if err != nil {
			if info != (AppArmorInfo{}) {
				t.Fatalf("error returned with a non-zero result: %+v", info)
			}
			return
		}
		if info.Enforce < 0 || info.Complain < 0 || info.Kill < 0 ||
			info.Unconfined < 0 || info.Total < 0 {
			t.Fatalf("negative profile count: %+v", info)
		}
		if sum := info.Enforce + info.Complain + info.Kill + info.Unconfined; sum > info.Total {
			t.Fatalf("modes count %d profiles out of %d: %+v", sum, info.Total, info)
		}
	})
}

func FuzzParseUfwStatus(f *testing.F) {
	seed(f, "ufw-status-verbose.txt", "ufw-status-inactive.txt",
		"ufw-status-allow-incoming.txt")
	f.Fuzz(func(t *testing.T, out string) {
		status := ParseUfwStatus(out)
		trimmed(t, "status line", status.StatusLine)
		if status.Active && status.StatusLine == "" {
			t.Fatal("active with no line to show for it")
		}
		if status.StatusLine != "" && !strings.HasPrefix(status.StatusLine, "Status:") {
			t.Fatalf("evidence line is not the Status line: %q", status.StatusLine)
		}
		if status.Rules < 0 {
			t.Fatalf("negative rule count: %d", status.Rules)
		}
		// The three policies are printed as words beside the verdict.
		for what, policy := range map[string]string{
			"incoming": status.Incoming,
			"outgoing": status.Outgoing,
			"routed":   status.Routed,
		} {
			trimmed(t, what+" policy", policy)
		}
	})
}

func FuzzParseFirewalldZone(f *testing.F) {
	seed(f, "firewalld-list-all-fedora42.txt")
	f.Fuzz(func(t *testing.T, out string) {
		zone := ParseFirewalldZone(out)
		trimmed(t, "target", zone.Target)
		if strings.ContainsAny(zone.Name, " \t\n") {
			t.Fatalf("zone name is not a bare word: %q", zone.Name)
		}
		for _, entry := range append(append([]string{}, zone.Services...), zone.Ports...) {
			if entry == "" || strings.ContainsAny(entry, " \t\n") {
				t.Fatalf("zone entry is not a bare word: %q", entry)
			}
		}
	})
}

func FuzzParseNftRuleCount(f *testing.F) {
	seed(f, "nft-ruleset.txt")
	f.Fuzz(func(t *testing.T, out string) {
		count := ParseNftRuleCount(out)
		if count < 0 {
			t.Fatalf("negative rule count: %d", count)
		}
		if lines := strings.Count(out, "\n") + 1; count > lines {
			t.Fatalf("counted %d rules in %d lines", count, lines)
		}
	})
}

// FuzzParseSSHDConfig matters twice over: the settings it returns are what the
// sshd probe judges, and the same map is filled from a plain sshd_config when
// `sshd -T` needs a root the process does not have.
func FuzzParseSSHDConfig(f *testing.F) {
	seed(f, "sshd-t.txt", "sshd-config-hardened.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for key, value := range ParseSSHDConfig(out) {
			if key == "" || strings.ContainsAny(key, " \t\n") {
				t.Fatalf("keyword is not a bare word: %q", key)
			}
			if key != strings.ToLower(key) {
				t.Fatalf("keyword is not lower case: %q", key)
			}
			// A Match block ends the file as far as this parser is
			// concerned, so nothing conditional can reach a verdict.
			if key == "match" {
				t.Fatal("a Match block was read as a setting")
			}
			trimmed(t, "value of "+key, value)
		}
	})
}

func FuzzParseSS(f *testing.F) {
	seed(f, "ss-fedora42.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, l := range ParseSS(out) {
			if l.Proto == "" {
				t.Fatalf("listener with no protocol: %+v", l)
			}
			trimmed(t, "listener line", l.Line)
			if strings.Contains(l.Port, ":") {
				t.Fatalf("port kept part of the address: %q", l.Port)
			}
			// "0.0.0.0%virbr0" is ss naming the interface a wildcard is
			// scoped to; the address the probe reports is the part before it.
			if strings.Contains(l.Address, "%") {
				t.Fatalf("address kept its interface scope: %q", l.Address)
			}
			// The name is what ss quoted inside users:(("sshd",pid=1,fd=3)),
			// so the quotes stay out of it and it is a single word.
			if strings.ContainsAny(l.Process, "\" \t") {
				t.Fatalf("process name kept ss syntax: %q", l.Process)
			}
			// The probe reports a globally reachable socket as a finding, so
			// a loopback address must never be one.
			if l.Global && strings.HasPrefix(l.Address, "127.") {
				t.Fatalf("loopback address reported as global: %q", l.Address)
			}
		}
	})
}

func FuzzParsePacmanUpdates(f *testing.F) {
	seed(f, "checkupdates.txt")
	f.Fuzz(func(t *testing.T, out string) {
		checkNames(t, out, ParsePacmanUpdates(out))
	})
}

func FuzzParseAptUpdates(f *testing.F) {
	seed(f, "apt-get-s-upgrade.txt")
	f.Fuzz(func(t *testing.T, out string) {
		checkNames(t, out, ParseAptUpdates(out))
	})
}

func FuzzParseDnfUpdates(f *testing.F) {
	seed(f, "dnf-check-update.txt")
	f.Fuzz(func(t *testing.T, out string) {
		packages := ParseDnfUpdates(out)
		checkNames(t, out, packages)
		for _, name := range packages {
			// dnf prints name.arch, and a line without the dot is a heading
			// rather than a package.
			if !strings.Contains(name, ".") {
				t.Fatalf("not a name.arch package: %q", name)
			}
		}
	})
}

// FuzzParsePasswdRootAccounts and FuzzParseShadowEmptyPasswords read the two
// files whose findings name real accounts. Whatever comes back is printed, so
// it has to be a field of the input and nothing else — never a fragment of the
// hash column of /etc/shadow.
func FuzzParsePasswdRootAccounts(f *testing.F) {
	seed(f, "passwd-fedora42.txt", "passwd-two-roots.txt")
	f.Fuzz(func(t *testing.T, text string) {
		for _, user := range ParsePasswdRootAccounts(text) {
			if strings.ContainsAny(user, ":\n") {
				t.Fatalf("account name is not one passwd field: %q", user)
			}
			if !strings.Contains(text, user) {
				t.Fatalf("account name %q is not in the input", user)
			}
		}
	})
}

func FuzzParseShadowEmptyPasswords(f *testing.F) {
	seed(f, "shadow.txt")
	f.Fuzz(func(t *testing.T, text string) {
		for _, user := range ParseShadowEmptyPasswords(text) {
			if strings.ContainsAny(user, ":\n") {
				t.Fatalf("account name is not one shadow field: %q", user)
			}
			if !strings.Contains(text, user) {
				t.Fatalf("account name %q is not in the input", user)
			}
		}
	})
}

func FuzzParseSudoNoPasswd(f *testing.F) {
	seed(f, "sudo-l.txt")
	f.Fuzz(func(t *testing.T, out string) {
		for _, entry := range ParseSudoNoPasswd(out) {
			trimmed(t, "sudo entry", entry)
			if !strings.Contains(entry, "NOPASSWD") {
				t.Fatalf("entry without NOPASSWD: %q", entry)
			}
		}
	})
}

// FuzzParsePasswdLoginAccounts reads the same file, for the accounts a lockout
// guard walks looking for a key. A home directory that is not a field of the
// input would send the key scan reading a path nobody wrote down.
func FuzzParsePasswdLoginAccounts(f *testing.F) {
	seed(f, "passwd-fedora42.txt", "passwd-two-roots.txt")
	f.Fuzz(func(t *testing.T, text string) {
		for _, account := range ParsePasswdLoginAccounts(text) {
			for label, field := range map[string]string{
				"name": account.Name, "home": account.Home, "shell": account.Shell,
			} {
				if strings.ContainsAny(field, ":\n") {
					t.Fatalf("%s is not one passwd field: %q", label, field)
				}
				if !strings.Contains(text, field) {
					t.Fatalf("%s %q is not in the input", label, field)
				}
			}
			if account.Home == "" {
				t.Fatalf("account %q has no home to look in", account.Name)
			}
		}
	})
}

// FuzzParseCgroupUnit reads /proc/<pid>/cgroup, and what it returns goes
// straight into a `systemctl disable --now` argv. A unit name that is not a
// plain service, or one carrying anything a shell would notice, must never
// come back.
func FuzzParseCgroupUnit(f *testing.F) {
	f.Add("0::/system.slice/nginx.service\n")
	f.Add("12:name=systemd:/system.slice/postgresql.service\n")
	f.Add("0::/user.slice/user-1000.slice/session-3.scope\n")
	f.Add("")
	f.Add("::")
	f.Fuzz(func(t *testing.T, text string) {
		unit := ParseCgroupUnit(text)
		if unit == "" {
			return
		}
		trimmed(t, "unit", unit)
		if !serviceRe.MatchString(unit) {
			t.Fatalf("cgroup yielded something that is not a service: %q", unit)
		}
		if _, err := BuildDisableUnit(unit); err != nil && !protectedUnits[unit] {
			t.Fatalf("cgroup yielded a unit no command can be built for: %q", unit)
		}
	})
}

// FuzzRenderSSHDDropIn reads back the file tui-secure itself wrote last time.
// It is the only input to a write that this tool also produced, which is
// exactly why it is fuzzed: a file edited by hand between two runs is
// attacker-shaped input to the next preview, and the file the dialog shows is
// the file that gets installed.
func FuzzRenderSSHDDropIn(f *testing.F) {
	f.Add("PasswordAuthentication no\n")
	f.Add("# Written by tui-secure.\n\nPermitRootLogin no\nMaxAuthTries 4\n")
	f.Add("Port 2222\nAllowUsers root\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, existing string) {
		content, err := RenderSSHDDropIn(existing, "PasswordAuthentication", "no")
		if err != nil {
			t.Fatalf("a keyword from this package's table was refused: %v", err)
		}
		for _, line := range splitLines(content) {
			trimmedLine := strings.TrimSpace(line)
			if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
				continue
			}
			fields := strings.Fields(trimmedLine)
			if len(fields) != 2 {
				t.Fatalf("the file gained a line that is not one keyword: %q", line)
			}
			if _, owned := sshdKey(fields[0]); !owned {
				t.Fatalf("the file gained a keyword this tool does not own: %q",
					fields[0])
			}
			if !sshdValueRe.MatchString(fields[1]) {
				t.Fatalf("the file gained a value this tool would not write: %q",
					fields[1])
			}
		}
		if !strings.Contains(content, "PasswordAuthentication no") {
			t.Fatalf("the keyword being set is missing:\n%s", content)
		}
	})
}
