package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/manifest"
	tuisecure "github.com/tui-tools/tui-secure"
)

// baseConfig is the configuration as it stands before the flags are folded in.
func baseConfig() config.Config {
	return config.Config{Tool: toolName, Values: defaults()}
}

func TestParseFlags(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	opts, err := parseFlags([]string{"--demo", "--theme", "/t/colors.toml"}, devNull)
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if !opts.demo || opts.themePath != "/t/colors.toml" {
		t.Errorf("opts = %+v", opts)
	}
	if opts.sudoSet {
		t.Error("sudoSet should be false when -sudo is absent")
	}
}

func TestApplyOverrides(t *testing.T) {
	cfg := baseConfig()
	applyOverrides(&cfg, options{themePath: "/t/colors.toml"})
	if got := cfg.Theme(); got != "/t/colors.toml" {
		t.Errorf("Theme() = %q", got)
	}
	// An untouched -sudo must not clear the configured prefix.
	if got := cfg.String(config.KeySudo, ""); got != "sudo -n" {
		t.Errorf("sudo = %q, want the config value", got)
	}

	// An explicit empty -sudo disables escalation.
	cfg = baseConfig()
	applyOverrides(&cfg, options{sudoSet: true, sudo: ""})
	if got := cfg.String(config.KeySudo, "unset"); got != "" {
		t.Errorf("sudo = %q, want empty", got)
	}
	if got := cfg.SudoPrefix(); got != nil {
		t.Errorf("SudoPrefix = %q, want nil", got)
	}
}

func TestDefaultsCoverEveryFlag(t *testing.T) {
	// Every key a flag can override must be declared, otherwise the
	// environment layer silently skips it.
	for _, key := range []string{config.KeySudo, config.KeyTheme} {
		if _, ok := defaults()[key]; !ok {
			t.Errorf("defaults() is missing %q", key)
		}
	}
}

func TestPickBackendDemo(t *testing.T) {
	backend, err := pickBackend(baseConfig(), options{demo: true})
	if err != nil {
		t.Fatalf("pickBackend: %v", err)
	}
	if !strings.Contains(backend.Describe(), "demo") {
		t.Errorf("Describe = %q, want it to say it is a demo", backend.Describe())
	}
}

// TestCheckReportsThePosture covers the contract the smoke test depends on:
// the fields a shell script greps for.
func TestCheckReportsThePosture(t *testing.T) {
	backend, err := pickBackend(baseConfig(), options{demo: true})
	if err != nil {
		t.Fatalf("pickBackend: %v", err)
	}
	var out bytes.Buffer
	if err := runCheck(backend, nil, &out); err != nil {
		t.Fatalf("runCheck: %v", err)
	}
	for _, want := range []string{
		`"tool": "tui-secure"`,
		`"backend": "host"`,
		`"worst": "bad"`,
		`"id": "secure-boot"`,
		`"id": "firewall"`,
		`"status": "warn"`,
		`"command": "sudo -n sshd -T"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--check output is missing %s", want)
		}
	}
}

// TestCheckExitsZeroOnAnInsecureMachine: the verdict travels in `worst`, not
// in the exit code, so a script can tell "this machine is insecure" from "this
// tool is broken".
func TestCheckExitsZeroOnAnInsecureMachine(t *testing.T) {
	backend, err := pickBackend(baseConfig(), options{demo: true})
	if err != nil {
		t.Fatalf("pickBackend: %v", err)
	}
	if err := runCheck(backend, nil, &bytes.Buffer{}); err != nil {
		t.Errorf("runCheck returned %v on a machine with a bad probe", err)
	}
}

func TestProbeCompatIsSkippedInDemo(t *testing.T) {
	if results := probeCompat(context.Background(), true); results != nil {
		t.Errorf("--demo probed %d real backends", len(results))
	}
}

// TestManifestDeclaresEveryBackendTheToolProbes: the manifest is the only
// place a version number is written down, so a backend the code reads and the
// manifest does not describe would be a version nobody can check.
func TestManifestDeclaresEveryBackendTheToolProbes(t *testing.T) {
	m, err := manifest.Load(tuisecure.ManifestJSON)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	for _, name := range []string{"systemd", "openssh", "ufw", "firewalld", "sbctl"} {
		backend, ok := m.Backend(name)
		if !ok {
			t.Errorf("the manifest declares no %q backend", name)
			continue
		}
		if len(backend.VersionCommand) == 0 {
			t.Errorf("%s has no version command", name)
		}
	}
}

// TestSSHVersionRegexReadsOpenSSH pins the one probe whose output goes to
// stderr and whose version string is not a plain number.
func TestSSHVersionRegexReadsOpenSSH(t *testing.T) {
	m, err := manifest.Load(tuisecure.ManifestJSON)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	backend, ok := m.Backend("openssh")
	if !ok {
		t.Fatal("no openssh backend in the manifest")
	}
	result := compat.ProbeWith(context.Background(), backend,
		func(context.Context, []string) (string, error) {
			return "OpenSSH_9.9p1, OpenSSL 3.2.6 30 Sep 2025", nil
		})
	if result.Version != "9.9" {
		t.Errorf("version = %q, want 9.9", result.Version)
	}
	if result.Status == compat.StatusBelowMinimum {
		t.Errorf("9.9 is above the declared minimum %s", result.Minimum)
	}
}
