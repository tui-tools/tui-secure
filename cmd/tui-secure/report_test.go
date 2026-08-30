package main

import (
	"strings"
	"testing"

	"github.com/tui-tools/tui-kit/compat"
)

// TestRunReportDemo checks the half of the block this tool owns. The kit's own
// tests cover the machine facts and the scrubbing; what has to be right here is
// that --demo says demo, that what the fake imitates is named beside it rather
// than the "host" the fake answers Name() with, and that no probe ran to
// produce any of it.
func TestRunReportDemo(t *testing.T) {
	var out strings.Builder
	opts := options{demo: true, report: true}
	if err := runReport(baseConfig(), opts, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{
		"backend: demo\n",
		"mode: demo (sample data, the system was not read)\n",
		"demo backend: host\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, toolName+" ") {
		t.Errorf("report should start with the tool name:\n%s", got)
	}
	// The versions belong to the real machine, and a fake has none of them.
	if strings.Contains(got, "backends:") {
		t.Errorf("a demo report should claim no backend versions:\n%s", got)
	}
}

// TestRunReportLive renders the live block on whatever machine the tests run
// on and holds it to the promise the bug form makes about it: it always
// answers, it names the backend, and it never names the user or the machine.
func TestRunReportLive(t *testing.T) {
	t.Setenv("HOSTNAME", "workstation")
	t.Setenv("USER", "alice")
	t.Setenv("HOME", "/home/alice")

	var out strings.Builder
	if err := runReport(baseConfig(), options{report: true}, &out); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got := out.String()
	for _, want := range []string{"backend: host", "mode: live\n", "backends: "} {
		if !strings.Contains(got, want) {
			t.Errorf("report is missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"alice", "workstation", "/home/"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("the report leaked %q:\n%s", forbidden, got)
		}
	}
}

// TestDescribeBackends renders every backend the tool probes, which is what
// tells "ufw is not on this machine" from "ufw is here and the probe could not
// read it" — two different bugs behind the same missing version.
func TestDescribeBackends(t *testing.T) {
	tests := []struct {
		name    string
		results []compat.Result
		want    string
	}{
		{
			name: "a version, an absent program and an unreadable one",
			results: []compat.Result{
				{Backend: "systemd", Version: "257"},
				{Backend: "ufw", Detail: "command not available: the ufw command was not found"},
				{Backend: "sbctl", Detail: "could not read a version from `sbctl version`"},
			},
			want: "systemd 257, ufw absent, sbctl (version unread)",
		},
		{
			name:    "a manifest that could not be read at all",
			results: nil,
			want:    "none",
		},
		{
			name:    "a result with no backend name is dropped",
			results: []compat.Result{{Version: "1.0"}},
			want:    "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeBackends(tc.results); got != tc.want {
				t.Errorf("describeBackends = %q, want %q", got, tc.want)
			}
		})
	}
}
