package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-secure/internal/host"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// newTestApp builds an app on the sample machine, sized like a normal
// terminal and already loaded.
func newTestApp(t *testing.T) (*app, *host.Fake) {
	t.Helper()
	backend := host.NewFake()
	a := newApp(backend, theme.New(), nil)
	a.width, a.height = 100, 30
	drain(t, a, a.Init())
	return a, backend
}

// drain runs a tea.Cmd and feeds its message back into the model, which is
// what the Bubble Tea runtime does. It is how a test exercises a read.
func drain(t *testing.T, a *app, cmd tea.Cmd) {
	t.Helper()
	for range 4 {
		if cmd == nil {
			return
		}
		msg := cmd()
		if msg == nil {
			return
		}
		_, cmd = a.Update(msg)
	}
}

// press sends one key and returns the command it produced.
func press(a *app, key string) tea.Cmd {
	var msg tea.KeyMsg
	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
	_, cmd := a.Update(msg)
	return cmd
}

// selectProbe moves the cursor to a probe by ID.
func selectProbe(t *testing.T, a *app, id string) {
	t.Helper()
	for i, probe := range a.visible {
		if probe.ID == id {
			a.cursor = i
			return
		}
	}
	t.Fatalf("no probe %q in the sample machine", id)
}

func TestLoadsTheSampleMachine(t *testing.T) {
	a, _ := newTestApp(t)
	if len(a.visible) != len(posture.IDs) {
		t.Fatalf("got %d probes, want %d", len(a.visible), len(posture.IDs))
	}
	if a.report.Worst != posture.StatusBad {
		t.Errorf("worst = %q, want the sample machine's second root account "+
			"to be bad news", a.report.Worst)
	}
	view := a.View()
	for _, want := range []string{"Secure Boot", "Firewall", "score"} {
		if !strings.Contains(view, want) {
			t.Errorf("the first frame is missing %q", want)
		}
	}
}

// TestFixesPreviewExactlyWhatTheyRun is the family's central promise, as a
// test: the command line in the confirm dialog is the command line the backend
// is then asked to run.
func TestFixesPreviewExactlyWhatTheyRun(t *testing.T) {
	tests := []struct {
		probe string
		want  []string
	}{
		{posture.ProbeKernel, []string{
			"sudo -n install -m 644 /tmp/tui-secure/90-tui-secure.conf " +
				host.DropInPath,
			"sudo -n sysctl -w kernel.kptr_restrict=1",
		}},
		{posture.ProbeUpdates, []string{
			"sudo -n systemctl enable --now omarchy-server-update.timer",
		}},
	}
	for _, test := range tests {
		a, backend := newTestApp(t)
		selectProbe(t, a, test.probe)

		drain(t, a, press(a, "a"))
		if a.mode != modeConfirm {
			t.Fatalf("%s: no confirm dialog opened (status: %s)", test.probe, a.status)
		}
		if got := strings.Split(a.confirm.Command, "\n$ "); !equal(got, test.want) {
			t.Errorf("%s: previewed %q, want %q", test.probe, got, test.want)
		}

		drain(t, a, press(a, "y"))
		ran := backend.Ran()
		if len(ran) != len(test.want) {
			t.Fatalf("%s: ran %d commands, want %d", test.probe, len(ran),
				len(test.want))
		}
		for i, cmd := range ran {
			if got := backend.Preview(cmd); got != test.want[i] {
				t.Errorf("%s: ran %q, want the previewed %q", test.probe, got,
					test.want[i])
			}
		}
	}
}

// equal compares two command line lists.
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCancellingRunsNothing(t *testing.T) {
	a, backend := newTestApp(t)
	selectProbe(t, a, posture.ProbeKernel)
	drain(t, a, press(a, "a"))
	drain(t, a, press(a, "n"))

	if len(backend.Ran()) != 0 {
		t.Errorf("answering no ran %d commands", len(backend.Ran()))
	}
	if a.status != "cancelled" {
		t.Errorf("status = %q, want cancelled", a.status)
	}
}

// TestConfirmedFixChangesTheProbe: the demo applies what the real command
// would have done, so the row the fix was pressed on comes back green.
func TestConfirmedFixChangesTheProbe(t *testing.T) {
	a, _ := newTestApp(t)
	selectProbe(t, a, posture.ProbeUpdates)
	before, _ := a.report.Probe(posture.ProbeUpdates)
	if len(before.Actions) != 1 {
		t.Fatalf("the sample machine's update timer is already enabled")
	}

	drain(t, a, press(a, "a"))
	drain(t, a, press(a, "y"))

	after, _ := a.report.Probe(posture.ProbeUpdates)
	if len(after.Actions) != 0 {
		t.Errorf("the fix is still offered after it ran")
	}
	if !strings.Contains(probeText(after), "enabled") {
		t.Errorf("the timer finding still says %q", probeText(after))
	}
}

// probeText flattens a probe's findings for an assertion.
func probeText(p posture.Probe) string {
	var b strings.Builder
	for _, finding := range p.Findings {
		b.WriteString(finding.Label + "=" + finding.Value + " ")
	}
	return b.String()
}

// TestProbeWithoutAnActionNamesItsOwner: tui-secure fixes almost nothing
// itself, and a probe that offers no action must say who does.
func TestProbeWithoutAnActionNamesItsOwner(t *testing.T) {
	a, backend := newTestApp(t)
	selectProbe(t, a, posture.ProbeAccounts)
	drain(t, a, press(a, "a"))

	if a.mode == modeConfirm {
		t.Fatal("a probe with no action opened a confirm dialog")
	}
	if len(backend.Ran()) != 0 {
		t.Error("a probe with no action ran a command")
	}
	if !strings.Contains(a.status, "tui-users") {
		t.Errorf("status = %q, want the tool that owns this fix", a.status)
	}
}

func TestDetailScreenShowsTheEvidence(t *testing.T) {
	a, _ := newTestApp(t)
	selectProbe(t, a, posture.ProbeSSH)
	drain(t, a, press(a, "enter"))

	if a.mode != modeDetail {
		t.Fatalf("enter did not open the detail screen")
	}
	probe, _ := a.report.Probe(posture.ProbeSSH)
	view := strings.Join(detailLines(probe), "\n")
	for _, want := range []string{
		"SSH server — warn",
		"PasswordAuthentication",
		"Evidence",
		"$ sudo -n sshd -T",
		"passwordauthentication yes",
		"Raw output",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("the detail screen is missing %q", want)
		}
	}

	drain(t, a, press(a, "esc"))
	if a.mode != modeList {
		t.Errorf("esc did not return to the posture list")
	}
}

func TestFilterMatchesVerdictAndSummary(t *testing.T) {
	a, _ := newTestApp(t)
	for _, test := range []struct {
		needle string
		want   int
	}{
		// The sshd probe, and the ports probe whose findings name sshd: the
		// filter reads the findings too, which is what makes it useful for a
		// process or a port number.
		{"ssh", 2},
		{"bad", 1},
		{"firewall", 2}, // the firewall probe, and the ports probe it owns
		{"nothing here", 0},
	} {
		a.filter = test.needle
		a.applyFilter()
		if len(a.visible) != test.want {
			t.Errorf("filter %q matched %d probes, want %d",
				test.needle, len(a.visible), test.want)
		}
	}
}

// TestRendersAtEveryWidth is the responsive contract: from a narrow pane to a
// wide screen, no frame may wrap, because a wrapped row desynchronises Bubble
// Tea's line accounting and every frame after it lands in the wrong place.
func TestRendersAtEveryWidth(t *testing.T) {
	for width := 40; width <= 200; width += 4 {
		a, _ := newTestApp(t)
		a.width, a.height = width, 24
		a.clampCursor()

		screens := map[string]func(){
			"list":   func() { a.mode = modeList },
			"detail": func() { a.mode = modeDetail; a.detailID = posture.ProbeKernel },
			"help":   func() { a.mode = modeHelp },
			"confirm": func() {
				a.detailID = ""
				a.mode = modeList
				selectProbe(t, a, posture.ProbeKernel)
				drain(t, a, press(a, "a"))
			},
		}
		for name, setup := range screens {
			setup()
			for i, line := range strings.Split(a.View(), "\n") {
				if got := lineWidth(line); got > width {
					t.Fatalf("%s at %d cols: line %d is %d cells wide",
						name, width, i, got)
				}
			}
		}
	}
}

// lineWidth measures a rendered line, ignoring the ANSI escapes the theme adds.
func lineWidth(line string) int {
	width, inEscape := 0, false
	for _, r := range line {
		switch {
		case r == 0x1b:
			inEscape = true
		case inEscape && (r == 'm' || r == 'K' || r == 'H'):
			inEscape = false
		case inEscape:
		default:
			width++
		}
	}
	return width
}

func TestBusyStateSwallowsInput(t *testing.T) {
	a, backend := newTestApp(t)
	selectProbe(t, a, posture.ProbeKernel)
	a.busy = true
	drain(t, a, press(a, "a"))
	if a.mode != modeList || len(backend.Ran()) != 0 {
		t.Errorf("a key pressed while a command runs must be ignored")
	}
}

// TestReRunOneProbe covers R, which is the key you press after fixing
// something outside this tool.
func TestReRunOneProbe(t *testing.T) {
	a, _ := newTestApp(t)
	selectProbe(t, a, posture.ProbeFirewall)
	drain(t, a, press(a, "R"))
	if !strings.Contains(a.status, "Firewall") {
		t.Errorf("status = %q, want the probe that was re-run", a.status)
	}
}

func TestCompatFactsOnlyForInstalledBackends(t *testing.T) {
	results := []compat.Result{
		{Backend: "systemd", Version: "257"},
		{Backend: "ufw"},
		{Backend: "firewalld", Version: "2.3.2"},
	}
	kept := installed(results)
	if len(kept) != 2 {
		t.Fatalf("kept %d backends, want the two that answered", len(kept))
	}
	for _, result := range kept {
		if result.Backend == "ufw" {
			t.Error("a backend this machine does not have is not a header fact")
		}
	}
}
