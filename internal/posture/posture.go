// Package posture defines the backend-agnostic model tui-secure renders and
// the interface every implementation satisfies. The UI knows only these types:
// it never builds a bootctl, getenforce, ufw or sshd argv itself. Fixes are
// Command values produced by the backend, shown in a preview dialog and only
// then executed.
package posture

import (
	"context"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
)

// The probe identifiers, in the order the screen shows them. The order is
// fixed rather than sorted by verdict: a row that moves when the machine
// changes is a row nobody can learn the position of, and this screen is read
// often enough for that to matter.
const (
	// ProbeSecureBoot: the firmware trusted the thing it booted.
	ProbeSecureBoot = "secure-boot"
	// ProbeMAC: SELinux or AppArmor, and what they have been denying.
	ProbeMAC = "mac"
	// ProbeFirewall: ufw, firewalld or a bare nftables ruleset.
	ProbeFirewall = "firewall"
	// ProbeSSH: the settings of the one service the internet talks to.
	ProbeSSH = "ssh"
	// ProbeUpdates: what is pending, and whether anything applies it.
	ProbeUpdates = "updates"
	// ProbeAccounts: who can become root, and how easily.
	ProbeAccounts = "accounts"
	// ProbeKernel: the sysctl hardening basics and core dumps.
	ProbeKernel = "kernel"
	// ProbePorts: what is listening, and on which address.
	ProbePorts = "ports"
)

// IDs is the report's probe order.
var IDs = []string{
	ProbeSecureBoot, ProbeMAC, ProbeFirewall, ProbeSSH,
	ProbeUpdates, ProbeAccounts, ProbeKernel, ProbePorts,
}

// Command is a single invocation the user is about to run. Argv excludes any
// privilege wrapper: the backend adds it when previewing and when executing.
//
// It is an alias rather than a type of its own, so a backend hands the very
// value the confirm dialog displayed straight to the kit runner, with no
// conversion in between. That identity is what makes the preview a promise.
type Command = runner.Command

// Status is a probe's verdict.
type Status string

// The four verdicts. Unknown is not a failure of the tool: it is what a probe
// says when the machine would not answer — a missing binary, or a read that
// needs a root this process was not given.
const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusBad     Status = "bad"
	StatusUnknown Status = "unknown"
)

// rank orders the verdicts from best to worst, with unknown between ok and
// warn: not knowing is worse than knowing it is fine, and better than knowing
// it is not.
func (s Status) rank() int {
	switch s {
	case StatusOK:
		return 0
	case StatusUnknown:
		return 1
	case StatusWarn:
		return 2
	case StatusBad:
		return 3
	default:
		return 1
	}
}

// Worst returns the least reassuring of a set of verdicts. It is how a probe
// that judges several settings reaches one answer, and how a report reaches
// its headline.
func Worst(statuses ...Status) Status {
	worst := StatusOK
	for _, s := range statuses {
		if s.rank() > worst.rank() {
			worst = s
		}
	}
	return worst
}

// Evidence is the exact command a probe ran and the one line it based its
// verdict on. Both halves matter: the command so the reader can run it
// themselves, the line so they can see what was read out of it.
type Evidence struct {
	// Command is the command line, privilege prefix included.
	Command string `json:"command"`
	// Line is the output line the verdict rests on, empty when the command
	// itself answered nothing.
	Line string `json:"line,omitempty"`
}

// Fix is what to do about a probe that is not ok. It names either the sibling
// tool that owns the change or the command to run by hand — tui-secure fixes
// almost nothing itself, on purpose.
type Fix struct {
	// Hint is one sentence saying what would improve the verdict.
	Hint string `json:"hint,omitempty"`
	// Tool is the tui-tools tool that owns this change, when there is one.
	Tool string `json:"tool,omitempty"`
	// Command is the command line a user would run, previewed here and never
	// executed by tui-secure.
	Command string `json:"command,omitempty"`
}

// Action is a fix tui-secure will run itself, once it has been previewed and
// confirmed. Only the safe one-liners are offered; everything else is a Fix.
type Action struct {
	// ID identifies the action to the backend that built it.
	ID string `json:"id"`
	// Label is what the picker and the confirm dialog call it.
	Label string `json:"label"`
	// Danger marks a change worth a red dialog.
	Danger bool `json:"danger,omitempty"`
}

// Finding is one judged setting inside a probe: what was read, what it says,
// and what that is worth.
type Finding struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Status Status `json:"status"`
	// Note explains a verdict that is not obvious from the value alone.
	Note string `json:"note,omitempty"`
}

// Probe is one row of the posture screen: a question about the machine, the
// answer, and everything needed to check the answer.
type Probe struct {
	// ID is the stable identifier used by --check, by the filter and by
	// BuildAction ("firewall", "ssh").
	ID string `json:"id"`
	// Title is the row label.
	Title string `json:"title"`
	// Status is the verdict.
	Status Status `json:"status"`
	// Summary is the one line the row shows.
	Summary string `json:"summary"`
	// Reason says why the status is unknown, and is empty otherwise.
	Reason string `json:"reason,omitempty"`
	// Findings are the individual settings the verdict was assembled from.
	Findings []Finding `json:"findings,omitempty"`
	// Evidence is the commands that were run and the lines that were read.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Raw is the full output of those commands, shown under the evidence.
	Raw string `json:"-"`
	// Fix is what to do about it.
	Fix Fix `json:"fix,omitempty"`
	// Actions are the fixes this tool will run, after a confirm dialog.
	Actions []Action `json:"actions,omitempty"`
}

// Stack is what the machine turned out to be running, named by the probes that
// found it. It is the header's one-line answer to "what am I looking at".
type Stack struct {
	SecureBoot string `json:"secureBoot,omitempty"`
	MAC        string `json:"mac,omitempty"`
	Firewall   string `json:"firewall,omitempty"`
	SSHD       string `json:"sshd,omitempty"`
	Updates    string `json:"updates,omitempty"`
}

// String renders the stack for the header: the parts that were detected,
// separated, with the ones that were not left out entirely.
func (s Stack) String() string {
	parts := make([]string, 0, 5)
	for _, part := range []string{s.SecureBoot, s.MAC, s.Firewall, s.SSHD, s.Updates} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return "nothing detected"
	}
	return strings.Join(parts, " · ")
}

// Score is the headline: how many probes landed where, and one number.
type Score struct {
	// Value is the weighted percentage: an ok counts whole, a warn counts
	// half, a bad counts nothing. Unknown probes are left out of both sides,
	// because scoring a question nobody could answer would be inventing a
	// verdict.
	Value int `json:"value"`
	// Counted is how many probes the value was computed from.
	Counted int `json:"counted"`
	OK      int `json:"ok"`
	Warn    int `json:"warn"`
	Bad     int `json:"bad"`
	Unknown int `json:"unknown"`
}

// ScoreOf counts the probes and computes the weighted score.
func ScoreOf(probes []Probe) Score {
	var score Score
	points := 0.0
	for _, p := range probes {
		switch p.Status {
		case StatusOK:
			score.OK++
			points++
		case StatusWarn:
			score.Warn++
			points += 0.5
		case StatusBad:
			score.Bad++
		default:
			score.Unknown++
		}
	}
	score.Counted = score.OK + score.Warn + score.Bad
	if score.Counted > 0 {
		score.Value = int(points*100/float64(score.Counted) + 0.5)
	}
	return score
}

// Report is the whole picture tui-secure renders.
type Report struct {
	// Backend names the implementation that produced this report.
	Backend string `json:"backend"`
	// Distro is the machine's own name for itself, from /etc/os-release.
	Distro string `json:"distro"`
	// DistroID is the os-release ID, which is what the update probe switches
	// on ("fedora", "ubuntu", "arch").
	DistroID string `json:"distroId,omitempty"`
	// Kernel is the running kernel release.
	Kernel string `json:"kernel,omitempty"`
	// Stack is what was detected on this machine.
	Stack Stack `json:"stack"`
	// Probes are the rows, in the order they are shown.
	Probes []Probe `json:"probes"`
	// Score is the headline.
	Score Score `json:"score"`
	// Worst is the least reassuring verdict in the report. It is the field a
	// script reads: --check exits 0 whenever the tool worked, so the verdict
	// travels in the JSON rather than in the exit code.
	Worst Status `json:"worst"`
}

// Finish computes the derived fields of a report once its probes are in.
func (r *Report) Finish() {
	r.Score = ScoreOf(r.Probes)
	statuses := make([]Status, 0, len(r.Probes))
	for _, p := range r.Probes {
		statuses = append(statuses, p.Status)
	}
	r.Worst = Worst(statuses...)
}

// Probe returns the probe with the given ID.
func (r Report) Probe(id string) (Probe, bool) {
	for _, p := range r.Probes {
		if p.ID == id {
			return p, true
		}
	}
	return Probe{}, false
}

// Replace swaps one probe for a freshly run version of itself, keeping the
// order of the report, and recomputes the score.
func (r *Report) Replace(p Probe) {
	for i := range r.Probes {
		if r.Probes[i].ID == p.ID {
			r.Probes[i] = p
			r.Finish()
			return
		}
	}
}

// Plan is a fix the user is about to apply: what it is called, what it will do
// in words, and the exact commands that do it.
type Plan struct {
	// Title is the confirm dialog's title.
	Title string
	// Body explains the change, and carries the drop-in file's diff when the
	// change writes one.
	Body string
	// Commands are run in order, and are what the confirm dialog shows.
	Commands []Command
	// Danger marks a change worth a red dialog.
	Danger bool
}

// Backend is the boundary between the UI and the machine. Load and Reload read
// state; BuildAction turns an offered fix into previewable Commands; Run
// executes a Command the user confirmed. Nothing else may mutate the system.
type Backend interface {
	// Name is the backend identifier ("host", "demo").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string

	// Preview renders the exact command line Run will execute, privilege
	// wrapper included. This is the text shown in the confirm dialog.
	Preview(cmd Command) string

	// Load runs every probe.
	Load(ctx context.Context) (Report, error)
	// Reload runs one probe again, by ID.
	Reload(ctx context.Context, id string) (Probe, error)
	// BuildAction turns an offered action into a plan, without running any
	// part of it.
	BuildAction(probeID, actionID string) (Plan, error)
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd Command) (string, error)
}
