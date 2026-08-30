package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// mode is the screen the app currently shows. Only one dialog is open at a
// time, which keeps the update loop flat.
type mode int

const (
	modeList mode = iota
	modeDetail
	modeConfirm
	modeFilter
	modePicker
	modeHelp
)

// loadTimeout bounds a full read. Every probe shells out, and the slowest of
// them asks a package manager what is pending.
const loadTimeout = 90 * time.Second

// runTimeout bounds a confirmed fix.
const runTimeout = 60 * time.Second

// app is the tui-secure Bubble Tea model.
type app struct {
	backend posture.Backend
	theme   theme.Theme
	// backends is what the version probes found, rendered in the header.
	backends []compat.Result

	report posture.Report
	// visible holds the probes left after the filter, in display order.
	visible []posture.Probe

	width, height int
	cursor        int
	offset        int
	filter        string

	// detailID is the probe the detail screen is showing, empty on the list.
	detailID string
	// detailOffset is the detail screen's scroll position.
	detailOffset int

	mode    mode
	confirm ui.Confirm
	input   ui.Input
	picker  ui.Picker
	// pending are the actions the open picker is choosing between.
	pending []posture.Action

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last read returned an error, so the empty
	// state does not claim the machine simply has nothing to report.
	loadFailed bool
	// busy blocks input while a command runs.
	busy bool
}

// loadedMsg carries the result of a full read.
type loadedMsg struct {
	report posture.Report
	err    error
}

// probeMsg carries the result of re-running one probe.
type probeMsg struct {
	probe posture.Probe
	err   error
}

// ranMsg carries the result of running a plan.
type ranMsg struct {
	// title is the plan's title, echoed in the status line.
	title string
	// probeID is the probe the plan changed, re-read afterwards.
	probeID string
	output  string
	err     error
}

// plan is what a confirm dialog is holding: one or more commands, run in
// order. Enabling ufw is a single command; setting a hardening key is two, the
// drop-in and the write, and both are shown before either runs.
type plan struct {
	title    string
	probeID  string
	commands []posture.Command
}

// newApp builds the model around a backend.
func newApp(backend posture.Backend, th theme.Theme,
	backends []compat.Result) *app {
	a := &app{
		backend:  backend,
		theme:    th,
		backends: backends,
		width:    80,
		height:   24,
		loading:  true,
	}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first read.
func (a *app) Init() tea.Cmd { return a.load() }

// load runs every probe in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		report, err := backend.Load(ctx)
		return loadedMsg{report: report, err: err}
	}
}

// reloadProbe runs one probe again in the background.
func (a *app) reloadProbe(id string) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
		defer cancel()
		probe, err := backend.Reload(ctx, id)
		return probeMsg{probe: probe, err: err}
	}
}

// run executes a confirmed plan in the background, one command at a time,
// stopping at the first failure.
func (a *app) run(p plan) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		var outputs []string
		for _, cmd := range p.commands {
			out, err := backend.Run(ctx, cmd)
			if err != nil {
				return ranMsg{title: p.title, probeID: p.probeID,
					output: out, err: err}
			}
			if trimmed := strings.TrimSpace(out); trimmed != "" {
				outputs = append(outputs, trimmed)
			}
		}
		return ranMsg{title: p.title, probeID: p.probeID,
			output: strings.Join(outputs, "; ")}
	}
}

// setStatus records a plain message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.report = msg.report
		a.applyFilter()
		return a, nil

	case probeMsg:
		a.loading = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.report.Replace(msg.probe)
		a.applyFilter()
		a.setStatusf(ui.StatusOK, "%s: %s", msg.probe.Title, msg.probe.Summary)
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.reloadProbe(msg.probeID)
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.title, firstLine(summary))
		return a, a.reloadProbe(msg.probeID)

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeFilter {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	return a, nil
}

// handleKey routes a key press to the open dialog, or to the current screen.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeFilter:
		return a.handleFilter(msg)
	case modePicker:
		return a.handlePicker(msg)
	case modeHelp:
		a.mode = a.returnMode()
		return a, nil
	case modeDetail:
		return a.handleDetailKey(msg)
	default:
		return a.handleListKey(msg)
	}
}

// returnMode is the screen a dialog goes back to.
func (a *app) returnMode() mode {
	if a.detailID != "" {
		return modeDetail
	}
	return modeList
}

// handleConfirm resolves the confirm dialog.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = a.returnMode()
	confirmed := a.confirm.Confirmed
	pending, ok := a.confirm.Payload.(plan)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(pending.commands[0]))
	return a, a.run(pending)
}

// handleFilter resolves the filter prompt.
func (a *app) handleFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		// Filter as the user types.
		a.filter = a.input.Value()
		a.applyFilter()
		return a, cmd
	}
	if a.input.Accepted {
		a.filter = a.input.Value()
	} else {
		a.filter = ""
	}
	a.applyFilter()
	a.mode = modeList
	return a, nil
}

// handlePicker resolves the action picker.
func (a *app) handlePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.picker.Update(msg)
	if !a.picker.Done {
		return a, nil
	}
	choice, accepted := a.picker.Selected(), a.picker.Accepted
	actions, probeID := a.pending, a.pickerProbe()
	a.picker, a.pending = ui.Picker{}, nil
	a.mode = a.returnMode()
	if !accepted {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	for _, action := range actions {
		if action.Label == choice {
			a.confirmAction(probeID, action)
			return a, nil
		}
	}
	return a, nil
}

// pickerProbe is the probe the open picker belongs to.
func (a *app) pickerProbe() string {
	id, _ := a.picker.Payload.(string)
	return id
}

// handleListKey handles the posture screen.
func (a *app) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.cursor, a.offset = 0, 0
	case "G", "end":
		a.cursor = max(len(a.visible)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.tableHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.tableHeight())
	case "/":
		a.input = ui.NewInput("Filter probes", "name, verdict, summary…", a.filter)
		a.input.Help = "Matches the probe, its verdict and its summary. Empty clears the filter."
		a.mode = modeFilter
	case "enter":
		return a, a.openDetail()
	case "r", "ctrl+r":
		a.loading = true
		return a, a.load()
	case "R":
		return a, a.reloadCurrent()
	case "a":
		return a, a.openActions()
	}
	return a, nil
}

// handleDetailKey handles the per-probe screen.
func (a *app) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "esc", "backspace", "left":
		a.detailID, a.detailOffset = "", 0
		a.mode = modeList
		return a, nil
	case "?":
		a.mode = modeHelp
		return a, nil
	case "j", "down":
		a.detailOffset++
		return a, nil
	case "k", "up":
		a.detailOffset = max(a.detailOffset-1, 0)
		return a, nil
	case "g", "home":
		a.detailOffset = 0
		return a, nil
	case "pgdown", "ctrl+f":
		a.detailOffset += a.detailHeight()
		return a, nil
	case "pgup", "ctrl+b":
		a.detailOffset = max(a.detailOffset-a.detailHeight(), 0)
		return a, nil
	case "r", "ctrl+r":
		a.loading = true
		return a, a.load()
	case "R":
		return a, a.reloadCurrent()
	case "a":
		return a, a.openActions()
	}
	return a, nil
}

// currentProbe is the probe the keys apply to: the one the detail screen is
// showing, or the highlighted row of the list.
func (a *app) currentProbe() (posture.Probe, bool) {
	if a.mode == modeDetail && a.detailID != "" {
		return a.report.Probe(a.detailID)
	}
	if a.cursor < 0 || a.cursor >= len(a.visible) {
		return posture.Probe{}, false
	}
	return a.visible[a.cursor], true
}

// openDetail opens the selected probe's screen.
func (a *app) openDetail() tea.Cmd {
	probe, ok := a.currentProbe()
	if !ok {
		a.setStatus(ui.StatusWarn, "no probe selected")
		return nil
	}
	a.detailID, a.detailOffset = probe.ID, 0
	a.mode = modeDetail
	return nil
}

// reloadCurrent re-runs the selected probe.
func (a *app) reloadCurrent() tea.Cmd {
	probe, ok := a.currentProbe()
	if !ok {
		a.setStatus(ui.StatusWarn, "no probe selected")
		return nil
	}
	a.setStatusf(ui.StatusInfo, "re-running %s…", probe.Title)
	return a.reloadProbe(probe.ID)
}

// openActions offers the fixes a probe carries: none, one, or a picker.
//
// A probe with no action is not a dead end — it has a Fix, which names the
// tool or the command that owns the change. Saying so here is the difference
// between "this tool cannot help" and "this is not this tool's job".
func (a *app) openActions() tea.Cmd {
	probe, ok := a.currentProbe()
	if !ok {
		a.setStatus(ui.StatusWarn, "no probe selected")
		return nil
	}
	switch len(probe.Actions) {
	case 0:
		a.setStatus(ui.StatusWarn, noActionHint(probe))
		return nil
	case 1:
		a.confirmAction(probe.ID, probe.Actions[0])
		return nil
	}

	labels := make([]string, 0, len(probe.Actions))
	for _, action := range probe.Actions {
		labels = append(labels, action.Label)
	}
	a.picker = ui.NewPicker("Fix "+probe.Title, labels, "")
	a.picker.Payload = probe.ID
	a.pending = probe.Actions
	a.mode = modePicker
	return nil
}

// noActionHint explains what to do with a probe tui-secure will not fix
// itself.
func noActionHint(probe posture.Probe) string {
	switch {
	case probe.Fix.Tool != "":
		return probe.Title + ": this one belongs to " + probe.Fix.Tool
	case probe.Fix.Command != "":
		return probe.Title + ": run " + probe.Fix.Command
	case probe.Status == posture.StatusOK:
		return probe.Title + " is already ok"
	default:
		return probe.Title + ": nothing here is safe to change automatically"
	}
}

// confirmAction builds a plan and opens the confirm dialog with it. The plan
// is built, never run: what the dialog shows is what the runner is handed on
// a yes.
func (a *app) confirmAction(probeID string, action posture.Action) {
	built, err := a.backend.BuildAction(probeID, action.ID)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   built.Title,
		Body:    a.bodyForDialog(built.Body),
		Command: a.previewAll(built.Commands),
		Danger:  built.Danger,
		Payload: plan{title: built.Title, probeID: probeID,
			commands: built.Commands},
	}
}

// previewAll renders every command of a plan, one per line, each with the
// prompt the dialog puts in front of the first one.
func (a *app) previewAll(commands []posture.Command) string {
	previews := make([]string, 0, len(commands))
	for _, cmd := range commands {
		previews = append(previews, a.backend.Preview(cmd))
	}
	return strings.Join(previews, "\n$ ")
}

// applyFilter recomputes the visible probes from the current filter.
func (a *app) applyFilter() {
	if a.filter == "" {
		a.visible = a.report.Probes
		a.clampCursor()
		return
	}
	needle := strings.ToLower(a.filter)
	var kept []posture.Probe
	for _, probe := range a.report.Probes {
		if strings.Contains(strings.ToLower(probeHaystack(probe)), needle) {
			kept = append(kept, probe)
		}
	}
	a.visible = kept
	a.clampCursor()
}

// probeHaystack is the text the filter matches against.
func probeHaystack(p posture.Probe) string {
	parts := []string{p.ID, p.Title, string(p.Status), p.Summary, p.Fix.Tool}
	for _, finding := range p.Findings {
		parts = append(parts, finding.Label, finding.Value)
	}
	return strings.Join(parts, " ")
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.cursor += delta
	a.clampCursor()
}

// clampCursor keeps the cursor and the scroll offset within range.
func (a *app) clampCursor() {
	if len(a.visible) == 0 {
		a.cursor, a.offset = 0, 0
		return
	}
	a.cursor = min(max(a.cursor, 0), len(a.visible)-1)

	height := a.tableHeight()
	if a.cursor < a.offset {
		a.offset = a.cursor
	}
	if a.cursor >= a.offset+height {
		a.offset = a.cursor - height + 1
	}
	a.offset = max(min(a.offset, max(len(a.visible)-height, 0)), 0)
}

// firstLine keeps status messages to one line.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
