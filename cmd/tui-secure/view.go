package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// Layout constants: the rows the table cannot use.
const (
	headerLines = 2
	footerLines = 2
	// minTableHeight keeps at least one visible row on a very short terminal.
	minTableHeight = 1
)

// tableHeight is the number of probe rows that fit on screen.
func (a *app) tableHeight() int {
	// header + table header + footer + status line.
	return max(a.height-headerLines-footerLines-2, minTableHeight)
}

// detailHeight is the number of detail lines that fit on screen.
func (a *app) detailHeight() int {
	return max(a.height-headerLines-footerLines-1, minTableHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeFilter:
		return a.input.View(a.theme, a.width, a.height)
	case modePicker:
		return a.picker.View(a.theme, a.width, a.height)
	case modeHelp:
		return placeCenter(
			ui.HelpScreen(a.theme, "tui-secure — keys", helpKeys(), a.width),
			a.width, a.height)
	case modeDetail:
		return a.detailView()
	}
	return a.listView()
}

// placeCenter centers a rendered box in the terminal.
func placeCenter(box string, width, height int) string {
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// listView renders the posture: header, probe table, help bar, status.
func (a *app) listView() string {
	header := a.headerView("")

	var body string
	switch {
	case a.loading && len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "probing the machine…", a.width, a.tableHeight()+1)
	case len(a.visible) == 0 && a.filter != "":
		body = ui.EmptyState(a.theme, "no probe matches "+strconv.Quote(a.filter),
			a.width, a.tableHeight()+1)
	case len(a.visible) == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme,
			"could not read this machine — see the message below",
			a.width, a.tableHeight()+1)
	case len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "no probe returned anything",
			a.width, a.tableHeight()+1)
	default:
		body = a.probeTable()
	}

	help := ui.HelpBar(a.theme, a.shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{header, body, help, status}, "\n")
}

// headerView renders the facts at the top of both screens: the score, the
// machine, and what it turned out to be running.
func (a *app) headerView(subtitleExtra string) string {
	t := a.theme

	score := a.report.Score
	scoreStyle := a.styleFor(a.report.Worst)
	facts := []ui.Fact{{
		Label: "score",
		Value: strconv.Itoa(score.Value) + "%  " +
			strconv.Itoa(score.OK) + " ok · " +
			strconv.Itoa(score.Warn) + " warn · " +
			strconv.Itoa(score.Bad) + " bad · " +
			strconv.Itoa(score.Unknown) + " unknown",
		Style: &scoreStyle,
	}}
	if a.report.Distro != "" {
		value := a.report.Distro
		if a.report.Kernel != "" {
			value += "  " + a.report.Kernel
		}
		facts = append(facts, ui.Fact{Label: "machine", Value: value})
	}
	facts = append(facts, ui.Fact{Label: "stack", Value: a.report.Stack.String()})
	// The backend versions, for the backends this machine actually has. A
	// version nobody has tested is coloured; a tested one is quiet.
	for _, result := range installed(a.backends) {
		facts = append(facts, ui.CompatFact(t, result))
	}

	subtitle := a.backend.Describe()
	if subtitleExtra != "" {
		subtitle += "  ·  " + subtitleExtra
	}
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}
	return ui.Header{Title: "tui-secure", Subtitle: subtitle, Facts: facts}.
		Render(t, a.width)
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	count := strconv.Itoa(len(a.visible))
	if a.filter != "" {
		return count + " of " + strconv.Itoa(len(a.report.Probes)) +
			" probes  ·  ? for help"
	}
	return count + " probes  ·  enter for detail  ·  ? for help"
}

// probeTable renders the probe list, dropping columns on narrow terminals.
func (a *app) probeTable() string {
	columns := []ui.Column{
		{Title: "PROBE", Width: 22},
		{Title: "VERDICT", Width: 8},
		{Title: "SUMMARY", Width: 30, Flex: true},
	}
	// Progressive disclosure: the owner of the fix only when it fits.
	showFix := a.width >= 96
	if showFix {
		columns = append(columns, ui.Column{Title: "FIX", Width: 18})
	}

	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, probe := range a.visible {
		row := []string{probe.Title, string(probe.Status), probe.Summary}
		if showFix {
			row = append(row, fixCell(probe))
		}
		rows = append(rows, row)
		style := a.rowStyle(probe.Status)
		styles = append(styles, &style)
	}

	return ui.Table{
		Columns:  columns,
		Rows:     rows,
		Styles:   styles,
		Selected: a.cursor,
		Offset:   a.offset,
		Height:   a.tableHeight(),
	}.Render(a.theme, a.width)
}

// fixCell names who owns the fix: a sibling tool, this tool itself when it
// offers an action, or nothing at all.
func fixCell(p posture.Probe) string {
	switch {
	case len(p.Actions) > 0:
		return "a to fix here"
	case p.Fix.Tool != "":
		return p.Fix.Tool
	case p.Fix.Command != "":
		return "a command"
	default:
		return ""
	}
}

// styleFor is the theme style a verdict is drawn in.
func (a *app) styleFor(status posture.Status) lipgloss.Style {
	switch status {
	case posture.StatusOK:
		return a.theme.OK
	case posture.StatusWarn:
		return a.theme.Warn
	case posture.StatusBad:
		return a.theme.Danger
	default:
		return a.theme.Muted
	}
}

// rowStyle colours a row by its verdict, so the machine's problems are visible
// before a single word is read.
func (a *app) rowStyle(status posture.Status) lipgloss.Style {
	return a.theme.Row.Foreground(a.styleFor(status).GetForeground())
}

// detailView renders one probe in full: its verdict, the settings behind it,
// the commands that were run, their raw output and the fix.
func (a *app) detailView() string {
	probe, ok := a.report.Probe(a.detailID)
	if !ok {
		return a.listView()
	}
	header := a.headerView(probe.Title)
	lines := detailLines(probe)

	height := a.detailHeight()
	offset := min(a.detailOffset, max(len(lines)-height, 0))
	a.detailOffset = offset
	end := min(offset+height, len(lines))

	body := make([]string, 0, height)
	for _, line := range lines[offset:end] {
		body = append(body, a.theme.Row.Width(a.width).Render(
			ui.Truncate(line, a.width-2)))
	}
	for i := len(body); i < height; i++ {
		body = append(body, a.theme.Row.Width(a.width).Render(""))
	}

	help := ui.HelpBar(a.theme, a.detailHelpKeys(probe), a.width)
	position := strconv.Itoa(offset+1) + "–" + strconv.Itoa(end) +
		" of " + strconv.Itoa(len(lines)) + " lines  ·  esc to go back"
	status := ui.StatusLine(a.theme, a.statusKind, a.status, position, a.width)
	return strings.Join([]string{header,
		strings.Join(body, "\n"), help, status}, "\n")
}

// detailLines builds the detail screen's text, section by section. It returns
// plain strings so the screen can be scrolled and width-truncated in one
// place.
//
// The order is the order a reader needs it in: the verdict, what it was
// assembled from, the commands that were asked, the fix, and only then the
// raw output — which is the longest part and the one you scroll to when you
// do not believe the rest.
func detailLines(probe posture.Probe) []string {
	lines := []string{
		probe.Title + " — " + string(probe.Status),
		"",
		"  " + probe.Summary,
	}
	if probe.Reason != "" {
		lines = append(lines, "  why unknown: "+probe.Reason)
	}

	if findings := visibleFindings(probe); len(findings) > 0 {
		lines = append(lines, "", "What was read")
		width := 0
		for _, finding := range findings {
			width = max(width, len(finding.Label))
		}
		for _, finding := range findings {
			line := "  " + pad(finding.Label, width) + "  " + finding.Value
			if finding.Status != posture.StatusOK {
				line += "  [" + string(finding.Status) + "]"
			}
			lines = append(lines, line)
			if finding.Note != "" {
				lines = append(lines, "  "+pad("", width)+"  ("+finding.Note+")")
			}
		}
	}

	lines = append(lines, "", "Evidence")
	if len(probe.Evidence) == 0 {
		lines = append(lines, "  (this probe read no command output)")
	}
	for _, evidence := range probe.Evidence {
		lines = append(lines, "  $ "+evidence.Command)
		if evidence.Line != "" {
			lines = append(lines, "    → "+evidence.Line)
		}
	}

	if probe.Fix.Hint != "" || probe.Fix.Tool != "" || probe.Fix.Command != "" {
		lines = append(lines, "", "Fix")
		if probe.Fix.Hint != "" {
			lines = append(lines, wrapInto("  ", probe.Fix.Hint, 76)...)
		}
		if probe.Fix.Tool != "" {
			lines = append(lines, "  owned by: "+probe.Fix.Tool)
		}
		if probe.Fix.Command != "" {
			lines = append(lines, "  $ "+probe.Fix.Command)
		}
	}
	for _, action := range probe.Actions {
		lines = append(lines, "  a → "+action.Label)
	}

	if strings.TrimSpace(probe.Raw) != "" {
		lines = append(lines, "", "Raw output")
		for _, line := range strings.Split(
			strings.TrimSuffix(probe.Raw, "\n"), "\n") {
			lines = append(lines, "  "+line)
		}
	}
	return lines
}

// visibleFindings drops the one finding that exists for the header rather than
// for the reader.
func visibleFindings(probe posture.Probe) []posture.Finding {
	kept := make([]posture.Finding, 0, len(probe.Findings))
	for _, finding := range probe.Findings {
		if finding.Label == "stack" {
			continue
		}
		kept = append(kept, finding)
	}
	return kept
}

// pad right-pads a label so the values line up.
func pad(s string, width int) string {
	for len(s) < width {
		s += " "
	}
	return s
}

// wrapInto breaks a sentence into indented lines no wider than width. The
// detail screen truncates to the terminal anyway; this keeps a long fix hint
// readable on a wide one.
func wrapInto(indent, text string, width int) []string {
	var lines []string
	current := indent
	for _, word := range strings.Fields(text) {
		if len(current)+len(word)+1 > width && strings.TrimSpace(current) != "" {
			lines = append(lines, current)
			current = indent
		}
		if strings.TrimSpace(current) != "" {
			current += " "
		}
		current += word
	}
	if strings.TrimSpace(current) != "" {
		lines = append(lines, current)
	}
	return lines
}

// bodyForDialog trims a plan's body to what fits above the command preview,
// saying how much was left out. The kit's dialog does not scroll, so a body
// longer than the terminal would push the command preview off the screen —
// and the command preview is the one thing that must never be missed.
func (a *app) bodyForDialog(body string) string {
	budget := max(min(a.height-12, dialogBodyLines), 4)
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if len(lines) <= budget {
		return body
	}
	kept := append([]string{}, lines[:budget]...)
	return strings.Join(kept, "\n") + "\n… " +
		strconv.Itoa(len(lines)-budget) + " more lines"
}

// dialogBodyLines is the most body the confirm dialog will show.
const dialogBodyLines = 14

// shortHelpKeys is the single-line hint bar of the posture screen.
func (a *app) shortHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "enter", Desc: "detail"},
		{Key: "a", Desc: "fix"},
		{Key: "r", Desc: "re-run all"},
		{Key: "R", Desc: "re-run one"},
		{Key: "/", Desc: "filter"},
		{Key: "?", Desc: "help"},
		{Key: "q", Desc: "quit"},
	}
}

// detailHelpKeys is the hint bar of the detail screen, which offers the fix
// only when there is one.
func (a *app) detailHelpKeys(probe posture.Probe) []ui.KeyHint {
	hints := []ui.KeyHint{{Key: "↑/↓", Desc: "scroll"}}
	if len(probe.Actions) > 0 {
		hints = append(hints, ui.KeyHint{Key: "a", Desc: "fix"})
	}
	return append(hints,
		ui.KeyHint{Key: "R", Desc: "re-run"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "esc", Desc: "back"})
}

// helpKeys is the full key list shown on the help screen.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "↑/k, ↓/j", Desc: "move the selection, or scroll the detail screen"},
		{Key: "g / G", Desc: "first / last probe"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "enter", Desc: "open the probe: evidence, raw output and the fix"},
		{Key: "esc", Desc: "leave the detail screen"},
		{Key: "/", Desc: "filter the probes (esc clears)"},
		{Key: "a", Desc: "apply an offered fix, previewed and confirmed first"},
		{Key: "r", Desc: "re-run every probe"},
		{Key: "R", Desc: "re-run the selected probe"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "verdicts", Desc: "ok · warn · bad · unknown (nobody could answer)"},
		{Key: "note", Desc: "every change is previewed and confirmed first"},
		{Key: "note", Desc: "most fixes belong to a sibling tool, and are named"},
	}
}
