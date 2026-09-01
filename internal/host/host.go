// Package host is the machine backend of tui-secure, and the only place in the
// repository that starts a process.
//
// Everything about reaching the machine — resolving the binaries, applying the
// privilege prefix, bounding each call, turning a failure into one readable
// line — belongs to the kit runner. What is left here is the translation
// between what the system's own tools print and the verdicts in
// internal/posture, and the assembly of the argv that a confirm dialog will
// show before it runs.
//
// Two rules hold across every probe in this package:
//
//   - A read that needs a privilege this process does not have is not a
//     failure. It is `unknown`, with the reason. Escalation is `sudo -n`,
//     which never prompts, so a probe cannot block the screen on a password.
//   - A binary that is not installed is not a failure either. A machine
//     without ufw is a machine with a different firewall, or none, and both
//     are answers.
//
// Almost everything here reads. The things that write — turning a firewall on,
// setting one kernel hardening key or one sshd keyword through a drop-in,
// enabling the update timer, stopping the unit behind a port — are built in
// command.go and sshd.go, previewed, and run only after a confirm dialog.
package host

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// ErrNotAvailable reports that a command this machine does not have was asked
// for. It is the kit's sentinel, re-exported so callers need not import runner.
var ErrNotAvailable = runner.ErrNotAvailable

// searchPaths are the locations a non-root PATH commonly omits. The security
// tools are the worst offenders: nearly all of them live in an sbin directory
// that an unprivileged shell has never heard of.
var searchPaths = map[string][]string{
	"bootctl":          {"/usr/bin/bootctl", "/bin/bootctl"},
	"sbctl":            {"/usr/bin/sbctl", "/bin/sbctl"},
	"getenforce":       {"/usr/sbin/getenforce", "/sbin/getenforce", "/usr/bin/getenforce"},
	"sestatus":         {"/usr/sbin/sestatus", "/sbin/sestatus", "/usr/bin/sestatus"},
	"aa-status":        {"/usr/sbin/aa-status", "/sbin/aa-status", "/usr/bin/aa-status"},
	"ausearch":         {"/usr/sbin/ausearch", "/sbin/ausearch", "/usr/bin/ausearch"},
	"journalctl":       {"/usr/bin/journalctl", "/bin/journalctl"},
	"systemctl":        {"/usr/bin/systemctl", "/bin/systemctl"},
	"ufw":              {"/usr/sbin/ufw", "/sbin/ufw"},
	"firewall-cmd":     {"/usr/bin/firewall-cmd", "/bin/firewall-cmd"},
	"nft":              {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"},
	"sshd":             {"/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"},
	"ss":               {"/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss"},
	"sysctl":           {"/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"},
	"sudo":             {"/usr/bin/sudo", "/bin/sudo"},
	"cat":              {"/usr/bin/cat", "/bin/cat"},
	"install":          {"/usr/bin/install", "/bin/install"},
	"checkupdates":     {"/usr/bin/checkupdates", "/bin/checkupdates"},
	"pacman":           {"/usr/bin/pacman", "/bin/pacman"},
	"apt-get":          {"/usr/bin/apt-get", "/bin/apt-get"},
	"dnf":              {"/usr/bin/dnf", "/bin/dnf"},
	"needs-restarting": {"/usr/bin/needs-restarting", "/bin/needs-restarting"},
}

// osReleasePath and kernelPath are read directly rather than through `uname`
// and a shell: they are files, the kernel keeps them current, and reading a
// file needs no process at all.
const (
	osReleasePath = "/etc/os-release"
	kernelPath    = "/proc/sys/kernel/osrelease"
)

// Real probes the machine this tool is running on. It satisfies
// posture.Backend.
type Real struct {
	// sudo is the escalation prefix from the configuration, nil when the
	// commands run directly (as root, or with --sudo "").
	sudo []string

	// runners are built on first use and kept: a probe asks for a binary by
	// name and either gets one or finds out this machine has no such command.
	// Two sets, because escalation is per call site rather than per binary —
	// `systemctl is-active` needs nothing, `sshd -T` needs root.
	mu        sync.Mutex
	plain     map[string]*runner.Runner
	escalated map[string]*runner.Runner
	missing   map[string]error

	// staged is the drop-in file a sysctl or sshd action has written to a
	// private temporary directory, keyed by destination. Nothing reaches /etc
	// until the confirmed install command runs.
	staged map[string]string

	// What the probes learned that an action later needs. An action is only
	// ever offered by a probe that has just read this machine, so building the
	// plan from that same read is what keeps the command in the dialog and the
	// verdict on the screen talking about the same thing.
	//
	// sshdUnit is the ssh server's unit name (sshd, or ssh on Debian) and
	// sshdSettingsSeen the effective configuration the ssh probe read.
	// portUnits maps a listening port to the unit the ports probe traced it
	// back to.
	sshdUnit         string
	sshdSettingsSeen map[string]string
	portUnits        map[string]string
}

// NewReal builds the host backend. sudoPrefix comes from the configuration
// ("sudo -n"); pass nil to run the commands directly.
//
// It cannot fail: unlike a tool that drives one backend, tui-secure has no
// single binary whose absence means "nothing to show". A machine missing every
// program it looks for still gets a screen — of eight unknowns, each naming
// what it wanted.
func NewReal(sudoPrefix []string) (*Real, error) {
	return &Real{
		sudo:      sudoPrefix,
		plain:     map[string]*runner.Runner{},
		escalated: map[string]*runner.Runner{},
		missing:   map[string]error{},
		staged:    map[string]string{},
		portUnits: map[string]string{},
	}, nil
}

// Name identifies the backend.
func (r *Real) Name() string { return "host" }

// Describe is the one-line summary shown in the header: how this process
// reaches the machine.
func (r *Real) Describe() string {
	if len(r.sudo) == 0 {
		return "this machine (root)"
	}
	return "this machine, escalating with " + strings.Join(r.sudo, " ")
}

// runnerFor returns the runner for a binary, building it on first use.
// escalate decides whether *reads* through it are wrapped in the privilege
// prefix; a command run through Run always is.
func (r *Real) runnerFor(bin string, escalate bool) (*runner.Runner, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cache := r.plain
	if escalate {
		cache = r.escalated
	}
	if run, ok := cache[bin]; ok {
		return run, nil
	}
	key := bin
	if escalate {
		key = "sudo:" + bin
	}
	if err, ok := r.missing[key]; ok {
		return nil, err
	}

	unprivileged := false
	opts := runner.Options{
		Bin:         bin,
		SearchPaths: searchPaths[bin],
		SudoPrefix:  r.sudo,
	}
	if !escalate {
		opts.PrivilegedReads = &unprivileged
	}
	run, err := runner.New(opts)
	if err != nil {
		r.missing[key] = err
		return nil, err
	}
	cache[bin] = run
	return run, nil
}

// Preview renders the exact command line Run will execute. Every command goes
// through the runner of its own binary, so the preview carries the privilege
// prefix that binary will really be called with.
func (r *Real) Preview(cmd posture.Command) string {
	if len(cmd.Argv) == 0 {
		return ""
	}
	run, err := r.runnerFor(cmd.Argv[0], true)
	if err != nil {
		// The binary is missing, so there is no resolved path to show. The
		// argv is still the honest answer to "what would this run".
		if len(r.sudo) == 0 {
			return cmd.String()
		}
		return strings.Join(r.sudo, " ") + " " + cmd.String()
	}
	return run.Preview(cmd)
}

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd posture.Command) (string, error) {
	if len(cmd.Argv) == 0 {
		return "", fmt.Errorf("host: nothing to run")
	}
	run, err := r.runnerFor(cmd.Argv[0], true)
	if err != nil {
		return "", err
	}
	return run.Run(ctx, cmd)
}

// collector accumulates what a probe read: the evidence lines it will show,
// and the full output underneath them.
type collector struct {
	evidence []posture.Evidence
	raw      strings.Builder
}

// record appends a command's full output to the raw block.
func (c *collector) record(preview, output string) {
	if c.raw.Len() > 0 {
		c.raw.WriteString("\n")
	}
	c.raw.WriteString("$ " + preview + "\n")
	if strings.TrimSpace(output) == "" {
		c.raw.WriteString("(no output)\n")
		return
	}
	c.raw.WriteString(strings.TrimSuffix(output, "\n") + "\n")
}

// judged notes that a verdict rests on one line of a command's output.
func (c *collector) judged(preview, line string) {
	c.evidence = append(c.evidence,
		posture.Evidence{Command: preview, Line: strings.TrimSpace(line)})
}

// read runs an unprivileged read, records it, and returns the output together
// with the command line as the user would type it.
func (r *Real) read(ctx context.Context, c *collector,
	argv ...string) (out, preview string, err error) {
	return r.runRead(ctx, c, false, argv...)
}

// readPrivileged runs a read through `sudo -n`. It is used only where the
// underlying tool refuses an unprivileged caller.
func (r *Real) readPrivileged(ctx context.Context, c *collector,
	argv ...string) (out, preview string, err error) {
	return r.runRead(ctx, c, true, argv...)
}

// runRead is the shared implementation. A command that fails still has its
// output recorded: `dnf check-update` exits 100 when there are updates, and
// `needs-restarting -r` exits 1 when a reboot is needed, so the exit code is
// part of the answer rather than an error.
func (r *Real) runRead(ctx context.Context, c *collector, escalate bool,
	argv ...string) (out, preview string, err error) {
	run, err := r.runnerFor(argv[0], escalate)
	if err != nil {
		return "", strings.Join(argv, " "), err
	}
	preview = run.Preview(posture.Command{Argv: argv})
	if !escalate {
		preview = strings.Join(argv, " ")
	}
	out, err = run.Read(ctx, argv...)
	c.record(preview, out)
	return out, preview, err
}

// available reports whether a binary exists on this machine.
func (r *Real) available(bin string) bool {
	_, err := r.runnerFor(bin, false)
	return err == nil
}

// Load runs every probe, in the order the screen shows them.
//
// A probe that panics would take the whole screen with it, and a probe is a
// parser fed by a machine nobody controls — so each one is run behind a
// recover that turns the crash into an `unknown` row naming the probe. It has
// never fired; it exists because the alternative is a tool that dies on an
// output shape its author never saw.
func (r *Real) Load(ctx context.Context) (posture.Report, error) {
	report := posture.Report{Backend: r.Name()}
	report.Distro, report.DistroID = distro()
	report.Kernel = kernel()

	for _, id := range posture.IDs {
		probe := r.runProbe(ctx, id)
		report.Probes = append(report.Probes, probe)
	}
	report.Stack = stackOf(report.Probes)
	report.Finish()
	return report, nil
}

// Reload runs one probe again.
func (r *Real) Reload(ctx context.Context, id string) (posture.Probe, error) {
	for _, known := range posture.IDs {
		if known == id {
			return r.runProbe(ctx, id), nil
		}
	}
	return posture.Probe{}, fmt.Errorf("host: no probe called %q", id)
}

// runProbe dispatches one probe by ID and guards it.
func (r *Real) runProbe(ctx context.Context, id string) (probe posture.Probe) {
	defer func() {
		if recovered := recover(); recovered != nil {
			probe = posture.Probe{
				ID: id, Title: titleFor(id), Status: posture.StatusUnknown,
				Summary: "this probe failed to run",
				Reason:  fmt.Sprintf("%v", recovered),
			}
		}
	}()

	switch id {
	case posture.ProbeSecureBoot:
		return r.probeSecureBoot(ctx)
	case posture.ProbeMAC:
		return r.probeMAC(ctx)
	case posture.ProbeFirewall:
		return r.probeFirewall(ctx)
	case posture.ProbeSSH:
		return r.probeSSH(ctx)
	case posture.ProbeUpdates:
		return r.probeUpdates(ctx)
	case posture.ProbeAccounts:
		return r.probeAccounts(ctx)
	case posture.ProbeKernel:
		return r.probeKernel(ctx)
	case posture.ProbePorts:
		return r.probePorts(ctx)
	default:
		return posture.Probe{ID: id, Title: id, Status: posture.StatusUnknown,
			Summary: "no such probe"}
	}
}

// titleFor is the row label of a probe.
func titleFor(id string) string {
	switch id {
	case posture.ProbeSecureBoot:
		return "Secure Boot"
	case posture.ProbeMAC:
		return "Access control (MAC)"
	case posture.ProbeFirewall:
		return "Firewall"
	case posture.ProbeSSH:
		return "SSH server"
	case posture.ProbeUpdates:
		return "Updates"
	case posture.ProbeAccounts:
		return "Accounts"
	case posture.ProbeKernel:
		return "Kernel hardening"
	case posture.ProbePorts:
		return "Listening ports"
	default:
		return id
	}
}

// stackOf reads the header's one-line "what am I looking at" out of the probes
// that found each part.
func stackOf(probes []posture.Probe) posture.Stack {
	stack := posture.Stack{}
	for _, p := range probes {
		switch p.ID {
		case posture.ProbeSecureBoot:
			stack.SecureBoot = detected(p, "SB")
		case posture.ProbeMAC:
			stack.MAC = detected(p, "MAC")
		case posture.ProbeFirewall:
			stack.Firewall = detected(p, "firewall")
		case posture.ProbeSSH:
			stack.SSHD = detected(p, "sshd")
		case posture.ProbeUpdates:
			stack.Updates = detected(p, "updates")
		}
	}
	return stack
}

// detected is the short name a probe recorded for what it found, falling back
// to a plain "unknown" label for the header.
func detected(p posture.Probe, fallback string) string {
	for _, f := range p.Findings {
		if f.Label == stackLabel {
			return f.Value
		}
	}
	return fallback + ": unknown"
}

// stackLabel marks the finding a probe uses to name what it detected. It is
// filtered out of the detail screen, because the header already says it.
const stackLabel = "stack"

// stack builds that finding.
func stack(value string) posture.Finding {
	return posture.Finding{Label: stackLabel, Value: value,
		Status: posture.StatusOK}
}

// distro reads the machine's own name for itself out of /etc/os-release.
func distro() (pretty, id string) {
	raw, err := os.ReadFile(osReleasePath)
	if err != nil {
		return "unknown", ""
	}
	values := map[string]string{}
	for _, line := range splitLines(string(raw)) {
		key, value, ok := cutKey(line)
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"`)
	}
	pretty = values["PRETTY_NAME"]
	if pretty == "" {
		pretty = values["NAME"]
	}
	if pretty == "" {
		pretty = "unknown"
	}
	return pretty, values["ID"]
}

// distroFamily maps a distribution onto the package manager family whose
// commands the update probe knows: "arch", "debian" or "fedora". ID_LIKE is
// consulted so a derivative (Omarchy on Arch, Mint on Ubuntu) is recognised
// without listing every one of them.
func distroFamily() string {
	raw, err := os.ReadFile(osReleasePath)
	if err != nil {
		return ""
	}
	values := map[string]string{}
	for _, line := range splitLines(string(raw)) {
		key, value, ok := cutKey(line)
		if !ok {
			continue
		}
		values[key] = strings.Trim(value, `"`)
	}
	candidates := append([]string{values["ID"]},
		strings.Fields(values["ID_LIKE"])...)
	for _, candidate := range candidates {
		switch candidate {
		case "arch", "archlinux", "omarchy":
			return "arch"
		case "debian", "ubuntu":
			return "debian"
		case "fedora", "rhel", "centos":
			return "fedora"
		}
	}
	return ""
}

// cutKey splits a KEY=value line.
func cutKey(line string) (key, value string, ok bool) {
	i := strings.IndexByte(line, '=')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
}

// kernel is the running kernel release.
func kernel() string {
	raw, err := os.ReadFile(kernelPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// reason turns a failed read into the sentence an unknown probe shows. It
// keeps the runner's own wording, which already names the command that could
// not be run and why.
func reason(err error) string {
	if err == nil {
		return ""
	}
	return runner.FirstLine(err.Error())
}
