package host

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// Enabling ufw used to be confirmed twice: once by this tool's dialog, and
// once by ufw itself, which asks "Command may disrupt existing ssh
// connections. Proceed (y|n)?" when it runs under an ssh session. The command
// now runs with --force, because it runs without a terminal to answer on, so
// the question ufw asked is asked here instead — with the answer to it read
// from the rules ufw is about to load, before the user says y.

// SSHAccess is what the rules ufw will load say about the ssh port.
type SSHAccess struct {
	// Port is the ssh port that was checked.
	Port string
	// Session reports that this process runs inside an ssh session, and Port
	// is the port that session came in on.
	Session bool
	// Source says where Port came from, for the dialog.
	Source string
	// Known reports that ufw's rules were read. When they were not, nothing
	// below is an answer.
	Known bool
	// Allowed reports that an incoming connection to Port from anywhere will
	// be let through.
	Allowed bool
	// Restricted reports that Port is allowed only from some sources or on
	// some interfaces: whether the session survives depends on where it comes
	// from.
	Restricted bool
	// Rule is the `ufw show added` line that decided, empty when none did.
	Rule string
	// DefaultAccept reports that ufw's default incoming policy is ACCEPT, which
	// lets the port through with no rule at all.
	DefaultAccept bool
}

// UfwRuleVerdict is what one rule list says about one port.
type UfwRuleVerdict struct {
	Allowed    bool
	Restricted bool
	Denied     bool
	Rule       string
}

// ParseUfwAddedForPort reads `ufw show added` and decides what the rules say
// about incoming tcp traffic to one port. ufw evaluates its rules in order and
// the first match wins, so the first rule that applies to the port from
// anywhere decides; a rule limited to some sources or interfaces is noted and
// the search goes on. Outgoing and routed rules never apply to an incoming
// ssh connection and are skipped.
func ParseUfwAddedForPort(out, port string) UfwRuleVerdict {
	var restricted string
	for _, line := range splitLines(out) {
		rule, ok := parseUfwRule(line)
		if !ok || !rule.matches(port) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		switch {
		case rule.allows() && !rule.limited():
			return UfwRuleVerdict{Allowed: true, Rule: trimmed}
		case rule.allows():
			if restricted == "" {
				restricted = trimmed
			}
		case !rule.limited():
			// A deny or reject for everyone, ahead of any allow for everyone.
			return UfwRuleVerdict{Denied: true, Rule: trimmed}
		}
	}
	if restricted != "" {
		return UfwRuleVerdict{Restricted: true, Rule: restricted}
	}
	return UfwRuleVerdict{}
}

// ufwRule is one parsed `ufw ...` line.
type ufwRule struct {
	action    string
	direction string
	iface     string
	from      string
	to        string
	fromPort  string
	toPort    string
	proto     string
	app       string
	spec      string
}

// parseUfwRule reads one line of `ufw show added`: either the simple syntax
// (`ufw allow 22/tcp`, `ufw limit OpenSSH`) or the full one (`ufw allow from
// 10.0.0.0/8 to any port 22 proto tcp`). A line it does not understand, or a
// routed rule, is reported as not a rule.
func parseUfwRule(line string) (ufwRule, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 || fields[0] != "ufw" {
		return ufwRule{}, false
	}
	fields = fields[1:]
	if fields[0] == "route" {
		return ufwRule{}, false
	}
	rule := ufwRule{action: fields[0]}
	switch rule.action {
	case "allow", "limit", "deny", "reject":
	default:
		return ufwRule{}, false
	}
	fields = fields[1:]
	if len(fields) > 0 && (fields[0] == "in" || fields[0] == "out") {
		rule.direction = fields[0]
		fields = fields[1:]
	}
	if len(fields) > 0 && strings.HasPrefix(fields[0], "log") {
		fields = fields[1:]
	}
	if len(fields) == 0 {
		return ufwRule{}, false
	}

	full := false
	for _, f := range fields {
		switch f {
		case "on", "from", "to", "port", "proto", "app":
			full = true
		}
	}
	if !full {
		// The simple syntax: everything left is one port, service or app
		// name, which ufw prints quoted when it has a space in it.
		rule.spec = strings.Trim(strings.Join(fields, " "), "'\"")
		return rule, true
	}

	side := ""
	for i := 0; i < len(fields); i++ {
		next := ""
		if i+1 < len(fields) {
			next = strings.Trim(fields[i+1], "'\"")
		}
		switch fields[i] {
		case "on":
			rule.iface, i = next, i+1
		case "from":
			rule.from, side, i = next, "from", i+1
		case "to":
			rule.to, side, i = next, "to", i+1
		case "port":
			if side == "from" {
				rule.fromPort = next
			} else {
				rule.toPort = next
			}
			i++
		case "app":
			if side == "to" || side == "" {
				rule.app = next
			}
			i++
		case "proto":
			rule.proto, i = next, i+1
		case "comment":
			i = len(fields)
		}
	}
	return rule, true
}

// allows reports whether the rule lets matching traffic in.
func (r ufwRule) allows() bool { return r.action == "allow" || r.action == "limit" }

// limited reports whether the rule applies only to some of the traffic to the
// port: from some sources, from some source ports, to some local address, or
// on some interface.
func (r ufwRule) limited() bool {
	return r.iface != "" || !anyAddress(r.from) || !anyAddress(r.to) ||
		r.fromPort != ""
}

// anyAddress reports whether an address in a ufw rule means everywhere.
func anyAddress(address string) bool {
	switch address {
	case "", "any", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

// matches reports whether the rule applies to incoming tcp traffic to port.
func (r ufwRule) matches(port string) bool {
	if r.direction == "out" {
		return false
	}
	if r.spec != "" {
		spec, proto, _ := strings.Cut(r.spec, "/")
		if proto != "" && proto != "tcp" {
			return false
		}
		return portInSpec(spec, port)
	}
	if r.proto != "" && r.proto != "tcp" && r.proto != "any" {
		return false
	}
	switch {
	case r.app != "":
		return portInSpec(r.app, port)
	case r.toPort != "":
		return portInSpec(r.toPort, port)
	}
	// No port at all: the rule covers every port.
	return true
}

// sshNames are the service and application profile names ufw resolves to
// port 22: the /etc/services entry and the profile openssh-server ships.
var sshNames = map[string]bool{"ssh": true, "openssh": true}

// portInSpec reports whether a ufw port list ("22", "22,80", "1000:2000",
// "ssh", "OpenSSH") includes port.
func portInSpec(spec, port string) bool {
	if sshNames[strings.ToLower(spec)] {
		return port == "22"
	}
	want, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		low, high, isRange := strings.Cut(part, ":")
		lo, errLo := strconv.Atoi(low)
		if errLo != nil {
			continue
		}
		hi := lo
		if isRange {
			if v, errHi := strconv.Atoi(high); errHi == nil {
				hi = v
			}
		}
		if want >= lo && want <= hi {
			return true
		}
	}
	return false
}

// ParseUfwDefaultInput reads DEFAULT_INPUT_POLICY out of /etc/default/ufw.
func ParseUfwDefaultInput(text string) string {
	for _, line := range splitLines(text) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "DEFAULT_INPUT_POLICY" {
			return strings.ToUpper(strings.Trim(strings.TrimSpace(value), "\"'"))
		}
	}
	return ""
}

// SSHSessionPort returns the local port of the ssh session this process runs
// in, read from SSH_CONNECTION ("client-ip client-port server-ip
// server-port"), or "" outside one.
func SSHSessionPort(sshConnection string) string {
	fields := strings.Fields(sshConnection)
	if len(fields) != 4 {
		return ""
	}
	if _, err := strconv.Atoi(fields[3]); err != nil {
		return ""
	}
	return fields[3]
}

// ufwDefaultPath is where ufw keeps its default policies.
const ufwDefaultPath = "/etc/default/ufw"

// sshAccess reads what enabling ufw would do to ssh: which port matters, and
// what the rules ufw will load say about it. Every read here is read-only;
// `ufw show added` needs root and goes through the privileged runner.
func (r *Real) sshAccess(ctx context.Context) SSHAccess {
	access := SSHAccess{}
	if port := SSHSessionPort(os.Getenv("SSH_CONNECTION")); port != "" {
		access.Port, access.Session, access.Source = port, true, "this ssh session"
	} else {
		r.mu.Lock()
		configured := r.sshdSettingsSeen["port"]
		r.mu.Unlock()
		if configured != "" {
			access.Port, access.Source = configured, "sshd's configuration"
		} else {
			access.Port, access.Source = "22", "sshd's default"
		}
	}

	out, _, err := r.readPrivileged(ctx, &collector{}, "ufw", "show", "added")
	if err != nil || !strings.Contains(out, "Added user rules") {
		return access
	}
	access.Known = true
	verdict := ParseUfwAddedForPort(out, access.Port)
	access.Allowed, access.Restricted, access.Rule =
		verdict.Allowed, verdict.Restricted, verdict.Rule
	if !verdict.Allowed && !verdict.Denied {
		//nolint:gosec // a fixed path, not user input
		if text, readErr := os.ReadFile(ufwDefaultPath); readErr == nil &&
			ParseUfwDefaultInput(string(text)) == "ACCEPT" {
			access.DefaultAccept, access.Allowed = true, true
		}
	}
	return access
}

// UfwEnablePlan builds the confirm dialog for enabling ufw. The dialog is
// always red, as any firewall enable is; what changes with the rules is the
// first thing it says. When the ssh port is not plainly allowed the title
// itself carries the warning, so it is the first line read, in the danger
// color, before y.
func UfwEnablePlan(access SSHAccess) (posture.Plan, error) {
	cmd, err := BuildUfwEnable()
	if err != nil {
		return posture.Plan{}, err
	}
	port := access.Port
	who := "ssh port " + port + "/tcp (from " + access.Source + ")"
	cutoff := "ends any ssh session to this machine and locks out new ones"
	if access.Session {
		who = "port " + port + "/tcp (the port this ssh session came in on)"
		cutoff = "ends this ssh session and locks out every new one"
	}

	title := "Enable ufw"
	var status string
	switch {
	case !access.Known:
		title = "Enable ufw: ssh port " + port + " could not be checked"
		status = "WARNING: ufw's rules could not be read (`ufw show added` " +
			"needs root), so nobody has checked that " + who + " stays open. " +
			"If it does not, enabling ufw " + cutoff + "."
	case access.DefaultAccept:
		status = "ssh stays reachable: ufw's default incoming policy is " +
			"ACCEPT, so " + who + " is let through with no rule."
	case access.Allowed:
		status = "ssh stays reachable: " + who + " is allowed by the rule `" +
			access.Rule + "`."
	case access.Restricted:
		title = "Enable ufw: ssh port " + port + " is allowed only from some places"
		status = "WARNING: " + who + " is allowed only by `" + access.Rule +
			"`. A connection from anywhere else is dropped once ufw is on; " +
			"make sure yours matches before answering y."
	default:
		title = "Enable ufw: ssh port " + port + " is NOT allowed"
		status = "WARNING: no rule ufw will load allows " + who + ". Enabling " +
			"ufw " + cutoff + ".\nAllow it first (sudo ufw allow " + port +
			"/tcp), or answer y only if you have another way in."
	}

	body := status + "\n\nufw will start filtering now and on every boot. " +
		"ufw would normally ask about ssh itself; this dialog is that question, " +
		"so the command runs with --force."
	return posture.Plan{
		Title:    title,
		Body:     body,
		Commands: []posture.Command{cmd},
		Danger:   true,
	}, nil
}

// ufwPlan reads the machine and builds the plan.
func (r *Real) ufwPlan() (posture.Plan, error) {
	return UfwEnablePlan(r.sshAccess(context.Background()))
}
