package host

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// This file is how tui-secure tells a running sshd from an idle,
// socket-activated one, and what it does differently for the second.
//
// Since 22.10, Ubuntu enables ssh.socket and leaves ssh.service disabled: the
// socket listens on port 22 and starts sshd on the first connection. Until
// somebody connects, `systemctl is-active ssh` says "inactive", and a probe
// that only asked the service read the machine as having no ssh server at
// all, graded its settings as harmless and offered a reload that fails with
// "ssh.service is not active, cannot reload". The same idle state also leaves
// /run/sshd (the service's RuntimeDirectory) missing, and sshd then refuses
// both `sshd -T` and `sshd -t -f` before reading a keyword. tui-ssh handles
// the same two cases the same way.

// SSHDService is the ssh server as this machine runs it.
type SSHDService struct {
	// Unit is the service name: ssh on Debian and Ubuntu, sshd elsewhere.
	Unit string
	// Running reports that the service itself is active.
	Running bool
	// Socket is the socket unit that starts the service on demand, empty when
	// no such socket is listening.
	Socket string
}

// SocketActivated reports that a socket unit is listening for sshd, whether or
// not the service has been started by a connection yet.
func (s SSHDService) SocketActivated() bool { return s.Socket != "" }

// Exposed reports whether a connection to this machine reaches sshd today:
// either the server is running, or a socket is listening and will start it.
// An idle socket-activated server is exposed exactly as much as a running one.
func (s SSHDService) Exposed() bool { return s.Running || s.SocketActivated() }

// State is the one-line description the probe shows next to "running".
func (s SSHDService) State() string {
	switch {
	case s.Running && s.SocketActivated():
		return s.Unit + " is active, started by " + s.Socket
	case s.Running:
		return s.Unit + " is active"
	case s.SocketActivated():
		return s.Unit + " idle, " + s.Socket + " listening"
	default:
		return "not running"
	}
}

// sshdServiceUnits are the service names the ssh server is packaged under, in
// the order they are asked about, and the socket that goes with each.
var sshdServiceUnits = []struct{ service, socket string }{
	{"sshd", "sshd.socket"},
	{"ssh", "ssh.socket"},
}

// ResolveSSHDService decides how the ssh server runs here from what
// `systemctl is-active` says about each candidate unit. activeState is given a
// unit name and returns its state ("active", "inactive", ...), or "" when it
// could not be read. It is a function of those answers alone, so a test can
// describe a machine without having one.
//
// A running service wins, and its own socket is then asked about, so the reload
// on an Ubuntu machine somebody has already connected to is still the one that
// works whether or not the service is running. With no service running, a
// listening socket is what makes the server reachable.
func ResolveSSHDService(activeState func(unit string) string) SSHDService {
	for _, candidate := range sshdServiceUnits {
		if activeState(candidate.service) != "active" {
			continue
		}
		service := SSHDService{Unit: candidate.service, Running: true}
		if activeState(candidate.socket) == "active" {
			service.Socket = candidate.socket
		}
		return service
	}
	for _, candidate := range sshdServiceUnits {
		if activeState(candidate.socket) == "active" {
			return SSHDService{Unit: candidate.service, Socket: candidate.socket}
		}
	}
	return SSHDService{Unit: "sshd"}
}

// sshdSocketRe is the pair of socket units this tool knows start sshd.
var sshdSocketRe = regexp.MustCompile(`^(sshd|ssh)\.socket$`)

// BuildSSHDApply is the command that makes sshd pick up an installed drop-in.
//
// On a machine where the service runs sshd directly it is the plain reload.
// Where a socket starts sshd on demand, or where the service is not running at
// all, `systemctl reload` fails with "is not active, cannot reload" after the
// file is already in place. `try-reload-or-restart` reloads a running sshd the
// same way (sshd has a reload action, so it is never restarted) and leaves a
// stopped one alone, which reads the new file when it next starts.
func BuildSSHDApply(service SSHDService) (posture.Command, error) {
	if service.Running && !service.SocketActivated() {
		return BuildSSHDReload(service.Unit)
	}
	if !sshdUnitRe.MatchString(service.Unit) {
		return posture.Command{}, fmt.Errorf("host: %q is not an ssh server unit", service.Unit)
	}
	description := "Reload " + service.Unit + " if it is running; it reads the " +
		"new file when it next starts otherwise"
	if service.SocketActivated() {
		if !sshdSocketRe.MatchString(service.Socket) {
			return posture.Command{}, fmt.Errorf("host: %q is not an ssh socket unit",
				service.Socket)
		}
		description = "Reload " + service.Unit + " if it is running; " +
			service.Socket + " starts it with the new file otherwise"
	}
	return posture.Command{
		Argv:        []string{"systemctl", "try-reload-or-restart", service.Unit},
		Description: description,
		Destructive: true,
	}, nil
}

// privsepRe matches the line sshd prints, and exits on, when the privilege
// separation directory compiled into it does not exist. It refuses `sshd -T`
// and `sshd -t -f` alike, before it reads a single keyword.
var privsepRe = regexp.MustCompile(`Missing privilege separation directory: (\S+)`)

// runtimePrivsepRe is the shape of a privilege separation directory that is a
// runtime directory: one level under /run (or /var/run), which systemd creates
// when the service starts and removes when it stops. Debian and Ubuntu build
// sshd with /run/sshd. Other distributions use a directory the package ships
// (/var/empty/sshd, /usr/share/empty.sshd), whose absence is a broken
// installation and not something to create here.
var runtimePrivsepRe = regexp.MustCompile(`^/(?:var/)?run/[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// PrivsepDirMode is the mode systemd gives a RuntimeDirectory by default.
const PrivsepDirMode = "0755"

// MissingPrivsepDir reports whether sshd's output is the missing privilege
// separation directory message, and which directory it named. The directory is
// read from sshd's own words because it is a build-time choice.
func MissingPrivsepDir(out string) (string, bool) {
	match := privsepRe.FindStringSubmatch(out)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// IsRuntimePrivsepDir reports whether a privilege separation directory is a
// runtime directory, the only kind tui-secure offers to create.
func IsRuntimePrivsepDir(dir string) bool {
	return runtimePrivsepRe.MatchString(dir)
}

// BuildEnsurePrivsepDir creates a missing runtime privilege separation
// directory the way systemd would: root-owned, mode 0755. It refuses anything
// that is not a single directory under /run, so a path sshd printed can never
// turn into a write somewhere else.
func BuildEnsurePrivsepDir(dir string) (posture.Command, error) {
	if !IsRuntimePrivsepDir(dir) {
		return posture.Command{}, fmt.Errorf("host: %s", PrivsepExplanation(dir, SSHDService{}))
	}
	return posture.Command{
		Argv: []string{"install", "-d", "-m", PrivsepDirMode,
			"-o", "root", "-g", "root", dir},
		Description: "Create " + dir + ", the directory sshd needs before it " +
			"will check a file",
		Destructive: true,
	}, nil
}

// PrivsepExplanation says why sshd could not check a configuration and how
// that state ends.
func PrivsepExplanation(dir string, service SSHDService) string {
	if !IsRuntimePrivsepDir(dir) {
		return "sshd's privilege separation directory " + dir + " is missing. " +
			"It ships with the OpenSSH server package rather than being created " +
			"at start, so reinstalling the package restores it; until then sshd " +
			"cannot check a configuration, and tui-secure installs nothing unchecked"
	}
	unit := service.Unit
	if unit == "" {
		unit = "sshd"
	}
	if service.SocketActivated() && !service.Running {
		return unit + ".service is idle under socket activation, and " + dir +
			" is its RuntimeDirectory: it appears when the service starts, on " +
			"the first connection. Until then sshd cannot check a configuration, " +
			"so a change creates " + dir + " first"
	}
	return dir + " (the RuntimeDirectory of " + unit + ".service) does not " +
		"exist, so the service has not started since boot. Until it does, sshd " +
		"cannot check a configuration, so a change creates " + dir + " first"
}

// sshdFixCommand is the shell line the fix column shows for the sshd row.
func sshdFixCommand(service SSHDService) string {
	apply := "reload"
	if !service.Running || service.SocketActivated() {
		apply = "try-reload-or-restart"
	}
	unit := service.Unit
	if unit == "" {
		unit = "sshd"
	}
	return "sudo sshd -t && sudo systemctl " + apply + " " + unit
}

// sshdStackValue is the short name the header shows for the ssh server.
func sshdStackValue(service SSHDService) string {
	switch {
	case service.Running:
		return "sshd: running"
	case service.SocketActivated():
		return "sshd: idle (" + service.Socket + ")"
	default:
		return "sshd: stopped"
	}
}

// activeState reads one `systemctl is-active` answer. is-active exits non-zero
// for every state but active and prints the state anyway, so the exit code is
// not the answer: the first line of output is. Only "active" is ever acted on.
func activeState(out string) string {
	if lines := splitLines(out); len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}
