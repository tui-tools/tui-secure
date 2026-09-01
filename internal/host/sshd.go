package host

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tui-tools/tui-secure/internal/posture"
)

// This file is the sshd half of what tui-secure can do *to* a machine: the
// keywords it will set, the drop-in it writes them into, and the guard that
// refuses a change which would lock everyone out.
//
// The shape is deliberately the sysctl one. A key is looked up in a table this
// package owns, the file is rendered in full and staged in a private temporary
// directory, and the confirm dialog shows three commands: the server's own
// parser checking the staged file, the install that puts it in /etc, and the
// reload that makes it true. Nothing reaches /etc until all three are agreed
// to, and the check runs first so a file sshd refuses never gets installed.

// SSHDDropInPath is the file an sshd action writes. It belongs to this tool:
// the whole file is regenerated on every change, seeded from what it held
// before, so a keyword this tool does not own does not survive a write.
const SSHDDropInPath = "/etc/ssh/sshd_config.d/50-tui-secure.conf"

// SSHDDropInName is the file's base name, used when comparing against the
// other drop-ins sshd will read.
const SSHDDropInName = "50-tui-secure.conf"

// SSHDFileMode is the mode the drop-in gets. sshd_config drop-ins are read by
// root only, and OpenSSH refuses a configuration file that is group- or
// world-writable, so 0600 is both the safe and the accepted answer.
const SSHDFileMode = "600"

// SSHDKey is one sshd keyword this tool has an opinion about.
type SSHDKey struct {
	// Key is the keyword, spelled the way sshd_config spells it.
	Key string
	// Want is the value tui-secure writes.
	Want string
	// Why is the one line explaining what the value buys.
	Why string
	// Weak reports that a value read from the machine is one this tool offers
	// to change. It is given the value as `sshd -T` printed it, lowercased.
	Weak func(value string) bool
}

// SSHDKeys are the keywords the ssh probe grades and this tool will set, in the
// order the drop-in writes them.
//
// The list is short for the same reason the sysctl one is: every entry is a
// setting whose right value is the same on a laptop, a server and a container
// host. Anything whose answer depends on what the machine is for — Port,
// ListenAddress, AllowUsers — belongs to tui-ssh, which can show the whole
// file.
var SSHDKeys = []SSHDKey{
	{
		Key: "PermitRootLogin", Want: "no",
		Why: "root logs in as itself only from the console; over ssh it is an " +
			"account name every scanner already knows",
		Weak: func(v string) bool {
			switch v {
			case "yes", "prohibit-password", "without-password", "forced-commands-only":
				return true
			}
			return false
		},
	},
	{
		Key: "PasswordAuthentication", Want: "no",
		Why:  "passwords are guessable; keys are not",
		Weak: func(v string) bool { return v == "yes" },
	},
	{
		Key: "PermitEmptyPasswords", Want: "no",
		Why:  "an account with no password would otherwise be an open door",
		Weak: func(v string) bool { return v == "yes" },
	},
	{
		Key: "PubkeyAuthentication", Want: "yes",
		Why:  "key authentication is the way in that this tool assumes exists",
		Weak: func(v string) bool { return v == "no" },
	},
	{
		Key: "MaxAuthTries", Want: "4",
		Why: "each connection gets a bounded number of guesses before it is " +
			"dropped",
		Weak: func(v string) bool {
			tries, err := strconv.Atoi(v)
			return err == nil && tries > 6
		},
	},
	{
		Key: "X11Forwarding", Want: "no",
		Why:  "X11 forwarding exposes the client's display to the server",
		Weak: func(v string) bool { return v == "yes" },
	},
}

// sshdKey finds a keyword by name, case-insensitively, which is how sshd reads
// them and how `sshd -T` prints them back (lowercased).
func sshdKey(name string) (SSHDKey, bool) {
	for _, key := range SSHDKeys {
		if strings.EqualFold(key.Key, name) {
			return key, true
		}
	}
	return SSHDKey{}, false
}

// sshdValueRe is the shape of a value this tool will write into sshd_config.
// The keys come from the table above and so do the values, and both are checked
// anyway: the table is the only thing standing between a future caller and a
// crafted keyword.
var sshdValueRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// RenderSSHDDropIn returns the text of the drop-in with one keyword set.
//
// Unlike the sysctl drop-in, the whole file is regenerated from this package's
// table: it is seeded from what the file holds today, so a keyword agreed to
// earlier survives, but a line naming something this tool does not own is
// dropped rather than carried forward. That is what makes the preview complete
// — the file shown in the dialog is the whole file that will exist.
func RenderSSHDDropIn(existing, key, value string) (string, error) {
	owned, ok := sshdKey(key)
	if !ok {
		return "", fmt.Errorf("host: %q is not a keyword this tool sets", key)
	}
	if !sshdValueRe.MatchString(value) {
		return "", fmt.Errorf("host: %q is not a value this tool will write", value)
	}

	settings := parseSSHDDropIn(existing)
	settings[strings.ToLower(owned.Key)] = value

	var b strings.Builder
	b.WriteString("# Written by tui-secure. Each keyword was previewed and confirmed.\n")
	b.WriteString("# Delete a line and run `sudo systemctl reload sshd` to undo it.\n\n")
	for _, k := range SSHDKeys {
		if set, has := settings[strings.ToLower(k.Key)]; has {
			fmt.Fprintf(&b, "%s %s\n", k.Key, set)
		}
	}
	return b.String(), nil
}

// parseSSHDDropIn reads back the keywords this tool wrote last time, keeping
// only the ones it owns and only values it would write itself.
func parseSSHDDropIn(text string) map[string]string {
	settings := map[string]string{}
	for _, line := range splitLines(text) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) != 2 {
			continue
		}
		owned, ok := sshdKey(fields[0])
		if !ok || !sshdValueRe.MatchString(fields[1]) {
			continue
		}
		settings[strings.ToLower(owned.Key)] = fields[1]
	}
	return settings
}

// stagedPathRe accepts the staging path the sshd commands read and copy. It is
// a path this package built, and it is checked anyway.
var stagedPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// BuildSSHDValidate asks sshd to parse a staged file. It is a read — `sshd -t
// -f` parses the file, says what it thinks of it and exits — and it is the
// first command of the plan, so a file the server refuses never reaches /etc.
func BuildSSHDValidate(tempPath string) (posture.Command, error) {
	if !stagedPathRe.MatchString(tempPath) {
		return posture.Command{}, fmt.Errorf("host: %q is not a staged file path", tempPath)
	}
	return posture.Command{
		Argv:        []string{"sshd", "-t", "-f", tempPath},
		Description: "Check " + tempPath + " with the server's own parser",
	}, nil
}

// BuildInstallSSHDDropIn copies a staged drop-in into /etc/ssh/sshd_config.d.
// `install` is used rather than `cp` because it sets the mode in the same call,
// so there is no window where the file is on disk world-readable.
func BuildInstallSSHDDropIn(tempPath string) (posture.Command, error) {
	if !stagedPathRe.MatchString(tempPath) {
		return posture.Command{}, fmt.Errorf("host: %q is not a staged file path", tempPath)
	}
	return posture.Command{
		Argv: []string{"install", "-m", SSHDFileMode, tempPath, SSHDDropInPath},
		Description: "Install " + tempPath + " as " + SSHDDropInPath +
			", so the setting survives a reboot",
		Destructive: true,
	}, nil
}

// BuildSSHDReload asks the server to re-read its configuration. Reload rather
// than restart: sshd re-execs on SIGHUP, and the sessions already open survive
// it — which matters more here than anywhere else in this tool, because one of
// those sessions is probably the one reading this.
func BuildSSHDReload(unit string) (posture.Command, error) {
	if !sshdUnitRe.MatchString(unit) {
		return posture.Command{}, fmt.Errorf("host: %q is not an ssh server unit", unit)
	}
	return posture.Command{
		Argv:        []string{"systemctl", "reload", unit},
		Description: "Reload " + unit + " so it re-reads its configuration",
		Destructive: true,
	}, nil
}

// sshdUnitRe is the pair of names the ssh server is packaged under: Debian and
// Ubuntu call the unit ssh, everyone else calls it sshd. Nothing else is a unit
// this tool will reload, which is the same detection the ssh probe does and the
// same one tui-ssh does.
var sshdUnitRe = regexp.MustCompile(`^(sshd|ssh)(\.service)?$`)

// LoginPath is a way into this machine over ssh that would still work after a
// change. The guard below counts them, and refuses to remove the last one.
type LoginPath struct {
	// Keys are the accounts found to have at least one authorized key.
	Keys []string
	// Blocked are the accounts whose authorized_keys could not be read, which
	// is what an unprivileged process gets for another user's home directory.
	Blocked []string
}

// authorizedKeyFiles are the per-account files sshd reads by default.
var authorizedKeyFiles = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

// ScanLoginPaths looks for an account on this machine that could log in with a
// key. It reads files only, and it never reports what it read: the account
// names are all that leaves this function, never a key.
//
// An account whose file cannot be read is recorded as blocked rather than
// counted as keyless. The difference decides whether a lockout is refused or
// only warned about, and inventing the answer in either direction would be
// worse than saying which homes could not be looked into.
func ScanLoginPaths(passwd string) LoginPath {
	var found LoginPath
	for _, account := range ParsePasswdLoginAccounts(passwd) {
		hasKey, blocked := false, false
		for _, name := range authorizedKeyFiles {
			path := filepath.Join(account.Home, name)
			// #nosec G304 -- the path is a home directory read out of
			// /etc/passwd joined with a constant file name; the content is
			// tested for a key line and then discarded.
			raw, err := os.ReadFile(path)
			switch {
			case err == nil && hasKeyLine(string(raw)):
				hasKey = true
			case err != nil && !os.IsNotExist(err):
				blocked = true
			}
		}
		switch {
		case hasKey:
			found.Keys = append(found.Keys, account.Name)
		case blocked:
			found.Blocked = append(found.Blocked, account.Name)
		}
	}
	sort.Strings(found.Keys)
	sort.Strings(found.Blocked)
	return found
}

// hasKeyLine reports whether an authorized_keys file holds anything sshd would
// accept as a key, which is any line that is neither blank nor a comment.
func hasKeyLine(text string) bool {
	for _, line := range splitLines(text) {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return true
		}
	}
	return false
}

// SSHDLockout reports why a change must be refused, or "" when it may go ahead.
//
// It is given the configuration as it would be *after* the change, so the
// question it answers is the only one that matters: once this drop-in is
// installed and sshd has reloaded, is there still a way in?
//
// There are two ways to answer no. Both authentication methods can be off, in
// which case nothing gets in whatever keys exist. Or passwords can be off with
// no account on this machine holding a key — and if root login is being turned
// off as well, root's own key does not count, because root would not be allowed
// to use it.
func SSHDLockout(after map[string]string, paths LoginPath) string {
	password := strings.ToLower(after["passwordauthentication"])
	pubkey := strings.ToLower(after["pubkeyauthentication"])
	rootLogin := strings.ToLower(after["permitrootlogin"])

	if password == "no" && pubkey == "no" {
		return "this would leave sshd with no way to authenticate anyone: " +
			"PasswordAuthentication and PubkeyAuthentication would both be no. " +
			"Set PubkeyAuthentication to yes first."
	}
	if password != "no" {
		return ""
	}

	usable := make([]string, 0, len(paths.Keys))
	for _, account := range paths.Keys {
		if account == "root" && rootLogin == "no" {
			continue
		}
		usable = append(usable, account)
	}
	if len(usable) > 0 || len(paths.Blocked) > 0 {
		return ""
	}
	detail := "no account on this machine has an authorized key"
	if len(paths.Keys) > 0 {
		detail = "the only account with an authorized key is root, and " +
			"PermitRootLogin would be no"
	}
	return "this would turn off password authentication while " + detail +
		", so nothing would be able to log in over ssh. Install a key for " +
		"your own account first, and check it works from a second session."
}

// SSHDLockoutWarning is what the confirm dialog says about a change that is
// allowed but still worth stopping to read.
func SSHDLockoutWarning(after map[string]string, paths LoginPath) string {
	if strings.ToLower(after["passwordauthentication"]) != "no" {
		return ""
	}
	if len(paths.Blocked) == 0 {
		return "After this, keys are the only way in.\n" +
			"The accounts holding one: " +
			strings.Join(firstN(paths.Keys, 6), ", ") + "."
	}
	return "After this, keys are the only way in, and the authorized_keys of\n" +
		strings.Join(firstN(paths.Blocked, 6), ", ") + " could not be read by " +
		"this process.\nKeep this session open and test a new one before you " +
		"close it."
}

// SSHDPlanInput is everything a plan for one keyword needs to know about this
// machine. It is gathered by the backend and passed in as data, so the plan
// itself — the refusals included — is one function that both backends run and a
// test can drive without a machine at all.
type SSHDPlanInput struct {
	// Key is the keyword being set.
	Key string
	// Effective is the configuration as it stands, keyed the way `sshd -T`
	// prints it: lowercased keyword, value as read.
	Effective map[string]string
	// Existing is what this tool's drop-in holds today, empty when there is
	// none.
	Existing string
	// Unit is the ssh server's unit name on this machine.
	Unit string
	// Paths is what the authorized-key scan found.
	Paths LoginPath
	// Shadow names a drop-in sshd reads before this tool's and which already
	// sets this keyword, empty when nothing shadows it.
	Shadow string
}

// SSHDPlan renders the drop-in, refuses the changes that would end in a locked
// door, and returns the three commands that apply the rest.
//
// tempPath is where the caller staged the file: a private temporary directory
// on a real machine, a name on the demo one. Staging first is what makes the
// change reviewable — the file the user approves is a file that already exists,
// `sshd -t -f` parses that exact file, and `install` copies it unchanged.
func SSHDPlan(in SSHDPlanInput, tempPath string) (posture.Plan, error) {
	key, ok := sshdKey(in.Key)
	if !ok {
		return posture.Plan{}, fmt.Errorf(
			"host: %q is not a keyword this tool sets", in.Key)
	}

	content, err := RenderSSHDDropIn(in.Existing, key.Key, key.Want)
	if err != nil {
		return posture.Plan{}, err
	}
	after := effectiveAfter(in.Effective, content)
	if refusal := SSHDLockout(after, in.Paths); refusal != "" {
		return posture.Plan{}, fmt.Errorf("host: %s", refusal)
	}

	validateCmd, err := BuildSSHDValidate(tempPath)
	if err != nil {
		return posture.Plan{}, err
	}
	installCmd, err := BuildInstallSSHDDropIn(tempPath)
	if err != nil {
		return posture.Plan{}, err
	}
	reloadCmd, err := BuildSSHDReload(in.Unit)
	if err != nil {
		return posture.Plan{}, err
	}

	body := key.Why + "."
	if warning := SSHDLockoutWarning(after, in.Paths); warning != "" {
		body += "\n\n" + warning
	}
	if in.Shadow != "" {
		body += "\n\n" + in.Shadow + " is read before " + SSHDDropInName +
			", and sshd takes the\nFIRST value it is given for a keyword, so " +
			"what is written here would\nbe read and ignored. Change it in " +
			in.Shadow + " instead."
	}
	body += "\n\n" + SSHDDropInPath + " will read:\n\n" + content
	return posture.Plan{
		Title:    "Set " + key.Key + " to " + key.Want,
		Body:     body,
		Commands: []posture.Command{validateCmd, installCmd, reloadCmd},
		Danger:   true,
	}, nil
}

// effectiveAfter is the configuration this machine would have once the drop-in
// is installed: what sshd reports today, with every keyword the new file
// carries laid over it.
func effectiveAfter(effective map[string]string, content string) map[string]string {
	after := make(map[string]string, len(effective)+len(SSHDKeys))
	for key, value := range effective {
		after[strings.ToLower(key)] = value
	}
	for key, value := range parseSSHDDropIn(content) {
		after[key] = value
	}
	return after
}

// SSHDShadowedBy names a drop-in sshd reads before this tool's, and which
// already decides the keyword being set.
//
// It matters because sshd takes the FIRST value it is given for a keyword, and
// the drop-ins are read in the order the shell globs them — so a file sorting
// before 50-tui-secure.conf wins, and writing the right value into a file that
// is read second would look like it worked and change nothing.
func SSHDShadowedBy(entries []string, contents map[string]string, key string) string {
	sort.Strings(entries)
	for _, name := range entries {
		if name >= SSHDDropInName {
			break
		}
		for _, line := range splitLines(contents[name]) {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
				return name
			}
		}
	}
	return ""
}
