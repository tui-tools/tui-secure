// Command tui-secure is a terminal UI for the security posture of one Linux
// machine: Secure Boot, the MAC layer, the firewall, sshd, pending updates,
// accounts, kernel hardening and listening ports. Each probe shows the command
// behind its verdict, and the three fixes it offers are previewed as an exact
// command line before they run.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-secure/internal/host"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-secure/config.toml and ~/.config/tui-secure/config.toml.
const toolName = "tui-secure"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys tui-secure understands. Only these
// are read from the environment (TUI_SECURE_SUDO, …).
func defaults() map[string]string {
	return map[string]string{
		config.KeySudo:  "sudo -n",
		config.KeyTheme: "",
	}
}

// options holds the parsed command line.
type options struct {
	demo        bool
	check       bool
	report      bool
	themePath   string
	sudo        string
	showVersion bool
	// sudoSet records whether -sudo was passed, so `--sudo ""` can disable
	// escalation instead of reading as "not given".
	sudoSet bool
}

// parseFlags defines and reads the command line.
func parseFlags(args []string, out *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.BoolVar(&opts.demo, "demo", false,
		"run against a sample machine, without probing the real one")
	fs.BoolVar(&opts.check, "check", false,
		"run every probe and print the posture as JSON, then exit (no UI, no "+
			"changes); the verdict travels in the `worst` field, not the exit code")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-secure — the machine's security posture\n\n"+
			"Usage:\n  tui-secure [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_SECURE_* in the environment.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName))
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sudo" {
			opts.sudoSet = true
		}
	})
	return opts, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

// run wires the configuration, the backend and the Bubble Tea program.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		// flag already printed the reason and the usage.
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if opts.showVersion {
		fmt.Println(toolName, version)
		return nil
	}

	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)

	// The configured theme is handed to the kit through the same variable the
	// user could set by hand, so precedence stays in one place. It is set
	// before the backend is built so --report can name the theme the UI would
	// have used even on a machine where no backend can be.
	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	// --report is the non-interactive path that must work everywhere. It runs
	// no probe and needs no privilege, and it comes before the backend is
	// required: a machine the tool cannot build a backend for is a machine
	// whose bug report still has to be filable.
	if opts.report {
		return runReport(cfg, opts, os.Stdout)
	}

	// The backends are probed once, before the first read: which version of
	// ufw, sshd or systemd this machine runs is a fact the header shows and
	// the compatibility block is judged against.
	backends := probeCompat(context.Background(), opts.demo)

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// --check is the non-interactive path: it probes and prints, and never
	// starts a terminal program.
	if opts.check {
		return runCheck(backend, backends, os.Stdout)
	}

	program := tea.NewProgram(newApp(backend, theme.New(), backends),
		tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, which is the
// last and highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
}

// pickBackend returns the demo backend or the real one.
func pickBackend(cfg config.Config, opts options) (posture.Backend, error) {
	if opts.demo {
		return host.NewFake(), nil
	}
	return host.NewReal(cfg.SudoPrefix())
}
