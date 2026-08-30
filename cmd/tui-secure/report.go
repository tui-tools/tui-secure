package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
)

// notAvailable is the runner's own wording for a program this machine does not
// have. It is what separates "ufw is not installed" from "ufw is here and the
// probe could not read a version off it" on the backends line.
const notAvailable = "command not available"

// noVersionDetail is why the backend line carries no version. tui-secure's
// backend is the machine itself, which has no version to read; the programs it
// probes each have one, and they are on the backends line below.
const noVersionDetail = "the machine itself, so there is no one version to read"

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What this function adds is the part only
// tui-secure knows: the version of every program it probes, and which of them
// this machine does not have at all.
//
// It never runs a probe. --check is the flag that does that, and most of its
// probes need privileges; a report has to work for a user who cannot get them,
// because the missing privilege may be the bug. The version probes it does run
// are the same ones the header uses, and they read a version string and
// nothing else.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	// The same probes --check and the header use. There is one set of version
	// probes in this tool and this is it.
	backends := probeCompat(context.Background(), opts.demo)

	var backendName, selectError string
	if backend, err := pickBackend(cfg, opts); err != nil {
		selectError = err.Error()
	} else {
		backendName = backend.Name()
	}

	info := report.Info{
		Tool:          toolName,
		Version:       version,
		Backend:       backendName,
		BackendDetail: noVersionDetail,
		Demo:          opts.demo,
		Sudo:          cfg.String(config.KeySudo, ""),
		Theme:         palette.Name,
	}
	if opts.demo {
		// The fake answers Name() with "host" like the real backend does, so
		// saying "demo" on the backend line and naming what it imitates beside
		// it is what keeps a demo report from reading as a report about this
		// machine.
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: "host",
		})
	} else {
		// The versions are the report's own half. A posture that looks wrong
		// is usually a probe meeting a version nobody tested, and "ufw absent"
		// tells that from "ufw is here and answered something we misread".
		info.Extra = append(info.Extra, report.Field{
			Key: "backends", Value: describeBackends(backends),
		})
	}
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeBackends renders every backend the tool probes as one line: the
// version where there is one, "absent" where the program is not on the
// machine. A report that named only the versions it found would leave the
// reader guessing whether a missing one was absent or merely unreadable.
func describeBackends(results []compat.Result) string {
	parts := make([]string, 0, len(results))
	for _, result := range results {
		name := strings.TrimSpace(result.Backend)
		if name == "" {
			continue
		}
		switch {
		case result.Version != "":
			parts = append(parts, name+" "+result.Version)
		case strings.Contains(result.Detail, notAvailable):
			parts = append(parts, name+" absent")
		default:
			// The program is here and the probe still came back without a
			// version, which is a different bug from not having it at all.
			parts = append(parts, name+" (version unread)")
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
