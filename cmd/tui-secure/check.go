package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-secure/internal/posture"
)

// checkTimeout bounds the whole read. Every probe shells out, and a machine
// whose package manager or journal is wedged must not hang a non-interactive
// check forever.
const checkTimeout = 90 * time.Second

// checkReport is what --check prints: the posture as the probes found it, plus
// the counts a test can assert on without walking the whole structure.
//
// It is a report of the read path only. --check never builds and never runs a
// fix: the whole point is that it is safe to run anywhere, including in CI
// against a production machine.
type checkReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Backend string `json:"backend"`
	// Describe is the backend's own one-line summary, which is where the demo
	// backend says it is a demo.
	Describe string `json:"describe"`
	// Distro and Kernel say which machine this posture belongs to.
	Distro   string `json:"distro"`
	DistroID string `json:"distroId,omitempty"`
	Kernel   string `json:"kernel,omitempty"`
	// Stack is what was detected: Secure Boot, MAC layer, firewall, sshd and
	// the update manager.
	Stack posture.Stack `json:"stack"`
	// Score is the headline, and Worst is the verdict a script reads.
	Score posture.Score  `json:"score"`
	Worst posture.Status `json:"worst"`
	// Probes are the rows in full: status, summary, findings, evidence and
	// the fix.
	Probes []posture.Probe `json:"probes"`
	// Compat is what the backend version probes found, one entry per backend
	// the manifest declares. It is reported rather than asserted: an untested
	// version is a fact about the machine, not a failure of the read path.
	Compat []compat.Result `json:"compat"`
}

// runCheck runs every probe through the real backend and prints the posture as
// JSON.
//
// It returns an error only when the tool itself could not work — which is why
// the exit code is not the verdict. A machine with a disabled firewall and
// root logins enabled is a *successful* run of tui-secure; the bad news is in
// `worst`, where a script can read it without confusing "this machine is
// insecure" with "this tool is broken".
func runCheck(backend posture.Backend, backends []compat.Result,
	out io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	report, err := backend.Load(ctx)
	if err != nil {
		return fmt.Errorf("%s backend read failed: %w", backend.Name(), err)
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(checkReport{
		Tool:     toolName,
		Version:  version,
		Backend:  backend.Name(),
		Describe: backend.Describe(),
		Distro:   report.Distro,
		DistroID: report.DistroID,
		Kernel:   report.Kernel,
		Stack:    report.Stack,
		Score:    report.Score,
		Worst:    report.Worst,
		Probes:   report.Probes,
		Compat:   backends,
	})
}
