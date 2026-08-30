package main

import (
	"context"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuisecure "github.com/tui-tools/tui-secure"
)

// probeCompat reads the version of every backend this tool talks to.
//
// tui-secure is the first tool in the family with more than one: it reads
// systemd, OpenSSH, ufw or firewalld, and sbctl where it exists. Each of them
// is probed once at startup, and what they are judged against — the minimum
// version, the versions the lab has actually run against, the caveats that
// apply to a range — comes from the repository's own tool.json, embedded in
// the binary, so there is no second copy of them in the code.
//
// It never fails. A manifest that cannot be parsed produces no results at all,
// and a backend this machine does not have produces one with an empty version
// and the reason: on a posture tool, "ufw is not installed here" is an answer
// worth showing rather than an error.
func probeCompat(ctx context.Context, demo bool) []compat.Result {
	// --demo drives an in-memory machine; probing the real systemd on the host
	// would report a version that has nothing to do with what is on screen.
	if demo {
		return nil
	}
	m, err := manifest.Load(tuisecure.ManifestJSON)
	if err != nil {
		return nil
	}
	results := make([]compat.Result, 0, len(m.Backends))
	for _, backend := range m.Backends {
		results = append(results, compat.Probe(ctx, backend))
	}
	return results
}

// installed keeps the backends that answered with a version, which are the
// ones this machine actually has. It is what the header shows: a row of
// versions for programs that are not installed would be noise.
func installed(results []compat.Result) []compat.Result {
	kept := make([]compat.Result, 0, len(results))
	for _, result := range results {
		if result.Version != "" {
			kept = append(kept, result)
		}
	}
	return kept
}
