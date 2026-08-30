package posture

import "testing"

// TestWorstOrdersTheVerdicts: unknown sits between ok and warn, because not
// knowing is worse than knowing it is fine and better than knowing it is not.
func TestWorstOrdersTheVerdicts(t *testing.T) {
	for _, test := range []struct {
		in   []Status
		want Status
	}{
		{[]Status{StatusOK, StatusOK}, StatusOK},
		{[]Status{StatusOK, StatusUnknown}, StatusUnknown},
		{[]Status{StatusUnknown, StatusWarn}, StatusWarn},
		{[]Status{StatusWarn, StatusBad, StatusOK}, StatusBad},
		{nil, StatusOK},
	} {
		if got := Worst(test.in...); got != test.want {
			t.Errorf("Worst(%v) = %q, want %q", test.in, got, test.want)
		}
	}
}

// TestScoreLeavesUnknownsOut: scoring a question nobody could answer would be
// inventing a verdict, so an unknown probe is counted and not weighed.
func TestScoreLeavesUnknownsOut(t *testing.T) {
	score := ScoreOf([]Probe{
		{Status: StatusOK}, {Status: StatusOK},
		{Status: StatusWarn}, {Status: StatusBad},
		{Status: StatusUnknown},
	})
	if score.Counted != 4 {
		t.Errorf("counted = %d, want the four that were answered", score.Counted)
	}
	if score.Unknown != 1 {
		t.Errorf("unknown = %d", score.Unknown)
	}
	// 1 + 1 + 0.5 + 0 out of 4.
	if score.Value != 63 {
		t.Errorf("value = %d, want 63", score.Value)
	}

	if got := ScoreOf([]Probe{{Status: StatusUnknown}}).Value; got != 0 {
		t.Errorf("a report of nothing but unknowns scores %d, want 0", got)
	}
}

func TestReportReplaceRescores(t *testing.T) {
	report := Report{Probes: []Probe{
		{ID: ProbeFirewall, Status: StatusBad},
		{ID: ProbeSSH, Status: StatusOK},
	}}
	report.Finish()
	if report.Worst != StatusBad || report.Score.Value != 50 {
		t.Fatalf("before: worst=%q score=%d", report.Worst, report.Score.Value)
	}

	report.Replace(Probe{ID: ProbeFirewall, Status: StatusOK})
	if report.Worst != StatusOK || report.Score.Value != 100 {
		t.Errorf("after: worst=%q score=%d", report.Worst, report.Score.Value)
	}
	if report.Probes[0].ID != ProbeFirewall {
		t.Error("Replace must keep the report's order")
	}
}

func TestStackString(t *testing.T) {
	full := Stack{SecureBoot: "SB: on", MAC: "MAC: SELinux enforcing",
		Firewall: "firewall: ufw"}
	if got := full.String(); got != "SB: on · MAC: SELinux enforcing · firewall: ufw" {
		t.Errorf("String() = %q", got)
	}
	if got := (Stack{}).String(); got != "nothing detected" {
		t.Errorf("an empty stack renders %q", got)
	}
}
