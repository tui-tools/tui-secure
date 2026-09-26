package host

import (
	"strings"
	"testing"
)

// showAddedHeader is the first line of `ufw show added` as ufw 0.36 on Ubuntu 24.04 prints it.
const showAddedHeader = "Added user rules (see 'ufw status' for running firewall):\n"

// TestParseUfwAddedForPort pins how a rule list is read for the ssh port.
func TestParseUfwAddedForPort(t *testing.T) {
	cases := []struct {
		name       string
		rules      string
		port       string
		allowed    bool
		restricted bool
		denied     bool
	}{
		{"no rules", "(None)", "22", false, false, false},
		{"plain port", "ufw allow 22", "22", true, false, false},
		{"port and tcp", "ufw allow 22/tcp", "22", true, false, false},
		{"udp only", "ufw allow 22/udp", "22", false, false, false},
		{"limit", "ufw limit 22/tcp", "22", true, false, false},
		{"app profile", "ufw allow OpenSSH", "22", true, false, false},
		{"service name", "ufw limit ssh", "22", true, false, false},
		{"app on another port", "ufw allow OpenSSH", "2222", false, false, false},
		{"port list", "ufw allow 80,443,2222/tcp", "2222", true, false, false},
		{"port range", "ufw allow 2000:3000/tcp", "2222", true, false, false},
		{"full syntax", "ufw allow proto tcp from any to any port 22", "22", true, false, false},
		{"from one network", "ufw allow from 10.0.0.0/8 to any port 22 proto tcp", "22", false, true, false},
		{"on one interface", "ufw allow in on eth0 to any port 22", "22", false, true, false},
		{"source port is not the port", "ufw allow from any port 22", "22", false, true, false},
		{"outgoing", "ufw allow out 22/tcp", "22", false, false, false},
		{"routed", "ufw route allow 22/tcp", "22", false, false, false},
		{"another port", "ufw allow 80/tcp\nufw allow 443/tcp", "22", false, false, false},
		{"deny first wins", "ufw deny 22/tcp\nufw allow 22/tcp", "22", false, false, true},
		{"allow first wins", "ufw allow 22/tcp\nufw deny 22/tcp", "22", true, false, false},
		{"restricted then open", "ufw allow from 10.0.0.1 to any port 22\nufw allow 22/tcp", "22", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseUfwAddedForPort(showAddedHeader+tc.rules+"\n", tc.port)
			if got.Allowed != tc.allowed || got.Restricted != tc.restricted ||
				got.Denied != tc.denied {
				t.Errorf("got %+v, want allowed=%t restricted=%t denied=%t",
					got, tc.allowed, tc.restricted, tc.denied)
			}
		})
	}
}

// TestSSHSessionPort reads the server-side port out of SSH_CONNECTION.
func TestSSHSessionPort(t *testing.T) {
	if got := SSHSessionPort("192.0.2.10 51234 192.0.2.1 2222"); got != "2222" {
		t.Errorf("port = %q, want 2222", got)
	}
	for _, bad := range []string{"", "1 2 3", "a b c d"} {
		if got := SSHSessionPort(bad); got != "" {
			t.Errorf("SSHSessionPort(%q) = %q, want empty", bad, got)
		}
	}
}

// TestParseUfwDefaultInput reads the default incoming policy.
func TestParseUfwDefaultInput(t *testing.T) {
	text := "IPV6=yes\nDEFAULT_INPUT_POLICY=\"ACCEPT\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"
	if got := ParseUfwDefaultInput(text); got != "ACCEPT" {
		t.Errorf("policy = %q", got)
	}
}

// TestUfwEnablePlanSSHAllowed: with the ssh port allowed the dialog says so
// plainly, names the rule, and carries no warning.
func TestUfwEnablePlanSSHAllowed(t *testing.T) {
	plan, err := UfwEnablePlan(SSHAccess{Port: "22", Session: true,
		Source: "this ssh session", Known: true, Allowed: true,
		Rule: "ufw allow 22/tcp"})
	if err != nil {
		t.Fatalf("UfwEnablePlan: %v", err)
	}
	if plan.Title != "Enable ufw" {
		t.Errorf("title = %q, want no warning in it", plan.Title)
	}
	if strings.Contains(plan.Body, "WARNING") {
		t.Errorf("an allowed port is warned about:\n%s", plan.Body)
	}
	for _, want := range []string{"ssh stays reachable", "port 22/tcp",
		"`ufw allow 22/tcp`"} {
		if !strings.Contains(plan.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, plan.Body)
		}
	}
	if !plan.Danger {
		t.Error("enabling a firewall is always a red dialog")
	}
	if len(plan.Commands) != 1 || plan.Commands[0].String() != "ufw --force enable" {
		t.Errorf("commands = %v", plan.Commands)
	}
}

// TestUfwEnablePlanSSHNotAllowed: the question ufw used to ask is asked here,
// in the red title, before y.
func TestUfwEnablePlanSSHNotAllowed(t *testing.T) {
	plan, err := UfwEnablePlan(SSHAccess{Port: "2222", Session: true,
		Source: "this ssh session", Known: true})
	if err != nil {
		t.Fatalf("UfwEnablePlan: %v", err)
	}
	if !plan.Danger {
		t.Error("the warning must be in the danger style")
	}
	if !strings.Contains(plan.Title, "2222 is NOT allowed") {
		t.Errorf("title does not carry the warning: %q", plan.Title)
	}
	for _, want := range []string{"WARNING", "ends this ssh session",
		"sudo ufw allow 2222/tcp"} {
		if !strings.Contains(plan.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, plan.Body)
		}
	}
	if strings.Contains(plan.Body, "stays reachable") {
		t.Errorf("body reassures about a closed port:\n%s", plan.Body)
	}
}

// TestUfwEnablePlanUnreadRulesWarn: rules nobody could read are not a yes.
func TestUfwEnablePlanUnreadRulesWarn(t *testing.T) {
	plan, err := UfwEnablePlan(SSHAccess{Port: "22", Source: "sshd's default"})
	if err != nil {
		t.Fatalf("UfwEnablePlan: %v", err)
	}
	if !strings.Contains(plan.Title, "could not be checked") ||
		!strings.Contains(plan.Body, "WARNING") {
		t.Errorf("unread rules are not warned about: %q\n%s", plan.Title, plan.Body)
	}
}

// TestUfwEnablePlanRestrictedWarns: an allow from one network is not an allow
// from wherever this session comes from.
func TestUfwEnablePlanRestrictedWarns(t *testing.T) {
	plan, err := UfwEnablePlan(SSHAccess{Port: "22", Source: "sshd's default",
		Known: true, Restricted: true,
		Rule: "ufw allow from 10.0.0.0/8 to any port 22 proto tcp"})
	if err != nil {
		t.Fatalf("UfwEnablePlan: %v", err)
	}
	if !strings.Contains(plan.Title, "only from some places") ||
		!strings.Contains(plan.Body, "10.0.0.0/8") {
		t.Errorf("restricted rule not warned about: %q\n%s", plan.Title, plan.Body)
	}
}
