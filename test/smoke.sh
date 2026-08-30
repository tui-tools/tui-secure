#!/bin/bash
# Backend smoke test for tui-secure, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-secure on PATH).
#
# What it proves is that the tool reads the machine's *real* posture and agrees
# with the machine's own tooling — not that a fake renders. The lab already
# covers --version and a --demo frame; this covers the probes.
#
# Three kinds of machine are asserted, because the family targets all three:
#
#   ubuntu    AppArmor and ufw. The MAC layer is AppArmor, and ufw is the
#             firewall whether or not it has been enabled.
#   fedora    SELinux and firewalld. SELinux may be enforcing or disabled;
#             both are answers, and the probe must say which.
#   arch      Omarchy Server. ufw is the firewall and must be active; the
#             SELinux/AppArmor addon may be absent entirely, so an unknown or
#             a warn from the MAC probe is the expected result there.
#
# One rule holds on every one of them: tui-secure must never exit non-zero
# because the machine is insecure. The verdict is in the `worst` field, and the
# exit code says only whether the tool worked.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-secure}"
# TOOL is the manifest name, which is what a compatibility result is keyed on.
TOOL=tui-secure
pass=0
fail=0

# check runs one assertion. It takes a label, a command and a grep pattern the
# command's output must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# check_absent is the inverse of a grep assertion: the command must succeed and
# its output must NOT contain the pattern. It is what proves a probe stayed
# quiet, which is a claim about something that did not happen.
check_absent() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && ! grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

# --- compatibility evidence -------------------------------------------------
#
# The manifest's `tested` lists are generated, not claimed: they are rebuilt
# from compat/results.jsonl by tui-kit/tools/compat-sync.py, and this is where
# the lines of that file come from. The versions recorded are the ones the tool
# itself probed, read back out of --check, so they describe the machine that
# really ran the suite rather than what the tester assumed was installed.
#
# tui-secure is the first tool in the family with several backends, so this
# emits one line per backend that answered. A backend the machine does not have
# — ufw on Fedora, sbctl almost everywhere — reports no version and is skipped:
# there is nothing to claim about a program that is not there.
record_compat() {
  local report="$1" outcome="$2" distro today block recorded=0
  block=$(sed -n '/"compat": \[/,/^  \]/p' <<<"$report")
  distro=$(. /etc/os-release && echo "${ID}-${VERSION_ID:-rolling}")
  today=$(date -u +%Y-%m-%d)

  while read -r backend version; do
    [[ -z $backend || -z $version ]] && continue
    local line
    line=$(printf '{"backend":"%s","date":"%s","distro":"%s","result":"%s","suite":"smoke","tool":"%s","version":"%s"}' \
      "$backend" "$today" "$distro" "$outcome" "$TOOL" "$version")
    printf 'compat-result: %s\n' "$line"
    if [[ -n ${TUI_COMPAT_RESULTS:-} ]]; then
      printf '%s\n' "$line" >>"$TUI_COMPAT_RESULTS"
    fi
    recorded=$((recorded + 1))
  done < <(awk '
    /"backend":/ { gsub(/[",]/, ""); b = $2 }
    /"version":/ { gsub(/[",]/, ""); if (b != "") { print b, $2; b = "" } }
  ' <<<"$block")

  if [[ $recorded -eq 0 ]]; then
    echo "      no backend version was probed, so no compatibility result is recorded"
  fi
}

echo "--- tui-secure smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"

family=$(. /etc/os-release && echo "${ID} ${ID_LIKE:-}")
case "$family" in
  *ubuntu* | *debian*) machine=ubuntu ;;
  *fedora* | *rhel*) machine=fedora ;;
  *arch* | *omarchy*) machine=arch ;;
  *) machine=other ;;
esac
echo "      machine=$machine"

report=$("$bin" --check 2>&1)

# 1. The read path works at all, unprivileged, and names the backend it drove.
#    Reading takes no privileges for most probes, so this runs as the plain lab
#    user — which is itself the assertion that the tool does not escalate to
#    look at things it can see without.
check "check reads the posture unprivileged" \
  "$bin --check" \
  '"backend": "host"'

# 2. Every probe reported. A probe that crashed would be missing entirely, and
#    a count is the cheapest way to notice.
for id in secure-boot mac firewall ssh updates accounts kernel ports; do
  check "the $id probe answered" "$bin --check" "\"id\": \"$id\""
done

# 3. Every probe carries a verdict from the four, and nothing else. The
#    compat block has a "status" of its own (tested/untested), so only the
#    probes array is read.
odd=$(sed -n '/"probes": \[/,/^  \],/p' <<<"$report" |
  grep '"status":' | grep -cvE '"status": "(ok|warn|bad|unknown)"')
if [[ $odd -eq 0 ]]; then
  printf 'PASS  every verdict is one of ok, warn, bad, unknown\n'
  pass=$((pass + 1))
else
  printf 'FAIL  %d verdict(s) are none of the four\n' "$odd"
  fail=$((fail + 1))
fi

# 3b. And nothing the accounts probe read out of /etc/shadow reaches the
#     output. It is the one probe that touches secrets, and the raw block it
#     keeps is deliberately the count rather than the file.
check_absent "no password hash reaches the output" \
  "$bin --check" \
  '\$(y|6|5|1)\$'

# 4. The machine is identified. A posture that does not say whose it is cannot
#    be filed.
check "the distribution is identified" \
  "$bin --check" \
  '"distro": ".+"'
check "the kernel is identified" \
  "$bin --check" \
  '"kernel": "[0-9]'

# 5. The headline exists and is one of the four verdicts.
check "the report carries a worst verdict" \
  "$bin --check" \
  '"worst": "(ok|warn|bad|unknown)"'

# 6. And the exit code is not the verdict: an insecure machine is still a
#    successful run. This is the assertion that keeps `tui-secure --check` from
#    failing a lab run because the guest has no firewall.
"$bin" --check >/dev/null 2>&1
status=$?
if [[ $status -eq 0 ]]; then
  printf 'PASS  --check exits 0 whatever the posture is\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check exited %d; the verdict belongs in the worst field\n' "$status"
  fail=$((fail + 1))
fi

case "$machine" in
  ubuntu)
    # AppArmor is the MAC layer on Ubuntu, and it is loaded from the start.
    check "AppArmor is the detected MAC layer" \
      "$bin --check" \
      '"mac": "MAC: AppArmor'

    # ufw is installed on every Ubuntu image. Whether it is *enabled* is the
    # machine's business; that the probe found ufw and not "none" is the tool's.
    check "ufw is the detected firewall" \
      "$bin --check" \
      '"firewall": "firewall: ufw"'

    check "the update probe knows apt" \
      "$bin --check" \
      '"updates": "updates: debian"'
    ;;

  fedora)
    # SELinux is the MAC layer on Fedora whether it is enforcing or not: the
    # probe must name it either way rather than reporting no MAC at all.
    check "SELinux is the detected MAC layer" \
      "$bin --check" \
      '"mac": "MAC: SELinux'

    check "firewalld is the detected firewall" \
      "$bin --check" \
      '"firewall": "firewall: firewalld"'

    check "the update probe knows dnf" \
      "$bin --check" \
      '"updates": "updates: fedora"'
    ;;

  arch)
    # Omarchy Server ships ufw and enables it, so this one is a real assertion
    # about the machine rather than about the parser.
    check "ufw is the detected firewall" \
      "$bin --check" \
      '"firewall": "firewall: ufw"'

    check "the firewall probe is not bad news" \
      "$bin --check | sed -n '/\"id\": \"firewall\"/,/\"fix\"/p'" \
      '"status": "(ok|warn)"'

    # The SELinux/AppArmor addon may be absent, so unknown and warn are both
    # correct here. What must not happen is a crash or a silent ok.
    check "the MAC probe answered, whatever it found" \
      "$bin --check | sed -n '/\"id\": \"mac\"/,/\"fix\"/p'" \
      '"status": "(ok|warn|unknown)"'

    check "the update probe knows pacman" \
      "$bin --check" \
      '"updates": "updates: arch"'
    ;;
esac

# 7. sshd is the one service the lab guests all run, so its probe is asserted
#    everywhere: either it read the configuration, or it said why it could not.
check "the sshd probe read the configuration or said why not" \
  "$bin --check | sed -n '/\"id\": \"ssh\"/,/\"fix\"/p'" \
  '("read from"|"reason")'

# 8. --check must never change anything. Two things a probe could plausibly
#    disturb are compared before and after: a kernel knob it offers to set, and
#    whether the firewall is running.
before_sysctl=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
before_units=$(systemctl is-active firewalld ufw sshd 2>/dev/null | tr '\n' ' ')
"$bin" --check >/dev/null 2>&1
after_sysctl=$(sysctl -n kernel.kptr_restrict 2>/dev/null)
after_units=$(systemctl is-active firewalld ufw sshd 2>/dev/null | tr '\n' ' ')
if [[ "$before_sysctl" == "$after_sysctl" && "$before_units" == "$after_units" ]]; then
  printf 'PASS  --check left the machine untouched\n'
  pass=$((pass + 1))
else
  printf 'FAIL  --check changed the machine\n'
  printf '      | sysctl: %s -> %s\n' "$before_sysctl" "$after_sysctl"
  printf '      | units:  %s -> %s\n' "$before_units" "$after_units"
  fail=$((fail + 1))
fi

# 9. And it must not have written the one file this tool can create.
if [[ ! -e /etc/sysctl.d/90-tui-secure.conf ]]; then
  printf 'PASS  --check wrote no drop-in\n'
  pass=$((pass + 1))
else
  printf 'FAIL  /etc/sysctl.d/90-tui-secure.conf exists after a read-only run\n'
  fail=$((fail + 1))
fi

if [[ $fail -eq 0 ]]; then
  record_compat "$report" pass
else
  record_compat "$report" fail
fi

echo "--- tui-secure: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
