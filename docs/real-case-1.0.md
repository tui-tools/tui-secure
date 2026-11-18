# Real case for 1.0: a posture check and its fixes on a Fedora server

Point 5 of the family's [stability bar](https://github.com/tui-tools/tui-kit/blob/main/docs/stability.md):
the tool has driven a real machine end to end for its main purpose, and what
that surfaced was fixed or filed.

## The machine, plainly

A lab virtual machine, not a production server: Fedora 44 Cloud Edition
(systemd 259, SELinux enforcing, firewalld 2.4.4, OpenSSH 10.2), booted by
[tui-lab](https://github.com/tui-tools/tui-lab) under KVM on the project's own
server. The tool ran as the ordinary user `lab` over SSH, escalating with
`sudo -n`. The build was `main` on 2026-11-18, then `main` with
[#32](https://github.com/tui-tools/tui-secure/pull/32).

The same build also ran read-only on the project's own server, a Fedora 44
machine in daily use: `tui-secure --check` exited 0 with all eight probes
answered. Nothing was changed on that machine, and its findings are not
published here.

## What was done, end to end

1. Opened on the posture screen: `score: 50%  1 ok · 6 warn · 1 bad`, with
   the firewall probe `bad: firewalld is installed but not running`. That was
   wrong, see below. With the fix the same machine read `score: 63%  2 ok ·
   6 warn · 0 bad` and `Firewall  ok  firewalld is running, default zone
   public`.
2. Kernel hardening, `a`: three fixes offered, one per key below the
   recommended value. Each was previewed as the whole
   `/etc/sysctl.d/90-tui-secure.conf` it would leave, then `install -m 644`
   and `sysctl -w`, and applied one at a time: `kernel.kptr_restrict = 1`,
   `fs.protected_regular = 2`, `fs.suid_dumpable = 0`. The probe went from
   `3 hardening key(s) below the recommended value` to `the hardening basics
   are set`.
3. The machine was rebooted. After it, `sysctl` printed the three values, the
   kernel probe was `ok` and the score `69`.

## What it surfaced

- Over SSH, polkit refuses every `firewall-cmd` query to an ordinary user
  (`NotAuthorizedException`, exit 253). The probe read that refusal as "not
  running", scored a firewalld that had run since boot as `bad` and offered to
  start it; after `a` it still said so. Fixed in
  [#32](https://github.com/tui-tools/tui-secure/pull/32): the read escalates
  through `sudo -n` on a refusal, and falls back to `systemctl is-active
  firewalld`. The smoke test now asserts the verdict, and fails on `main`
  without the fix on this machine (26 passed, 1 failed) and passes with it
  (27/27).
- The fix column and `--check`'s `fix.tool` still called tui-ssh, tui-update
  and tui-users "(planned)"; fixed in this release.
- Before 1.0, `r` re-ran every probe and `R` the selected one, the opposite of
  the family's `R`; swapped in this release.

## What it did not cover

The SSH, ports and firewall-enable fixes were not applied on this machine
(the firewall one only by accident, against the bug above, where it was a
no-op on a running firewalld).
