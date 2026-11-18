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

## Second run: tui-kit v0.5.0, on all three families

tui-kit v0.5.0 changed how a command runs as root: it is looked up only in the
system directories and must be owned by root, it starts from a minimal
environment, and as root the tool refuses configuration files root does not
own and `TUI_<TOOL>_*` variables carried in from sudo, su, doas or pkexec. So
the work above was repeated on 2026-11-18 with a static build of this branch's
head, `5636f34` (main with tui-kit v0.5.0 and Go 1.27.4 merged in),
installed root-owned as `/usr/local/bin/tui-secure`, on fresh tui-lab machines on
the project's own server: Ubuntu 24.04.5 (apt), Fedora 44 (dnf) and Omarchy
Server 4.0.1 (pacman), lab VMs again, not production hosts.

- The smoke test passed on all three as the ordinary user `lab`, who
  escalates with `sudo -n`, and again as root (`sudo env TUI_LAB_BIN=<binary> bash smoke.sh`):
  26/26 on Ubuntu, 27/27 on Fedora and Omarchy Server, as user and as root. On Omarchy Server the escalation and every command it runs were
  found through `/usr/sbin`, which the new kit trusts; nothing was refused.
- The main change was driven through the TUI in tmux once per family as
  `lab` and once as root, and checked on the machine afterwards:
  a kernel hardening fix through `a`, written to
  `/etc/sysctl.d/90-tui-secure.conf`, on all three (as root the fixes left
  were already applied, so the run there checked the keys and `--check`).
- tui-update then upgraded all three machines (see its report), Omarchy
  Server to 4.0.2. The smoke test passed again on the upgraded machines, and
  the new versions it observed are the 2026-11-18 lines in
  `compat/results.jsonl` (systemd 262 and OpenSSH 10.6 on Omarchy Server 4.0.2). Three runs of the smoke test made right after the fix above were left out: they failed only because the fix had left the drop-in that the test expects to be absent, and passed once it was removed.
- The contract changes were driven on all three: with the cursor on the
  Firewall row and `fs.protected_symlinks` lowered behind the tool's back,
  `r` left the Kernel hardening row as it was and `R` updated it (one more key
  below the recommended value); `--check` names the fix tools `tui-update` and
  `tui-users`, with no "(planned)".

New finding, filed as #34: as an ordinary user on Ubuntu, `aa-status` refuses
and the MAC probe reports a parse error instead of the refusal. The same with
the tui-kit v0.4.6 build; not a regression and not a contract question.
