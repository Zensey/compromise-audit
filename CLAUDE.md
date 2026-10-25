# compromise-audit

Standalone, read-only compromise audits that print to the console.

- `mac_audit.sh` — macOS
- `linux_audit.sh` — Linux (systemd distros: Debian/Ubuntu, RHEL/Fedora, Arch, SUSE)
- `k8s_audit.sh` — Kubernetes (node components + `kubectl` workload checks); its own system type, not part of the Linux script

## Rules

- **Read-only.** Never delete, change, disable or write anything to disk. No `rm`, `chmod`, `kill`, config edits, temp files.
- Single self-contained bash file per OS, no dependencies beyond what the OS ships. Optional tools (`debsums`, `getcap`, `docker`, `column`) must be guarded with `command -v` and degrade gracefully.
- Keep the two scripts structurally parallel: same helpers (`alert`/`warn`/`ok`/`info`/`section`/`show`/`need_root`), same colors and emoji, same SUMMARY block. When a check is added or fixed in one, consider whether the other needs it too.
- `ALERT` = strong indicator of compromise or serious misconfiguration. `CHECK` = needs a human look, may be legitimate. Don't promote noisy checks to ALERT.
- Every check that needs root must call `need_root` (or branch on `$IS_ROOT`) and say it was skipped rather than silently reporting "clean".
- Don't report "clean" when a check could not actually run (unreadable logs, missing tool).
- Exclude the script's own pipeline from process checks (e.g. `ps`, `awk`, `sort`, `head` show ~100% CPU because `%cpu` is a lifetime average).
- Output is ASCII-safe except the emoji markers; files use LF line endings.

## Testing

Syntax: `bash -n linux_audit.sh`

Linux script in a throwaway container (Debian has no `column`, `last`, systemd or journal there, so those paths are exercised as fallbacks):

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd):/audit:ro" debian:stable-slim bash -c \
  'apt-get update -qq; apt-get install -y -qq procps iproute2 openssh-server debsums sudo cron libcap2-bin util-linux; bash /audit/linux_audit.sh'
```

To test detections, plant indicators inside the container before running (never on the host): non-empty `/etc/ld.so.preload`, extra UID 0 user, empty password in `/etc/shadow`, `NOPASSWD` sudoers file, cron job with `curl | sh`, a copy of `/bin/sleep` named `xmrig` in `/tmp`, a SUID file in `/usr/local/bin`.

Not testable in Docker: systemd units/timers, `journalctl`, kernel-module and firewall checks (container shares the host kernel), and the whole macOS script. Test those on a real machine/VM.

## Gotchas

- Avoid sed backreferences (`\1`) when editing via scripts: a non-raw Python string turns `\1` into the control character `\x01` and `bash -n` still passes. Prefer sed forms without backreferences, and check with `grep -c $'\x01' <script>`.
- Debian container images create `/usr/sbin/policy-rc.d`; it is allowlisted in the unowned-executables check.

- `ORIG_PATH` is saved before the script overrides `PATH`; the PATH-hijack check uses it. A symlinked directory such as `/bin` -> `usr/bin` looks world-writable to `find`; use `find -L`.
- In Docker (and on fresh installs) several "changed in the last N days" checks fire because everything was just installed; expect a few CHECKs on a clean container (apt sources, PAM files, account files, MAC/firewall/LUKS absence, sysctl values inherited from the host kernel).
- The systemd and Docker code paths in `linux_audit.sh` are tested with shims (a fake `systemctl` plus `/run/systemd/system`, a fake `docker` printing canned lines). `k8s_audit.sh` is tested in Debian with a fake `kubectl` (answers `current-context`, `view`, `pods`), a risky manifest in `/etc/kubernetes/manifests`, and `nc -l 0.0.0.0 10255`/`10250` listeners; also run it on a plain host to confirm it reports "Nothing was checked"; the `bpftool` parsing was tested against a real privileged container.

## Known gaps

- `k8s_audit.sh` has not been run against a real cluster or node (only shims); its `kubectl` jsonpath output format and k3s/rke2 node detection are unverified.
- Not exercised on a real host: `needrestart`, `needs-restarting`, `dnf`/`zypper` update checks, `twprint`, the Firefox `certutil` and Java `keytool` paths, kernel-module cross-check with a genuinely hidden module.

- The macOS signature-integrity, sealed-volume, connection-context, reverse-shell (`lsof -a -i -d 0,1`), listener, interface, `systemsetup` NTP and Homebrew checks were written without access to a Mac and have not been run; test them on a real machine (also under the stock bash 3.2: no associative arrays, no `${var,,}`). Only the user-environment section's logic was exercised, in Debian with a `stat` shim.
- Home directories are word-split in `for` loops (`$ALL_HOMES`); home paths with spaces are not handled.
- Rootkits can hide from any check run on the audited system; a clean result is not proof.
