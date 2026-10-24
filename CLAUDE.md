# compromise-audit

Standalone, read-only compromise audits that print to the console.

- `mac_audit.sh` — macOS
- `linux_audit.sh` — Linux (systemd distros: Debian/Ubuntu, RHEL/Fedora, Arch, SUSE)

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

## Known gaps

- Rootkits can hide from any check run on the audited system; a clean result is not proof.
