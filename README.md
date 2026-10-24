# compromise-audit ⚖️

Read-only compromise checks for macOS and Linux.

Two standalone scripts for a quick check of a machine for signs of compromise. Output goes to the console only.

| Script | System |
|---|---|
| [`mac_audit.sh`](mac_audit.sh) | macOS |
| [`linux_audit.sh`](linux_audit.sh) | Linux with systemd (Debian/Ubuntu, RHEL/Fedora, Arch, SUSE) |

```bash
sudo bash mac_audit.sh      # macOS
sudo bash linux_audit.sh    # Linux
```

Without `sudo` the scripts still run, but some checks are skipped (marked "Skipped"). On macOS, grant Terminal **Full Disk Access** (System Settings → Privacy & Security) for full coverage.

## How to read the result

- 🔴 **ALERT** - a strong indicator of compromise or a serious misconfiguration.
- 🟡 **CHECK** - needs a human look; may be legitimate (VPN, corporate certificate, Homebrew).
- 🟢 - check passed.

A summary of all ALERT and CHECK items is printed at the end. CHECK does not mean infected. A clean result is not a guarantee: advanced malware (rootkits) can hide from checks run on the same system.

## What the scripts do not do

The scripts do not change the system. They contain no commands that delete, move or create files or change permissions (`rm`, `mv`, `cp`, `touch`, `chmod`, `chown`). They do not write settings (`defaults write`, `systemsetup -set`), manage services (`launchctl load/unload`, `systemctl start/stop`, `kill`) or install packages. They do not touch protections (SIP, Gatekeeper, firewall, SELinux) and do not install or remove profiles. All redirections go to `/dev/null`; everything else goes to the console. Every command is a "show state" command: `csrutil status`, `spctl --status`, `codesign -dv`, `PlistBuddy -c Print`, `crontab -l`, `profiles list`, `lsof`, `ps`, `ss`, `log show`, `journalctl`, `sshd -T`.

### Side effects

"Does not change the system" is not the same as "leaves no trace". The scripts are strictly read-only with respect to the file system and settings, with these caveats:

- **`sudo` is logged.** Running `sudo bash …` itself lands in the `sudo` log (`auth.log` / `secure` / unified log). The next run of the script will see it in the "sudo commands in last 7 days" section.
- **The SSH/VNC checks on macOS open network connections.** `nc -z 127.0.0.1 22` and `nc -z 127.0.0.1 5900` make a TCP connection to a local port (no data is sent). This is the only place where a script "touches" something instead of just reading it.
- **Linux: queries to the Docker daemon.** `docker ps` and `docker inspect` talk to the daemon socket. They change nothing, and run only if Docker is installed and you are root.
- **macOS: `sqlite3 -readonly` on TCC databases.** The database is opened read-only. If a database is in WAL mode, SQLite may still access the auxiliary `-shm`/`-wal` files.
- **Load and run time.** `find /` (SUID search on Linux), `debsums` / `rpm -Va`, and `log show --last 7d` (can take several minutes on macOS) noticeably load disk and CPU.
- **Reading sensitive files.** With `sudo` the scripts read `/etc/shadow`, `sudoers`, `authorized_keys` and shell history. Only account names and problem indicators are printed (password hashes are never printed), but review the output before sending it to anyone: it contains user names, host names, paths, fragments of command lines and log messages.
- **`sudo -u <user> security …` on macOS** runs a command as your user (only `dump-trust-settings`, a read).

## Checks: macOS (`mac_audit.sh`)

### 1. Built-in protection
- SIP (System Integrity Protection) enabled — ALERT if disabled
- Sealed system volume (`csrutil authenticated-root status`) enabled — ALERT if disabled (macOS 11+)
- Gatekeeper enabled — ALERT if disabled
- FileVault (disk encryption) — CHECK if off
- Application Firewall — CHECK if off

### 2. Persistence: LaunchAgents / LaunchDaemons
For every `.plist` in `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`:
- the launched executable is resolved (`Program` / `ProgramArguments`)
- code signature (`codesign`): unsigned / invalid → ALERT; missing file, ad-hoc signature → CHECK
- runs from `/tmp`, `/private/var/tmp`, `/Users/Shared` → ALERT; from a hidden folder → CHECK
- runs an interpreter (`bash`, `sh`, `zsh`, `python*`, `perl`, `ruby`, `osascript`, `curl`, `node`) → CHECK
- launch items created/modified in the last 14 days → CHECK

### 3. Other persistence mechanisms
- User `cron` jobs (and root's when run with `sudo`) → CHECK if present
- Configuration profiles (`profiles list`) → CHECK if present (requires `sudo`)
- Third-party login items / background tasks (`sfltool dumpbtm`, excluding `com.apple`) (requires `sudo`)
- Third-party kernel extensions (`kextstat`) → CHECK
- System extensions (`systemextensionsctl list`)

### 4. Processes and network
- Running processes outside system folders that are unsigned or have an invalid signature → ALERT
- Crypto-miner detection:
  - processes by name (`xmrig`, `minerd`, `kinsing`, etc.) or arguments (`stratum+tcp://`, `--donate-level`, pool names)
  - connections to mining-pool ports (3333, 4444, 5555, etc.) → CHECK
  - miner files on disk in `/tmp`, `/Users/Shared`, `~/Library`, `~/.local`, `~/.config`, `~/.cache`, `/usr/local/bin`, `/opt` → ALERT
  - miner references in launch items and cron → ALERT
  - processes with CPU ≥ 80% (excluding `ps`/`awk`/`sort`/`head`) → CHECK
- Listening TCP ports (`lsof`)
- Established connections (`lsof`)
- System proxy (HTTP/HTTPS/SOCKS/PAC) → CHECK
- DNS servers
- Non-default entries in `/etc/hosts` → CHECK

### 5. Accounts and remote access
- Local users, members of the `admin` group
- Recent logins (`last -20`)
- Remote Login (SSH, port 22) enabled → CHECK
- SSH password login (`PasswordAuthentication`, `KbdInteractiveAuthentication`): enabled while SSH is running → ALERT, otherwise CHECK
- Screen Sharing / Remote Management (port 5900) → CHECK
- `authorized_keys` of the user and root → CHECK, key list
- `sudoers`: `NOPASSWD` rule → ALERT; extra files in `/etc/sudoers.d` → CHECK (requires `sudo`)
- App permissions (TCC): screen recording, Accessibility, input monitoring, Full Disk Access, microphone, camera

### 6. User profile, files, certificates
- Suspicious lines in `.zshrc`, `.zprofile`, `.zshenv`, `.zlogin`, `.bashrc`, `.bash_profile`, `.profile` (`curl`, `wget`, `base64`, `osascript`, `nc`, `/tmp/`, `python -c`, `| sh`) → CHECK
- Executable files in `/private/tmp`, `/private/var/tmp`, `/Users/Shared` → CHECK
- Hidden files in `/Users/Shared` → CHECK
- Apps installed/modified in the last 14 days
- Signature integrity of third-party software: `codesign --verify --deep --strict` for apps in `/Applications` and `~/Applications`, `codesign --verify` for Mach-O binaries in `/opt/homebrew/bin` and `/usr/local/bin` → ALERT if a signature no longer verifies (modified after install); unsigned items → CHECK. Apple's own files are covered by the sealed system volume. Like package checksums, this catches modification after install, not a re-signed binary.
- Manually trusted root certificates (admin and user) → CHECK

### 7. Logs (7 days, `log show`)
- Successful SSH logins → ALERT if any
- `sudo` commands in the last 7 days (last 20)
- Failed authentication attempts → CHECK if more than 20

## Checks: Linux (`linux_audit.sh`)

### 1. Built-in protection
- SELinux (enforcing) or AppArmor (enabled); neither → CHECK
- ASLR (`randomize_va_space = 2`) → CHECK otherwise
- Firewall: ufw, firewalld, nftables/iptables rules → CHECK if none (nft/iptables rules require `sudo`)
- Disk encryption (LUKS/dm-crypt) → CHECK if none (may be fine for servers and VMs)
- Secure Boot (`mokutil`, if installed)
- Kernel taint (`/proc/sys/kernel/tainted`) → CHECK if not 0

### 2. Persistence: systemd, cron, init
- Custom units and timers in `/etc/systemd/system`, `/etc/systemd/user`, `~/.config/systemd/user` (all users):
  - `ExecStart` target missing on disk → CHECK
  - runs from `/tmp`, `/var/tmp`, `/dev/shm` → ALERT; from a hidden path → CHECK
  - binary not owned by any package (dpkg/rpm/pacman)
  - interpreter or downloader (`bash`, `sh`, `python*`, `curl`, `wget`, `nc`, `node`, etc.) → CHECK
  - `curl`, `wget`, `base64 -d`, `/dev/tcp/`, `nc -e`, `bash -i` or a miner inside the unit → ALERT
- Units modified in the last 14 days → CHECK
- List of systemd timers
- Cron: `/etc/crontab`, `/etc/cron.d`, `/var/spool/cron`, `crontab -l` of all users (with `sudo`) → CHECK; download/obfuscation/`/tmp` patterns → ALERT; cron files modified in the last 14 days → CHECK
- `at` jobs → CHECK (requires `sudo`)
- `/etc/rc.local` with commands → CHECK
- `/etc/ld.so.preload` non-empty → ALERT (userland rootkit technique)
- `LD_PRELOAD` / `LD_LIBRARY_PATH` in `/etc/environment`, `/etc/profile`, `/etc/profile.d`, `/etc/bash.bashrc` → CHECK
- XDG autostart (`/etc/xdg/autostart`, `~/.config/autostart`) modified in the last 30 days → CHECK
- udev rules modified in the last 14 days → CHECK
- PAM files and modules modified in the last 14 days → CHECK (password-stealing vector)
- `update-motd.d` scripts modified in the last 14 days → CHECK
- Kernel modules:
  - flagged with a taint (out-of-tree / unsigned) → CHECK
  - loaded modules with no file on disk (`modinfo -n`) → ALERT (sign of an LKM rootkit)

### 3. Processes and network
- Processes running from `/tmp`, `/var/tmp`, `/dev/shm`, hidden paths or `memfd` (fileless execution) → ALERT
- Processes whose binary was deleted → CHECK (normal right after a package update)
- PIDs visible in `/proc` but missing from `ps` (sign of a hidden process)
- Crypto-miner detection:
  - processes by name or arguments (`xmrig`, `kinsing`, `kdevtmpfsi`, `stratum+tcp://`, pool names)
  - connections to mining-pool ports → CHECK
  - miner files in `/tmp`, `/var/tmp`, `/dev/shm`, `/opt`, `/usr/local/bin`, and every user's `~/.cache`, `~/.config`, `~/.local` → ALERT
  - miner references in `/etc/systemd/system`, `/etc/cron.d`, `/var/spool/cron` → ALERT
  - processes with CPU ≥ 80% (excluding `ps`/`awk`/`sort`/`head`) → CHECK
- Listening TCP/UDP ports (`ss`)
- Established connections (`ss`)
- Interfaces in promiscuous mode (sniffer) → CHECK
- System proxy (environment variables, `/etc/environment`, `profile.d`, apt) → CHECK
- DNS servers
- Non-default entries in `/etc/hosts` → CHECK

### 4. Accounts and remote access
- Extra accounts with UID 0 → ALERT
- Accounts with an empty password in `/etc/shadow` → ALERT (requires `sudo`)
- Users with a login shell, members of the `sudo` / `wheel` / `admin` groups
- Recent logins (`last`), current sessions (`w`)
- `passwd`, `shadow`, `group`, `sudoers` modified in the last 14 days → CHECK
- SSH server listening on port 22 / service active → CHECK
- SSH password login: enabled while SSH is running → ALERT, otherwise CHECK (effective configuration via `sshd -T` with `sudo`, otherwise parsed from config files)
- `PermitRootLogin yes` → ALERT while SSH is running, otherwise CHECK
- Listening VNC (5900/5901), RDP (3389), Telnet (23) → CHECK
- `authorized_keys` of all users → CHECK, key list; modified in the last 14 days → CHECK
- `sudoers`: `NOPASSWD` → ALERT; files in `/etc/sudoers.d` → CHECK (requires `sudo`)

### 5. Files, profiles, SUID
- Suspicious lines in all users' shell profiles and in `/etc/profile`, `/etc/bash.bashrc`, `/etc/zsh/zshrc`, `/etc/profile.d` (`curl`, `wget`, `base64`, `/dev/tcp/`, `nc -e`, `python -c`, `| sh`, aliases replacing `sudo`/`ssh`/`su`) → CHECK
- Executable files in `/tmp`, `/var/tmp`, `/dev/shm` → CHECK
- Hidden files in temp folders → CHECK
- SUID/SGID files outside packages or in `/tmp`, `/home` → ALERT (requires `sudo`)
- Files with Linux capabilities (`getcap`) → CHECK (requires `sudo`)
- World-writable files in system paths → ALERT
- Package checksums: `debsums -c`, `rpm -Va` or `pacman -Qkk`, limited to `/bin`, `/sbin`, `/lib*`, `/usr/{bin,sbin,lib*,libexec}`, `/boot` → ALERT on modified files (requires `sudo`; Debian needs the `debsums` package). Files that packages list but that are missing on disk → CHECK. On Debian the number of packages that ship no checksum list (not verified) is reported.
- Executables in `/usr/bin`, `/usr/sbin`, `/usr/lib*`, `/usr/libexec` that no package owns (compared against the dpkg/rpm/pacman file lists; `/bin`, `/sbin`, `/lib*` are treated as `/usr/...`) → ALERT in `/usr/{bin,sbin}`, CHECK deeper (installers may generate files there). Requires `sudo`.
- Limitation: checksums and package databases live on the audited system, so an attacker with root can falsify them. These checks catch careless tampering (a replaced binary), not a careful adversary.
- System binaries modified in the last 3 days (informational)
- Docker: running containers, privileged containers → CHECK (with `sudo`)
- Manually added root certificates → CHECK
- Packages installed in the last 14 days

### 6. Logs (7 days, `journalctl` or `auth.log` / `secure`)
- Successful SSH logins → ALERT if any
- `sudo` commands in the last 7 days (last 20)
- Failed authentication attempts → CHECK if more than 20
- Top sources of failed logins (`lastb`)
- Suspicious commands in `.bash_history` / `.zsh_history` (`curl | sh`, `/dev/tcp/`, `nc -e`, `base64 -d`, `xmrig`) → CHECK

If logs are unavailable the check is skipped explicitly ("Log checks skipped") instead of being reported as clean.

## Not covered

- Browser extensions (the script reminds you to review them manually)
- Kernel-level and firmware rootkits
- Whether file contents are malicious (no antivirus scanning)
- Windows (no script)

## Development

Contribution rules and the testing procedure (including in a Debian container) are in [CLAUDE.md](CLAUDE.md).
"# compromise-audit" 
