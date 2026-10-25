# compromise-audit ⚖️

Read-only compromise checks for macOS, Linux and Kubernetes.

Three standalone scripts for a quick check of a machine (or cluster) for signs of compromise or dangerous exposure. Output goes to the console only.

| Script | System |
|---|---|
| [`mac_audit.sh`](mac_audit.sh) | macOS |
| [`linux_audit.sh`](linux_audit.sh) | Linux with systemd (Debian/Ubuntu, RHEL/Fedora, Arch, SUSE) |
| [`k8s_audit.sh`](k8s_audit.sh) | Kubernetes: node components (run on a node) and cluster workloads (anywhere `kubectl` works) |

```bash
sudo bash mac_audit.sh      # macOS
sudo bash linux_audit.sh    # Linux
sudo bash k8s_audit.sh [kube-context]   # Kubernetes node and/or cluster
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
- **Kubernetes: `k8s_audit.sh` runs `kubectl get pods -A` against your cluster** (if `kubectl` is installed and a context is configured), using the invoking user's `~/.kube/config` (or `$KUBECONFIG`), with a 15 s timeout. The script prints the context and API server it queries first. It is a read-only GET; run it only against clusters you are allowed to inspect.
- **Linux: other read-only helpers.** `bpftool prog list`, `needrestart -b -r l`, `auditctl -s`, `certutil -L -d sql:…` (opens the Firefox certificate database read-only), `keytool -list` (Java trust stores, default password), `apt list --upgradable` and `dnf -C updateinfo` (cached metadata, no refresh, no network), `dmesg`, `twprint`.
- **macOS: `sqlite3 -readonly` on TCC databases.** The database is opened read-only. If a database is in WAL mode, SQLite may still access the auxiliary `-shm`/`-wal` files.
- **Load and run time.** `find /` (SUID search on Linux), `debsums` / `rpm -Va`, and `log show --last 7d` (can take several minutes on macOS) noticeably load disk and CPU.
- **Reading sensitive files.** With `sudo` the scripts read `/etc/shadow`, `sudoers`, `authorized_keys` and shell history. Only account names and problem indicators are printed (password hashes are never printed), but review the output before sending it to anyone: it contains user names, host names, paths, fragments of command lines and log messages.
- **`sudo -u <user> security …` on macOS** runs a command as your user (only `dump-trust-settings`, a read).
- **`ssh-keygen -y -P ""` loads your private SSH keys.** It tries to read each `~/.ssh/id_*` with an empty passphrase to tell whether the key is protected. Nothing is printed or written, but the key is parsed in memory. Credential files (`~/.aws/credentials`, `~/.npmrc`, `.env`, …) are only `stat`ed for permissions; their contents are never read, and URLs shown from package-manager configs have embedded credentials masked (`https://***@host`).

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
- Known C2/RAT framework names (`sliver`, `mythic`, `meterpreter`, `cobaltstrike`, `havoc`, `pupy`, …) in running processes and in files under tmp, `/opt`, `/usr/local/bin` and home folders → ALERT
- Tunnel / proxy tools running (`ngrok`, `frpc`, `chisel`, `cloudflared`, `ligolo`, `socat`, `tor`, `sshuttle`, `proxychains`, …) and `ssh -R` / `ssh -D` tunnels → CHECK
- Outbound connections with context: process, executable path, signature, remote IP. A shell or netcat (`bash`, `sh`, `zsh`, `nc`, …) holding a non-local connection → ALERT (typical reverse shell); a scripting interpreter (`python`, `perl`, `node`, …) → CHECK
- Shells or netcat whose stdin/stdout is a network socket (`lsof -a -i -d 0,1`) → ALERT; interpreters → CHECK
- Listeners reachable beyond localhost with unusual owners: from tmp/hidden paths, shells or netcat → ALERT; interpreters, `socat`, or binaries outside system/app paths → CHECK
- Tunnel/VPN interfaces with addresses (`utun` with IPv4, `ppp`, `ipsec`, `tun`, `tap`, `wg`) → CHECK; configured VPN services (`scutil --nc list`)
- Time sync (requires `sudo`): network time disabled → CHECK; non-Apple NTP server → CHECK

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

### 7. User environment: SSH, secrets, git, package sources
- SSH client config (`/etc/ssh/ssh_config*`, `~/.ssh/config`): `ProxyCommand`, `LocalCommand`, `KnownHostsCommand`, `PermitLocalCommand yes`, `Match exec` → CHECK; `~/.ssh/rc` and `~/.ssh/environment` (run on every SSH login), `/etc/ssh/sshrc` → CHECK; files in `~/.ssh` changed in the last 14 days → CHECK
- `~/.gnupg`: `*.conf` changed in the last 14 days, `pinentry-program` outside `/usr` → CHECK; executables in `~/.config` changed in the last 14 days → CHECK
- Credential files (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.pgpass`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `gh`/`gcloud`/`azure` tokens, SSH private keys, `.env` files): only presence and permissions; group/other access (mode wider than 600) → CHECK. Contents are never read or printed.
- SSH private keys without a passphrase → CHECK
- Git: `core.hooksPath`, `core.sshCommand`, `core.fsmonitor`, `core.gitProxy`, `core.askPass` in global and repo configs → CHECK; active hooks in `.git/hooks` of repos under the home folder → CHECK, or ALERT if a hook contains download/obfuscation/shell patterns
- Homebrew: third-party taps → CHECK; `HOMEBREW_BOTTLE_DOMAIN`, `HOMEBREW_API_DOMAIN`, `HOMEBREW_*_GIT_REMOTE` overrides in shell files → CHECK
- Language package indexes (`pip.conf`, `.pypirc`, `.npmrc`, `.yarnrc`, `.cargo/config`, `.gemrc`, `uv.toml`, and `PIP_INDEX_URL`/`NPM_CONFIG_REGISTRY`/… in shell files): `extra-index-url`, `trusted-host`, or a non-official host → CHECK (tokens and passwords are not shown)

### 8. Logs (7 days, `log show`)
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
- Kernel hardening sysctl: `kernel.kptr_restrict=0`, `kernel.dmesg_restrict=0`, `kernel.unprivileged_bpf_disabled=0` → CHECK; `kernel.modules_disabled` reported (1 = module loading locked); `net.ipv4.ip_forward=1` → CHECK unless container/VPN software is running

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
  - cross-check `/proc/modules` against `/sys/module`: a module present in one list but not the other → ALERT (`lsmod` reads `/proc/modules`, so `/sys/module` is the independent source)
- Dynamic linker: `/etc/ld.so.conf` and `ld.so.conf.d/*` adding library paths from `/tmp`, `/dev/shm`, `/home`, hidden folders → ALERT; conf files not owned by any package, or changed in the last 14 days → CHECK
- eBPF (needs `bpftool` and `sudo`): loaded tracing/networking programs (`kprobe`, `tracepoint`, `xdp`, `sched_cls`, `lsm`, …) → CHECK with counts (Falco, Cilium and EDR agents are legitimate users); pinned objects in `/sys/fs/bpf` listed
- systemd extras: `ExecStartPre/Post`, `ExecStop*`, `ExecReload` from a temp folder → ALERT, via an interpreter/downloader → CHECK; `OnFailure=`/`OnSuccess=` chains → CHECK; `LD_PRELOAD` in a unit → ALERT; drop-in overrides (`*.service.d/*.conf` with `Exec*`) → CHECK (ALERT from a temp folder); hand-made timers (`OnBootSec`, `OnCalendar`, …) → CHECK
- anacron: custom jobs in `/etc/anacrontab` → CHECK (ALERT for download/obfuscation patterns); `/etc/inittab` non-standard entries → CHECK; `/etc/init.d` scripts not owned by a package → CHECK, with download/reverse-shell/miner patterns → ALERT

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
- Known C2/RAT framework names (`sliver`, `mythic`, `meterpreter`, `cobaltstrike`, `havoc`, `pupy`, …) in running processes and in files under `/tmp`, `/var/tmp`, `/dev/shm`, `/opt`, `/usr/local/bin` and home folders → ALERT
- Tunnel / proxy tools running (`ngrok`, `frpc`, `chisel`, `cloudflared`, `ligolo`, `socat`, `tor`, `sshuttle`, `proxychains`, …) and `ssh -R` / `ssh -D` tunnels → CHECK
- Outbound connections with context (requires `sudo`): process, executable path, owning package (`[NONE]` = not from a package), remote IP. A shell or netcat (`bash`, `sh`, `nc`, …) holding a non-local connection → ALERT (typical reverse shell); a scripting interpreter (`python`, `perl`, `node`, …) → CHECK
- Shells or netcat whose stdin/stdout is a network socket (`/proc/<pid>/fd/0,1`) → ALERT; interpreters with both on sockets → CHECK
- Listeners reachable beyond localhost with unusual owners: from tmp/hidden paths, shells or netcat → ALERT; interpreters, `socat`, or binaries outside `/usr`, `/opt`, `/snap` → CHECK
- Tunnel/VPN interfaces (`tun`, `tap`, `wg`, `ppp`, `gre`, `ipip`, `zt`, `tailscale`, …) → CHECK; default route shown
- Time sync: clock not synchronized or NTP disabled → CHECK; non-standard NTP servers (`timesyncd`, `chrony`, `ntp`) → CHECK; more than 5 clock steps in 7 days (journal) → CHECK
- System utilities (`ps`, `ss`, `netstat`, `ls`, `top`, `lsof`, `ip`, `find`, `w`, `ssh`, `sudo`, `dmesg`, …): a copy in `/usr/local/{bin,sbin}` → ALERT; a script instead of a binary (wrapper that can hide output) → ALERT; a copy in `~/bin`, `~/.local/bin`, `~/.cargo/bin` → CHECK; this shell's `PATH` containing `.`, an empty entry, a temp folder or a world-writable folder → CHECK. Size/content mismatch against the package is covered by the checksum check in section 5.
- Unix sockets listening in `/tmp`, `/var/tmp`, `/dev/shm` (excluding X11, ICE, tmux, ssh-agent, dbus, …) → CHECK
- Raw and packet sockets (`ss -w`, `ss -0`, covering `/proc/net/raw` and `/proc/net/packet`): held by a process from a temp/hidden path → ALERT; by a process outside a list of known network daemons (dhclient, NetworkManager, chrony, ping, …) → CHECK

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
- sshd directives (effective config via `sshd -T` with `sudo`): `AuthorizedKeysCommand`, `ForceCommand` (except `internal-sftp`), `GatewayPorts yes/clientspecified`, `PermitTunnel`, `PermitUserEnvironment` → CHECK; `PermitEmptyPasswords yes` → ALERT while SSH is running; legacy algorithms in `Ciphers`/`MACs`/`KexAlgorithms`/`HostKeyAlgorithms`/`PubkeyAcceptedAlgorithms` (3DES, CBC, arcfour, MD5, `hmac-sha1-96`, `ssh-rsa`, `ssh-dss`, DH group1/group14-sha1) → CHECK
- Permissions of critical files: `/etc/shadow`, `/etc/gshadow` (and `-` backups) readable by everyone or writable by a group, `/etc/passwd`, `/etc/group`, `/etc/sudoers*`, `sshd_config`, `ssh_host_*_key` and `authorized_keys` writable by others or wrongly owned → ALERT; `sudoers` readable by everyone → CHECK

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
- Hidden entries (name starting with `.`) that no package owns: directly in `/usr/{bin,sbin,lib*,libexec}`, `/usr/local`, `/bin`, `/sbin`, `/lib*`, `/boot` → ALERT; elsewhere under `/usr`, `/etc`, `/boot`, `/var` (depth ≤ 3) → CHECK. `.build-id` and a few known files are ignored. Requires `sudo`.
- Docker (with `sudo`): running containers; containers that are privileged, use host PID/network namespaces, add `SYS_ADMIN`/`SYS_PTRACE`/`SYS_MODULE`/`NET_ADMIN`/`ALL`, mount `docker.sock`/`containerd.sock` or sensitive host paths (`/`, `/etc`, `/root`, `/proc`, `/sys`, `/home`, …) → CHECK
- Container runtime exposure: Docker socket world-accessible → ALERT; members of the `docker` group (root-equivalent) → CHECK; Docker daemon configured for TCP without `tlsverify` → ALERT; Docker API port 2375 listening beyond localhost → ALERT, 2376 → CHECK. Kubernetes checks live in `k8s_audit.sh`.
- Trusted root certificates: system roots issued in the last 30 days (`openssl x509 -startdate` on `/etc/ssl/certs/*.pem`) → CHECK; files in `/usr/share/ca-certificates` that no package owns → CHECK; manually added roots (`/usr/local/share/ca-certificates`, `ca-trust/source/anchors`) → CHECK; Firefox profiles with imported certificates (`certutil -L`, needs `libnss3-tools`) and Firefox policies that install certificates/import enterprise roots → CHECK; Java `cacerts` entries outside the stock set (Debian `debian:` aliases, JDK `[jdk]` aliases; needs `keytool`) → CHECK
- Pending security updates from cached metadata only (nothing is refreshed): `apt list --upgradable`, `dnf/yum -C updateinfo`, `zypper --no-refresh`, `pacman -Qu` → CHECK if any security update is pending; reboot required (`/var/run/reboot-required`, `needrestart -b`, `needs-restarting -r`) → CHECK. The package index age is reported when older than 7 days.
- Packages installed in the last 14 days

### 6. User environment: SSH, secrets, git, package sources
- SSH client config (`/etc/ssh/ssh_config*`, `~/.ssh/config`) of all users: `ProxyCommand`, `LocalCommand`, `KnownHostsCommand`, `PermitLocalCommand yes`, `Match exec` → CHECK; `~/.ssh/rc`, `~/.ssh/environment` (run on every SSH login), `/etc/ssh/sshrc` → CHECK; files in `~/.ssh` changed in the last 14 days → CHECK
- `~/.gnupg`: `*.conf` changed in the last 14 days, `pinentry-program` outside `/usr` → CHECK; executables in `~/.config` changed in the last 14 days → CHECK
- Credential files (`~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, `~/.netrc`, `~/.pgpass`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `gh`/`gcloud`/`azure` tokens, SSH private keys, `.env` files): only presence and permissions; group/other access (mode wider than 600) → CHECK. Contents are never read or printed.
- SSH private keys without a passphrase → CHECK
- Git: `core.hooksPath`, `core.sshCommand`, `core.fsmonitor`, `core.gitProxy`, `core.askPass` in global and repo configs → CHECK; active hooks in `.git/hooks` of repos under home folders → CHECK, or ALERT if a hook contains download/obfuscation/shell patterns
- System package sources:
  - apt: `[trusted=yes]` / `allow-insecure`, `AllowUnauthenticated` and similar → ALERT; non-official repositories over plain HTTP, non-empty legacy `/etc/apt/trusted.gpg`, sources/keys changed in the last 30 days → CHECK; third-party hosts listed
  - dnf/yum/zypp: `gpgcheck=0`, `sslverify=0`, repo files changed in the last 30 days → CHECK; third-party hosts listed
  - pacman: `SigLevel` containing `Never` → ALERT; custom repositories → CHECK
- Language package indexes (`pip.conf`, `.pypirc`, `.npmrc`, `.yarnrc`, `.cargo/config`, `.gemrc`, `uv.toml`, and `PIP_INDEX_URL`/`NPM_CONFIG_REGISTRY`/… in shell files): `extra-index-url`, `trusted-host`, or a non-official host → CHECK (tokens and passwords are not shown)

### 7. Logs (7 days, `journalctl` or `auth.log` / `secure`)
- Successful SSH logins → ALERT if any
- `sudo` commands in the last 7 days (last 20)
- Failed authentication attempts → CHECK if more than 20
- Top sources of failed logins (`lastb`)
- Logging health: `systemd-journald` not running → ALERT; `rsyslog`/`syslog-ng`/`auditd` installed but stopped, `auditctl -s` showing `enabled=0`, journald `Storage=none` → CHECK; busy logs (`auth.log`, `syslog`, `messages`, `secure`, `kern.log`, `audit.log`) empty, `wtmp`/`lastlog` empty on a host that has been up for more than 2 days (skipped in containers) → CHECK; files in `/var/log` symlinked to `/dev/null` → ALERT; shell/tool history symlinked to `/dev/null` → CHECK; newest journal entry older than 24 h → CHECK
- File-integrity monitoring: if AIDE is installed, the newest report (`found differences` → CHECK, older than 8 days → CHECK, no report → CHECK); Tripwire report age and violations (`twprint`); a note if neither tool is installed
- Kernel log (`dmesg`, needs `sudo` and a readable ring buffer): unsigned/out-of-tree module loads, more than 20 AppArmor/SELinux denials, thermal/throttling messages, more than 10 crashes (segfault/protection fault) → CHECK; OOM events are reported as information
- Suspicious commands in `.bash_history` / `.zsh_history` (`curl | sh`, `/dev/tcp/`, `nc -e`, `base64 -d`, `xmrig`) → CHECK

If logs are unavailable the check is skipped explicitly ("Log checks skipped") instead of being reported as clean.

## Checks: Kubernetes (`k8s_audit.sh`)

A separate script because it targets a different kind of system: part 1 runs on a Kubernetes node, part 2 runs anywhere `kubectl` is configured (your laptop, a bastion). The summary says "Nothing was checked" if neither part could run, instead of reporting a clean result.

### 1. Node components (run on a node; `sudo` for process and manifest access)
Detected as a node when `/etc/kubernetes` exists or a `kubelet`/`k3s`/`rke2`/`k0s`/`microk8s`/`kube-apiserver` process runs; otherwise skipped.
- Ports listening beyond localhost (`ss`): kubelet read-only port 10255 → ALERT (unauthenticated pod/node information); kubelet API 10250 and etcd 2379/2380 → CHECK
- Static pod manifests (`/etc/kubernetes/manifests/*.yaml|yml`): `privileged: true`, `hostPID: true`, `hostIPC: true`, or a `hostPath` that is exactly `/`, `/etc`, `/root`, `/proc`, `/sys`, `/home`, `docker.sock` or `containerd.sock` → CHECK. Normal control-plane mounts (`/etc/kubernetes/pki`, `/var/lib/etcd`) and `hostNetwork` are not flagged.
- Static pod manifests changed in the last 14 days → CHECK (a changed manifest restarts a control-plane component)

### 2. Cluster workloads (`kubectl`; optional context argument)
- Prints the context and API server first, then reads `kubectl get pods -A`
- Pods outside `kube-system` with a `privileged` container, `hostPID`, or a `hostPath` of `/`, `/etc`, `/etc/*`, `/root`, `/proc`, `/sys`, `/home`, `docker.sock` or `containerd` sockets → CHECK (first 20). `kube-system` pods are only counted (CNI plugins, kube-proxy and node agents normally need host access)
- If `kubectl` is missing, no context is configured, or the cluster is unreachable/forbidden, the part is skipped with a message

Not covered: RBAC and `cluster-admin` bindings, secrets, NetworkPolicy, `initContainers`, capabilities (`SYS_ADMIN`, …), `hostNetwork`, `runAsUser: 0`, kubelet configuration (anonymous auth, `readOnlyPort`), and containerd/CRI containers on the node (`linux_audit.sh` inspects Docker only).

## Not covered

- Browser extensions (the script reminds you to review them manually)
- Kernel-level and firmware rootkits
- Whether file contents are malicious (no antivirus scanning)
- Windows (no script)

## Development

Contribution rules and the testing procedure (including in a Debian container) are in [CLAUDE.md](CLAUDE.md).
"# compromise-audit" 
