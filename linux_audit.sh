#!/bin/bash
# =====================================================================
#  linux_audit.sh — standalone Linux compromise audit (console output only)
#
#  READ-ONLY: nothing is deleted, changed, disabled or written to disk.
#
#  Usage:   sudo bash linux_audit.sh
#           (without sudo some checks are skipped)
#
#  Works on systemd-based distros (Debian/Ubuntu, RHEL/Fedora, Arch, SUSE).
# =====================================================================

set -u
export LC_ALL=C
ORIG_PATH="$PATH"   # PATH of the invoking shell, used by the PATH-hijack check
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:$PATH

# ---------- colors ----------
if [ -t 1 ]; then
  RED=$'\033[1;31m'; YEL=$'\033[1;33m'; GRN=$'\033[1;32m'
  BLU=$'\033[1;34m'; DIM=$'\033[2m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
  RED=""; YEL=""; GRN=""; BLU=""; DIM=""; BLD=""; RST=""
fi

# ---------- setup ----------
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
REAL_USER="${SUDO_USER:-$(id -un)}"
USER_HOME=$(getent passwd "$REAL_USER" 2>/dev/null | cut -d: -f6)
[ -n "$USER_HOME" ] || USER_HOME="$HOME"

# Home directories of all real users (for per-user checks)
ALL_HOMES=$(getent passwd | awk -F: '($3>=1000 && $3<65534) || $3==0 {print $6}' | sort -u)
[ -n "$ALL_HOMES" ] || ALL_HOMES="$USER_HOME"

HAVE_SYSTEMD=0; command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] && HAVE_SYSTEMD=1

ALERTS=0; WARNS=0
SUMMARY_ALERTS=""; SUMMARY_WARNS=""
NL=$'\n'

alert() {
  echo "  🔴 ${RED}ALERT:${RST} $*"
  ALERTS=$((ALERTS+1)); SUMMARY_ALERTS="${SUMMARY_ALERTS}  🔴 ${RED}ALERT:${RST} $*${NL}"
}
warn() {
  echo "  🟡 ${YEL}CHECK:${RST} $*"
  WARNS=$((WARNS+1)); SUMMARY_WARNS="${SUMMARY_WARNS}  🟡 ${YEL}CHECK:${RST} $*${NL}"
}
ok()      { echo "  🟢 $*"; }
info()    { echo "  ${DIM}$*${RST}"; }
section() { echo; echo "${BLU}${BLD}=== $1 ===${RST}"; }

# show "title" "command" [max lines] — run and print indented output
show() {
  local title="$1" cmd="$2" max="${3:-40}" out
  echo "  ${BLD}$title${RST}"
  out=$(export -f cols 2>/dev/null; bash -c "$cmd" 2>&1 | head -n "$max")
  if [ -n "$out" ]; then echo "$out" | sed 's/^/    /'; else info "  (empty)"; fi
}

# table formatter: column(1) is missing on minimal images
cols() { if command -v column >/dev/null 2>&1; then column -t; else cat; fi; }

need_root() {
  [ $IS_ROOT -eq 1 ] && return 0
  info "Skipped: requires sudo."
  return 1
}

# Package owning a file: prints package name or "NONE" (not owned / unknown)
pkg_owner() {
  local f="$1" r
  if command -v dpkg >/dev/null 2>&1; then
    r=$(dpkg -S "$f" 2>/dev/null | head -1 | cut -d: -f1)
    # merged-/usr: older packages register /bin/x while the file is reached as /usr/bin/x
    [ -z "$r" ] && case "$f" in /usr/*) r=$(dpkg -S "${f#/usr}" 2>/dev/null | head -1 | cut -d: -f1);; esac
  elif command -v rpm >/dev/null 2>&1; then
    r=$(rpm -qf "$f" 2>/dev/null | head -1); case "$r" in *"not owned"*) r="";; esac
  elif command -v pacman >/dev/null 2>&1; then
    r=$(pacman -Qoq "$f" 2>/dev/null | head -1)
  else
    r="?"
  fi
  [ -n "$r" ] && echo "$r" || echo "NONE"
}

# Real path of the program started by a systemd unit's ExecStart / cron line
first_exe() {
  local s="$1"
  s="${s#-}"; s="${s#@}"; s="${s#+}"; s="${s#!}"
  echo "${s%% *}"
}

HOSTNAME_S=$(hostname 2>/dev/null)
OS_NAME=$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)
echo "${BLD}Linux Security Audit${RST}"
echo "Host: $HOSTNAME_S  |  $OS_NAME  |  kernel $(uname -r)  |  $(date '+%Y-%m-%d %H:%M')"
echo "User: $REAL_USER  |  Mode: $([ $IS_ROOT -eq 1 ] && echo 'full (sudo)' || echo 'limited (no sudo)')"
[ $IS_ROOT -eq 0 ] && echo "${YEL}Running without sudo — some checks will be skipped.${RST}"

# =====================================================================
section "1. Built-in protection"

if [ -r /sys/fs/selinux/enforce ]; then
  if [ "$(cat /sys/fs/selinux/enforce)" = "1" ]; then ok "SELinux enforcing"
  else warn "SELinux is in permissive mode"; fi
elif command -v aa-status >/dev/null 2>&1 || [ -d /sys/kernel/security/apparmor ]; then
  if [ -r /sys/module/apparmor/parameters/enabled ] && grep -q Y /sys/module/apparmor/parameters/enabled; then
    ok "AppArmor enabled"
  else warn "AppArmor present but not enabled"; fi
else
  warn "No mandatory access control (SELinux/AppArmor) active"
fi

ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
if [ "$ASLR" = "2" ]; then ok "ASLR fully enabled"
else warn "ASLR is not fully enabled (randomize_va_space=${ASLR:-?})"; fi

# Firewall
FW=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then FW=1; ok "ufw firewall active"; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then FW=1; ok "firewalld running"; fi
if [ $FW -eq 0 ]; then
  if [ $IS_ROOT -eq 1 ]; then
    RULES=0
    command -v nft >/dev/null 2>&1 && RULES=$((RULES + $(nft list ruleset 2>/dev/null | grep -c 'rule\|accept\|drop\|reject')))
    command -v iptables >/dev/null 2>&1 && RULES=$((RULES + $(iptables -S 2>/dev/null | grep -vc '^-P .* ACCEPT$')))
    if [ "$RULES" -gt 0 ]; then ok "nftables/iptables rules present"
    else warn "No active firewall rules found"; fi
  else
    info "Firewall state requires sudo."
  fi
fi

# Disk encryption
if lsblk -o TYPE 2>/dev/null | grep -q crypt; then ok "Encrypted (LUKS/dm-crypt) volume in use"
else warn "No dm-crypt/LUKS volume — disk is not encrypted (ignore for servers/VMs if intended)"; fi

# Secure Boot
if command -v mokutil >/dev/null 2>&1; then
  if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then ok "Secure Boot enabled"
  else info "Secure Boot not enabled or unavailable"; fi
fi

# Kernel taint (unsigned/out-of-tree modules)
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null)
if [ -n "$TAINT" ] && [ "$TAINT" != "0" ]; then
  warn "Kernel is tainted (value $TAINT) — out-of-tree/unsigned module or other flag; check section 3"
else ok "Kernel not tainted"; fi

# Kernel hardening (sysctl)
sysctl_get() { cat "/proc/sys/$(echo "$1" | tr . /)" 2>/dev/null; }
WEAKSYS=""
[ "$(sysctl_get kernel.kptr_restrict)" = "0" ] && WEAKSYS="${WEAKSYS}kernel.kptr_restrict=0 (kernel addresses visible to users); "
[ "$(sysctl_get kernel.dmesg_restrict)" = "0" ] && WEAKSYS="${WEAKSYS}kernel.dmesg_restrict=0 (any user can read dmesg); "
[ "$(sysctl_get kernel.unprivileged_bpf_disabled)" = "0" ] && WEAKSYS="${WEAKSYS}kernel.unprivileged_bpf_disabled=0 (any user can load BPF programs); "
if [ -n "$WEAKSYS" ]; then warn "Weak kernel hardening: $WEAKSYS"
else ok "kptr_restrict, dmesg_restrict and unprivileged_bpf_disabled are hardened"; fi
MODDIS=$(sysctl_get kernel.modules_disabled)
if [ "$MODDIS" = "1" ]; then ok "Kernel module loading is locked (kernel.modules_disabled=1)"
else info "kernel.modules_disabled=${MODDIS:-?} — module loading is allowed (hardened servers set 1 after boot)"; fi
if [ "$(sysctl_get net.ipv4.ip_forward)" = "1" ]; then
  if ps -eo comm= | grep -qE '^(dockerd|containerd|kubelet|libvirtd|tailscaled|wg-quick|openvpn|strongswan|charon)$'; then
    info "net.ipv4.ip_forward=1 (expected here: container/VPN software is running)"
  else
    warn "net.ipv4.ip_forward=1 — this host routes packets (normal for routers/VPN gateways, otherwise a pivot risk)"
  fi
fi

# =====================================================================
section "2. Persistence: systemd units, cron, init"

if [ $HAVE_SYSTEMD -eq 1 ]; then
  echo "  ${BLD}Custom systemd units (/etc/systemd, ~/.config/systemd)${RST}"
  UNIT_DIRS="/etc/systemd/system /etc/systemd/user"
  for h in $ALL_HOMES; do UNIT_DIRS="$UNIT_DIRS $h/.config/systemd/user"; done
  found=0
  while IFS= read -r u; do
    [ -f "$u" ] || continue
    found=1
    name=$(basename "$u")
    line=$(grep -m1 -E '^ExecStart=' "$u" 2>/dev/null | cut -d= -f2-)
    exe=$(first_exe "$line")
    printf '    %-45s\n' "$name"
    printf '      -> %s\n' "${line:-"(no ExecStart)"}"

    if [ -n "$exe" ] && [ "${exe#/}" != "$exe" ]; then
      if [ ! -e "$exe" ]; then
        warn "Unit $name points to missing file: $exe"
      else
        case "$exe" in
          /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*)
            alert "Unit $name runs from temp folder: $exe";;
          */.*)
            warn "Unit $name runs from hidden path: $exe";;
        esac
        case "$exe" in
          /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*) ;;
          *) [ "$(pkg_owner "$exe")" = "NONE" ] && info "      (binary not owned by any package)";;
        esac
      fi
    fi
    case "$(basename "$exe")" in
      bash|sh|dash|zsh|python*|perl|ruby|curl|wget|nc|ncat|node)
        warn "Unit $name runs an interpreter/downloader: $line";;
    esac
    if grep -qiE '(^|[^[:alnum:]_./-])(curl|wget)[[:space:]]|base64 -d|/dev/tcp/|nc -e|bash -i|stratum\+|xmrig' "$u" 2>/dev/null; then
      alert "Unit $name contains suspicious commands (download/reverse shell/miner)"
    fi
    EXTRA=$(grep -E '^(ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload)=' "$u" 2>/dev/null)
    if [ -n "$EXTRA" ]; then
      while IFS= read -r xl; do
        xe=$(first_exe "${xl#*=}")
        case "$xe" in /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*) alert "Unit $name: ${xl%%=*} runs from temp folder: $xe";; esac
        case "$(basename "$xe")" in bash|sh|dash|zsh|python*|perl|ruby|curl|wget|nc|ncat|node) warn "Unit $name: ${xl%%=*} runs an interpreter/downloader: ${xl#*=}";; esac
      done <<< "$EXTRA"
    fi
    OF=$(grep -E '^(OnFailure|OnSuccess)=' "$u" 2>/dev/null)
    [ -n "$OF" ] && warn "Unit $name chains another unit: $(echo $OF) (verify the target)"
    grep -qE 'LD_PRELOAD' "$u" 2>/dev/null && alert "Unit $name sets LD_PRELOAD"
  done < <(find $UNIT_DIRS -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) -type f 2>/dev/null)
  [ $found -eq 0 ] && info "  (none)"

  RECENT_UNITS=$(find $UNIT_DIRS /usr/lib/systemd/system /lib/systemd/system -name '*.service' -mtime -14 2>/dev/null)
  [ -n "$RECENT_UNITS" ] && warn "systemd units created/modified in last 14 days: $(echo $RECENT_UNITS)"

  show "Enabled timers" "systemctl list-timers --all --no-pager --no-legend | awk '{print \$(NF-1), \$NF}'" 20
fi

# ---------- cron ----------
CRON=""
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$f" ] && CRON="${CRON}$(grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed "s|^|[$f] |")${NL}"
done
if [ $IS_ROOT -eq 1 ]; then
  for u in $(getent passwd | cut -d: -f1); do
    c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
    [ -n "$c" ] && CRON="${CRON}$(echo "$c" | sed "s|^|[user $u] |")${NL}"
  done
else
  c=$(crontab -l 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
  [ -n "$c" ] && CRON="${CRON}$(echo "$c" | sed "s|^|[user $REAL_USER] |")${NL}"
fi
CRON=$(echo "$CRON" | grep -v '^$' | grep -vE 'run-parts|/etc/cron\.(hourly|daily|weekly|monthly)|^\[/etc/crontab\] (SHELL|PATH|MAILTO)=')
if [ -n "$CRON" ]; then
  warn "Cron jobs found — make sure you created them"
  echo "$CRON" | cut -c1-220 | sed 's/^/    /'
else ok "No custom cron jobs"; fi

CRONBAD=$(echo "$CRON" | grep -iE 'curl|wget|base64|/dev/tcp/|nc -e|bash -i|/tmp/|/dev/shm/|python[0-9.]* -c')
[ -n "$CRONBAD" ] && alert "Cron jobs with download/obfuscation/temp-folder patterns:" && echo "$CRONBAD" | cut -c1-220 | sed 's/^/    /'

RECENT_CRON=$(find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron -type f -mtime -14 2>/dev/null)
[ -n "$RECENT_CRON" ] && warn "Cron files modified in last 14 days: $(echo $RECENT_CRON)"

# at jobs
if command -v atq >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  AT=$(atq 2>/dev/null)
  [ -n "$AT" ] && warn "Scheduled 'at' jobs:" && echo "$AT" | sed 's/^/    /'
fi

# ---------- init / boot scripts ----------
if [ -s /etc/rc.local ]; then
  RC=$(grep -vE '^[[:space:]]*(#|$|exit 0)' /etc/rc.local)
  [ -n "$RC" ] && warn "/etc/rc.local has commands" && echo "$RC" | cut -c1-200 | sed 's/^/    /'
fi

# ---------- ld.so.preload / LD_PRELOAD (userland rootkits) ----------
if [ -s /etc/ld.so.preload ]; then
  alert "/etc/ld.so.preload is non-empty (userland rootkit technique):"
  sed 's/^/    /' /etc/ld.so.preload
else ok "/etc/ld.so.preload empty/absent"; fi

LDP=$(grep -rlsE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null)
[ -n "$LDP" ] && warn "LD_PRELOAD/LD_LIBRARY_PATH set in: $(echo $LDP)"

# ---------- XDG autostart ----------
AUTOS=""
for d in /etc/xdg/autostart $(for h in $ALL_HOMES; do echo "$h/.config/autostart"; done); do
  [ -d "$d" ] && AUTOS="${AUTOS}$(find "$d" -name '*.desktop' -mtime -30 2>/dev/null)${NL}"
done
AUTOS=$(echo "$AUTOS" | grep -v '^$')
[ -n "$AUTOS" ] && warn "Autostart entries created/modified in last 30 days:" && echo "$AUTOS" | sed 's/^/    /'

# ---------- udev rules / PAM / motd ----------
RECENT_UDEV=$(find /etc/udev/rules.d /usr/lib/udev/rules.d -type f -mtime -14 2>/dev/null)
[ -n "$RECENT_UDEV" ] && warn "udev rules modified in last 14 days: $(echo $RECENT_UDEV)"

RECENT_PAM=$(find /etc/pam.d /lib/security /lib64/security /usr/lib/security /usr/lib/x86_64-linux-gnu/security -type f -mtime -14 2>/dev/null)
[ -n "$RECENT_PAM" ] && warn "PAM files modified in last 14 days (credential-stealing vector): $(echo $RECENT_PAM)"

RECENT_MOTD=$(find /etc/update-motd.d -type f -mtime -14 2>/dev/null)
[ -n "$RECENT_MOTD" ] && warn "update-motd scripts modified in last 14 days: $(echo $RECENT_MOTD)"

# ---------- kernel modules ----------
echo "  ${BLD}Kernel modules${RST}"
OOT=""
while read -r m _; do
  [ -z "$m" ] && continue
  t=$(cat "/sys/module/$m/taint" 2>/dev/null)
  [ -n "$t" ] && OOT="${OOT}${m} (taint: $t)${NL}"
done < <(tail -n +1 /proc/modules 2>/dev/null)
if [ -n "$OOT" ]; then
  warn "Kernel modules flagged as out-of-tree/unsigned (OK for NVIDIA/VirtualBox/ZFS drivers):"
  printf '%s' "$OOT" | sed 's/^/    /'
else ok "No tainted kernel modules"; fi

if command -v modinfo >/dev/null 2>&1; then
  NOFILE=""
  while read -r m _; do
    [ -z "$m" ] && continue
    modinfo -n "$m" >/dev/null 2>&1 || NOFILE="${NOFILE}${m} "
  done < <(cat /proc/modules 2>/dev/null)
  [ -n "$NOFILE" ] && alert "Loaded modules with no file on disk (possible LKM rootkit): $NOFILE"
fi

# ---------- dynamic linker configuration ----------
echo "  ${BLD}Dynamic linker configuration${RST}"
LD_BAD=0
for f in /etc/ld.so.conf /etc/ld.so.conf.d/*; do
  [ -f "$f" ] || continue
  while IFS= read -r line; do
    case "$line" in
      /tmp*|/var/tmp*|/dev/shm*|/run/shm*|/home/*|/root/*|*/.*)
        LD_BAD=1; alert "ld.so config $f adds a library path from a user/temp location: $line";;
    esac
  done < <(grep -vE '^[[:space:]]*(#|$|include)' "$f" 2>/dev/null)
  [ "$f" = "/etc/ld.so.conf" ] && continue
  if [ "$(pkg_owner "$f")" = "NONE" ]; then
    LD_BAD=1; warn "ld.so.conf.d file not owned by any package (hand-made or third-party installer): $f"
  fi
done
RECENT_LD=$(find /etc/ld.so.conf /etc/ld.so.conf.d -type f -mtime -14 2>/dev/null)
[ -n "$RECENT_LD" ] && LD_BAD=1 && warn "ld.so configuration changed in last 14 days: $(echo $RECENT_LD)"
[ $LD_BAD -eq 0 ] && ok "ld.so configuration looks standard"

# ---------- eBPF programs ----------
echo "  ${BLD}eBPF programs${RST}"
if command -v bpftool >/dev/null 2>&1; then
  if need_root; then
    BPF=$(bpftool prog list 2>/dev/null | awk '/^[0-9]+:/ {t=$2; n="-"; for(i=1;i<=NF;i++) if($i=="name") n=$(i+1); print t, n}')
    BPFX=$(echo "$BPF" | grep -E '^(kprobe|kretprobe|tracepoint|raw_tracepoint|raw_tracepoint_writable|perf_event|xdp|sched_cls|sched_act|lsm|tracing|ext|struct_ops|socket_filter|sk_skb|sk_msg|sk_lookup|flow_dissector) ' | sort | uniq -c | sort -nr | head -15)
    BPFN=$(echo "$BPF" | grep -c .)
    if [ -n "$BPFX" ]; then
      warn "eBPF tracing/networking programs loaded ($BPFN programs in total). Falco, Cilium, bpftrace and EDR agents use these; an unexpected one can be a rootkit:"
      echo "$BPFX" | sed 's/^/    /'
    else ok "No tracing/networking eBPF programs loaded ($BPFN programs in total)"; fi
    PINNED=$(find /sys/fs/bpf -mindepth 1 -maxdepth 2 2>/dev/null | head -10)
    [ -n "$PINNED" ] && info "Pinned BPF objects in /sys/fs/bpf:" && echo "$PINNED" | sed 's/^/    /'
  fi
else
  info "bpftool not installed — loaded BPF programs are not enumerated (Debian/Ubuntu: apt install bpftool)."
fi

# ---------- loaded modules: /proc/modules vs /sys/module ----------
echo "  ${BLD}Kernel module cross-check (/proc/modules vs /sys/module)${RST}"
PMODS=$(awk '{print $1}' /proc/modules 2>/dev/null | sort -u)
SMODS=$(for d in /sys/module/*; do [ -e "$d/initstate" ] && basename "$d"; done | sort -u)
if [ -n "$PMODS$SMODS" ]; then
  HIDMOD=$(comm -13 <(echo "$PMODS") <(echo "$SMODS") | grep -v '^$')
  GHOSTMOD=$(comm -23 <(echo "$PMODS") <(echo "$SMODS") | grep -v '^$')
  if [ -n "$HIDMOD" ]; then alert "Modules present in /sys/module but hidden from /proc/modules and lsmod (rootkit technique): $(echo $HIDMOD)"; fi
  if [ -n "$GHOSTMOD" ]; then alert "Modules listed in /proc/modules but missing from /sys/module: $(echo $GHOSTMOD)"; fi
  [ -z "$HIDMOD$GHOSTMOD" ] && ok "Module lists agree ($(echo "$PMODS" | grep -c .) loaded modules)"
fi

# ---------- anacron, inittab, init.d, systemd drop-ins and timers ----------
echo "  ${BLD}Scheduler and boot scripts${RST}"
SCHED_HIT=0
if [ -f /etc/anacrontab ]; then
  AC=$(grep -vE '^[[:space:]]*(#|$)' /etc/anacrontab | grep -vE '^[[:space:]]*[A-Za-z_]+=' | grep -v 'run-parts')
  if [ -n "$AC" ]; then
    SCHED_HIT=1; warn "Custom anacron jobs:"; echo "$AC" | cut -c1-200 | sed 's/^/    /'
    echo "$AC" | grep -qiE 'curl|wget|base64|/dev/tcp/|nc -e|bash -i|/tmp/|/dev/shm/' && alert "anacron job with download/obfuscation/temp-folder patterns"
  fi
fi
if [ -f /etc/inittab ]; then
  IT=$(grep -vE '^[[:space:]]*(#|$)' /etc/inittab | awk -F: '$3 ~ /respawn|once|wait|sysinit|boot|bootwait|ondemand/' | grep -vE 'getty|mingetty|/etc/rc|rc\.sysinit|rc\.d|shutdown|/sbin/init|ctrlaltdel|upstart|systemd|login')
  if [ -n "$IT" ]; then SCHED_HIT=1; warn "Non-standard /etc/inittab entries:"; echo "$IT" | cut -c1-200 | sed 's/^/    /'; fi
fi
INIT_UNOWNED=""; INIT_EVIL=""
for f in /etc/init.d/* /etc/rc.d/init.d/*; do
  [ -f "$f" ] || continue
  case "$f" in */README|*/skeleton|*/functions|*/.depend*) continue;; esac
  grep -qE '(^|[^[:alnum:]_./-])(curl|wget)[[:space:]]|/dev/tcp/|nc -e|bash -i|base64 -d|xmrig|stratum\+' "$f" 2>/dev/null && INIT_EVIL="${INIT_EVIL}${f}${NL}"
  [ "$(pkg_owner "$f")" = "NONE" ] && INIT_UNOWNED="${INIT_UNOWNED}${f}${NL}"
done
if [ -n "$INIT_EVIL" ]; then SCHED_HIT=1; alert "init scripts with download/reverse-shell/miner patterns:"; printf '%s' "$INIT_EVIL" | sed 's/^/    /'; fi
if [ -n "$INIT_UNOWNED" ]; then SCHED_HIT=1; warn "init scripts not owned by any package (hand-made or third-party):"; printf '%s' "$INIT_UNOWNED" | sed 's/^/    /'; fi
if [ $HAVE_SYSTEMD -eq 1 ]; then
  DROPINS=$(grep -rlE '^(ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload)=' /etc/systemd/system --include='*.conf' 2>/dev/null)
  for d in $DROPINS; do
    SCHED_HIT=1
    warn "systemd drop-in overrides how a service runs: $d"
    grep -E '^Exec' "$d" | cut -c1-160 | sed 's/^/    /'
    grep -qE '^Exec[A-Za-z]*=[-@+!]*(/tmp/|/var/tmp/|/dev/shm/)' "$d" && alert "Drop-in $d runs a command from a temp folder"
  done
  TIMERS=$(find /etc/systemd/system /etc/systemd/user $(for h in $ALL_HOMES; do echo "$h/.config/systemd/user"; done) -maxdepth 2 -name '*.timer' -type f 2>/dev/null)
  for t in $TIMERS; do
    SCHED_HIT=1
    sched=$(grep -hE '^(OnBootSec|OnStartupSec|OnUnitActiveSec|OnUnitInactiveSec|OnCalendar)=' "$t" | tr '\n' ' ')
    warn "Hand-made systemd timer $(basename "$t"): ${sched:-no schedule} (OnBootSec/OnStartupSec run after every boot)"
  done
fi
[ $SCHED_HIT -eq 0 ] && ok "No custom anacron/inittab/init.d entries, drop-ins or timers"

# =====================================================================
section "3. Processes & network"

# ---------- processes running from suspicious places or deleted binaries ----------
SUSP=""; DELETED=""
for p in /proc/[0-9]*; do
  pid=${p#/proc/}
  exe=$(readlink "$p/exe" 2>/dev/null) || continue
  [ -z "$exe" ] && continue
  case "$exe" in
    *"(deleted)"*) DELETED="${DELETED}${pid} ${exe}${NL}";;
  esac
  case "$exe" in
    /tmp/*|/var/tmp/*|/dev/shm/*|/run/shm/*|*/.*)
      SUSP="${SUSP}${pid} ${exe}${NL}";;
  esac
  case "$exe" in
    /memfd:*) SUSP="${SUSP}${pid} ${exe} (fileless)${NL}";;
  esac
done
if [ -n "$SUSP" ]; then
  alert "Processes running from temp/hidden location or memory:"
  printf '%s' "$SUSP" | sed 's/^/    /'
else ok "No processes running from /tmp, /dev/shm or hidden paths"; fi
if [ -n "$DELETED" ]; then
  warn "Processes whose binary was deleted (normal right after an update; otherwise a malware trick):"
  printf '%s' "$DELETED" | sort -u | head -20 | sed 's/^/    /'
fi

# ---------- hidden processes (visible in /proc but not in ps) ----------
PS_PIDS=$(ps -eo pid= | tr -d ' ' | sort -n)
PROC_PIDS=$(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n)
HIDDEN=$(comm -13 <(echo "$PS_PIDS") <(echo "$PROC_PIDS") | while read -r pid; do
  [ -d "/proc/$pid" ] && echo "$pid $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-100)"
done)
if [ -n "$HIDDEN" ]; then
  info "PIDs in /proc missing from ps (often short-lived processes; re-run to confirm):"
  echo "$HIDDEN" | head -10 | sed 's/^/    /'
fi

# ---------- crypto-miner detection ----------
echo "  ${BLD}Crypto-miner detection${RST}"
MINER_NAMES='xmrig|xmr-stak|minerd|cpuminer|ccminer|cgminer|bfgminer|ethminer|nbminer|t-rex|phoenixminer|lolminer|gminer|nanominer|srbminer|teamredminer|kdevtmpfsi|kinsing|minergate|nicehash|kthreaddi|sysupdate|networkservice|dbused'
MINER_ARGS='stratum\+(tcp|ssl|tls)://|--donate-level|--cpu-priority|randomx|cryptonight|minexmr|supportxmr|nanopool|moneroocean|hashvault|c3pool|2miners|f2pool|herominers|unmineable'
MINER_PORTS='3333|4444|5555|6666|7777|14433|14444|45560|45700'
MINER_FOUND=0

MINERS=$(ps -eww -o pid=,user=,%cpu=,args= | grep -iE "$MINER_NAMES|$MINER_ARGS" | grep -v grep)
if [ -n "$MINERS" ]; then
  MINER_FOUND=1
  alert "Possible crypto-miner process running:"
  echo "$MINERS" | cut -c1-220 | sed 's/^/    /'
fi

if command -v ss >/dev/null 2>&1; then
  # with "state established" ss prints: Recv-Q Send-Q Local Peer Process — match the peer port
  MCONN=$(ss -tnpH state established 2>/dev/null | awk '{print $4, $5}' | grep -E ":($MINER_PORTS)( |$)")
  if [ -n "$MCONN" ]; then
    MINER_FOUND=1
    warn "Connections to ports typical for mining pools ($MINER_PORTS):"
    echo "$MCONN" | sed 's/^/    /'
  fi
fi

MFILES=$(find /tmp /var/tmp /dev/shm /opt /usr/local/bin /root/.cache /root/.config $(for h in $ALL_HOMES; do echo "$h/.cache $h/.config $h/.local"; done) \
         -maxdepth 4 \( -iname '*xmrig*' -o -iname '*minerd*' -o -iname '*cpuminer*' -o -iname '*xmr-stak*' -o -iname '*kdevtmpfsi*' -o -iname '*kinsing*' \) 2>/dev/null | head -20)
if [ -n "$MFILES" ]; then
  MINER_FOUND=1
  alert "Miner-like files found on disk:"
  echo "$MFILES" | sed 's/^/    /'
fi

MUNITS=$(grep -rliE "$MINER_NAMES|stratum\+" /etc/systemd/system /etc/cron.d /var/spool/cron 2>/dev/null)
if [ -n "$MUNITS" ]; then
  MINER_FOUND=1
  alert "Units/cron files referencing a miner: $(echo $MUNITS)"
fi

[ $MINER_FOUND -eq 0 ] && ok "No crypto-miner indicators"

# ---------- known C2 / RAT frameworks ----------
echo "  ${BLD}Known C2 / RAT frameworks${RST}"
RAT_NAMES='sliver|mythic|apfell|meterpreter|metsvc|msfvenom|msfconsole|cobaltstrike|cobalt_strike|havoc-?(client|teamserver)|poshc2|koadic|pupy|empire-?(agent|server)|starkiller|bruteratel|merlin-?agent|dnscat|icmpsh|weevely|mettle|osxrat|macshellz|evilginx|revshell|reverse_?shell'
RAT_FOUND=0
RATP=$(ps -eww -o pid=,user=,args= | grep -iE "$RAT_NAMES" | grep -v grep)
if [ -n "$RATP" ]; then
  RAT_FOUND=1
  alert "Process matching a known C2/RAT framework:"
  echo "$RATP" | cut -c1-200 | sed 's/^/    /'
fi
RATF=$(find /tmp /var/tmp /dev/shm /opt /usr/local/bin $ALL_HOMES -maxdepth 4 \( -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null \
       | grep -iE "/[^/]*($RAT_NAMES)[^/]*$" | head -20)
if [ -n "$RATF" ]; then
  RAT_FOUND=1
  alert "Files named like a known C2/RAT framework:"
  echo "$RATF" | sed 's/^/    /'
fi
[ $RAT_FOUND -eq 0 ] && ok "No known C2/RAT framework names"

# ---------- tunnels and proxy tooling ----------
echo "  ${BLD}Tunnel / proxy tooling${RST}"
TUNNEL_RE='^(ngrok|frpc|frps|chisel|cloudflared|ligolo|ligolo-ng|sshuttle|autossh|proxychains|proxychains4|tor|socat|gost|rathole|bore|nps|npc|dnscat2|iodine|iodined|ptunnel|stunnel|stunnel4|3proxy|microsocks|redsocks|revsocks)$'
TUNP=$(ps -eo pid=,user=,comm= | awk -v re="$TUNNEL_RE" '$3 ~ re')
SSHT=$(ps -eo pid=,user=,args= | grep -E '(^|[ /])ssh( |$)' | grep -E ' -[A-Za-z]*[RD]([[:space:]]|[0-9:]|\[)' | grep -v grep)
if [ -n "$TUNP" ]; then
  warn "Tunnel/proxy tools running (legitimate if you started them):"
  echo "$TUNP" | sed 's/^/    /'
fi
if [ -n "$SSHT" ]; then
  warn "SSH reverse (-R) or SOCKS (-D) tunnels running:"
  echo "$SSHT" | cut -c1-200 | sed 's/^/    /'
fi
[ -z "$TUNP$SSHT" ] && ok "No tunnel/proxy tools or SSH tunnels running"

HICPU=$(ps -eo pid=,%cpu=,user=,comm= | awk '$2>=80 && $4!="ps" && $4!="awk" && $4!="sort" && $4!="head"' | sort -k2 -nr | head -10)
if [ -n "$HICPU" ]; then
  warn "Processes using >=80% CPU right now (re-check later; miners keep CPU high constantly):"
  echo "$HICPU" | sed 's/^/    /'
fi

# ---------- network ----------
if command -v ss >/dev/null 2>&1; then
  show "Listening TCP/UDP ports" "ss -tulnpH | awk '{print \$1, \$5, \$7}' | cols" 40
  show "Established connections" "ss -tnpH state established | awk '{print \$3, \$4, \$5}' | cols" 50
else
  show "Listening ports" "netstat -tulnp" 40
fi

# ---------- connections with process context ----------
echo "  ${BLD}Outbound connections with process context${RST}"
if [ $IS_ROOT -eq 1 ] && command -v ss >/dev/null 2>&1; then
  CONNS=""; REVSH=""; REVINT=""
  while read -r peer proc; do
    pid=$(echo "$proc" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
    [ -n "$pid" ] || continue
    remote="${peer%:*}"; remote=$(echo "$remote" | tr -d '[]')
    case "$remote" in 127.*|::1|::ffff:127.*|"") continue;; esac
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null); comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    [ -n "$exe" ] || continue
    CONNS="${CONNS}${exe}|${comm}|${remote}${NL}"
    case "$comm" in
      bash|sh|dash|zsh|ksh|ash|fish|nc|ncat|netcat) REVSH="${REVSH}${comm} (pid $pid) -> ${remote}${NL}";;
      python*|perl|ruby|node|php|lua|awk|gawk)     REVINT="${REVINT}${comm} (pid $pid) -> ${remote}${NL}";;
    esac
  done < <(ss -tnpH state established 2>/dev/null | awk '{print $4, $5}')
  if [ -n "$CONNS" ]; then
    lastexe=""; own=""
    printf '%s' "$CONNS" | sort -u | head -40 | while IFS='|' read -r exe comm remote; do
      if [ "$exe" != "$lastexe" ]; then own=$(pkg_owner "${exe% (deleted)}"); lastexe="$exe"; fi
      printf '    %-14s %-40s [%s] -> %s\n' "$comm" "$exe" "$own" "$remote"
    done
    info "[pkg] = owning package, [NONE] = not installed from a package (browsers, snap and manual installs are normal)"
  else
    info "  (no non-local established connections)"
  fi
  if [ -n "$REVSH" ]; then
    alert "Shell/netcat process holding a network connection (typical reverse shell):"
    printf '%s' "$REVSH" | sort -u | sed 's/^/    /'
  fi
  if [ -n "$REVINT" ]; then
    warn "Scripting interpreter holding a network connection (normal for many tools; verify):"
    printf '%s' "$REVINT" | sort -u | head -15 | sed 's/^/    /'
  fi
else
  info "Skipped: requires sudo (and ss)."
fi

# ---------- reverse shell: stdin/stdout on a socket ----------
echo "  ${BLD}Shells with stdin/stdout attached to a network socket${RST}"
if need_root; then
  FDSH=""; FDINT=""
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}; [ "$pid" = "$$" ] && continue
    comm=$(cat "$p/comm" 2>/dev/null) || continue
    case "$comm" in bash|sh|dash|zsh|ksh|ash|fish|nc|ncat|netcat|python*|perl|ruby|node|php|lua) ;; *) continue;; esac
    f0=$(readlink "$p/fd/0" 2>/dev/null); f1=$(readlink "$p/fd/1" 2>/dev/null)
    s0=0; s1=0
    case "$f0" in socket:*) s0=1;; esac
    case "$f1" in socket:*) s1=1;; esac
    [ $s0 -eq 0 ] && [ $s1 -eq 0 ] && continue
    cmdl=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-100)
    case "$comm" in
      python*|perl|ruby|node|php|lua) [ $s0 -eq 1 ] && [ $s1 -eq 1 ] && FDINT="${FDINT}${comm} (pid $pid): ${cmdl}${NL}";;
      *) FDSH="${FDSH}${comm} (pid $pid): ${cmdl}${NL}";;
    esac
  done
  if [ -n "$FDSH" ]; then
    alert "Shell/netcat whose stdin or stdout is a network socket (reverse/bind shell):"
    printf '%s' "$FDSH" | sed 's/^/    /'
  fi
  if [ -n "$FDINT" ]; then
    warn "Interpreter with stdin AND stdout on a network socket:"
    printf '%s' "$FDINT" | sed 's/^/    /'
  fi
  [ -z "$FDSH$FDINT" ] && ok "No shells wired to network sockets"
fi

# ---------- listeners reachable beyond localhost ----------
echo "  ${BLD}Listeners reachable beyond localhost (unusual owners only)${RST}"
if [ $IS_ROOT -eq 1 ] && command -v ss >/dev/null 2>&1; then
  LA=""; LC=""
  while read -r netid local proc; do
    addr="${local%:*}"
    case "$addr" in 127.*|"[::1]"|::1|"") continue;; esac
    pid=$(echo "$proc" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
    [ -n "$pid" ] || continue
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null); comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    item="${comm} (pid $pid) ${netid}/${local##*:} ${exe}"
    case "$exe" in
      /tmp/*|/var/tmp/*|/dev/shm/*|*/.*) LA="${LA}${item} [temp/hidden path]${NL}"; continue;;
    esac
    case "$comm" in
      bash|sh|dash|zsh|ksh|ash|fish|nc|ncat|netcat) LA="${LA}${item} [shell/netcat listener]${NL}"; continue;;
      python*|perl|ruby|node|php|lua|socat)         LC="${LC}${item} [interpreter/relay]${NL}"; continue;;
    esac
    case "$exe" in
      /usr/*|/bin/*|/sbin/*|/lib/*|/lib64/*|/snap/*|/opt/*|/nix/*|"") ;;
      *) LC="${LC}${item} [outside system paths]${NL}";;
    esac
  done < <(ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}')
  if [ -n "$LA" ]; then
    alert "Suspicious listener exposed to the network:"
    printf '%s' "$LA" | sort -u | sed 's/^/    /'
  fi
  if [ -n "$LC" ]; then
    warn "Listener exposed to the network from an unusual owner (dev servers are normal; verify):"
    printf '%s' "$LC" | sort -u | head -15 | sed 's/^/    /'
  fi
  [ -z "$LA$LC" ] && ok "No listeners from unusual owners exposed beyond localhost"
else
  info "Skipped: requires sudo (and ss)."
fi

# Promiscuous interfaces (sniffers)
PROMISC=$(ip -o link 2>/dev/null | grep -i PROMISC | awk -F': ' '{print $2}')
[ -n "$PROMISC" ] && warn "Interfaces in promiscuous mode (sniffing?): $PROMISC"

# Tunnel / VPN interfaces
TUNIF=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^(tun|tap|wg|ppp|vti|gre|gretap|ipip|sit|ip6tnl|zt|tailscale|nordlynx|proton|mullvad)[0-9a-z_-]*$')
if [ -n "$TUNIF" ]; then
  warn "Tunnel/VPN interfaces present — make sure you set them up: $(echo $TUNIF)"
  for i in $TUNIF; do
    ip -o addr show dev "$i" 2>/dev/null | awk '{print "    " $2, $3, $4}'
  done
  DEFR=$(ip route show default 2>/dev/null | head -3)
  [ -n "$DEFR" ] && info "Default route: $(echo "$DEFR" | tr '\n' ';')"
else ok "No tunnel/VPN interfaces"; fi

# Proxy settings
PROXY=$(env | grep -iE '^(http|https|all|ftp)_proxy=')
PROXYF=$(grep -hsiE '(http|https|all)_proxy|Acquire::http::Proxy' /etc/environment /etc/profile.d/* /etc/apt/apt.conf.d/* 2>/dev/null | grep -v '^#')
if [ -n "$PROXY$PROXYF" ]; then
  warn "System proxy configured — make sure it's yours (VPN/corporate)"
  printf '%s\n%s\n' "$PROXY" "$PROXYF" | grep -v '^$' | sed 's/^/    /'
else ok "No system proxy"; fi

if [ -L /etc/resolv.conf ] && command -v resolvectl >/dev/null 2>&1; then
  show "DNS servers" "resolvectl dns" 10
else
  show "DNS servers" "grep -E '^nameserver' /etc/resolv.conf" 10
fi

HOSTS=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE 'localhost|ip6-|^::1|^ff0|^127\.0\.1\.1|'"$HOSTNAME_S")
if [ -n "$HOSTS" ]; then
  warn "Non-default entries in /etc/hosts:"
  echo "$HOSTS" | sed 's/^/    /'
else ok "/etc/hosts is default"; fi

# ---------- time synchronization ----------
echo "  ${BLD}Time synchronization${RST}"
if [ $HAVE_SYSTEMD -eq 1 ] && command -v timedatectl >/dev/null 2>&1; then
  TD=$(timedatectl show 2>/dev/null)
  if [ -n "$TD" ]; then
    SYNC=$(echo "$TD" | awk -F= '$1=="NTPSynchronized"{print $2}')
    NTPON=$(echo "$TD" | awk -F= '$1=="NTP"{print $2}')
    if [ "$SYNC" = "yes" ]; then ok "Clock synchronized (NTP)"
    elif [ "$NTPON" = "no" ]; then warn "Network time sync is disabled — the clock can be moved to hide activity or break TLS/logs"
    else warn "Clock is not synchronized yet (NTPSynchronized=${SYNC:-?})"; fi
  fi
fi
NTPCFG=""
for f in /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf /etc/chrony/chrony.conf /etc/chrony.conf /etc/chrony/conf.d/*.conf /etc/chrony/sources.d/*.sources /etc/ntp.conf; do
  [ -f "$f" ] && NTPCFG="${NTPCFG}$(grep -hE '^[[:space:]]*(NTP|FallbackNTP)=|^[[:space:]]*(server|pool|peer)[[:space:]]' "$f" 2>/dev/null)${NL}"
done
NTPHOSTS=$(echo "$NTPCFG" | sed -e 's/^[^=]*=//' -e 's/^[[:space:]]*\(server\|pool\|peer\)[[:space:]]*//' | tr ' ' '\n' | grep -vE '^$|^(iburst|prefer|maxsources|minpoll|maxpoll|nts|xleave|offline|burst)' | sort -u)
ODDNTP=$(echo "$NTPHOSTS" | grep -vE 'pool\.ntp\.org|ntp\.ubuntu\.com|ntp\.org|nist\.gov|time\.(google|cloudflare|apple|windows)\.com|fedoraproject|amazonaws\.com|^169\.254\.|^$')
if [ -n "$ODDNTP" ]; then
  warn "Non-standard NTP servers configured (corporate/internal servers are normal; otherwise verify): $(echo $ODDNTP)"
elif [ -n "$NTPHOSTS" ]; then ok "NTP servers are standard"; fi
if [ $HAVE_SYSTEMD -eq 1 ] && command -v journalctl >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  STEPS=$(journalctl --no-pager -q --since "7 days ago" 2>/dev/null | grep -ciE 'time has been changed|clock.*(jumped|stepped)|system clock wrong|adjusting time.*step|time jumped')
  if [ "${STEPS:-0}" -gt 5 ]; then warn "System clock was stepped/changed $STEPS times in the last 7 days"
  elif [ "${STEPS:-0}" -gt 0 ]; then info "System clock stepped $STEPS time(s) in the last 7 days (normal after boot/resume)"; fi
fi

# ---------- system utilities: PATH hijacking and wrapper scripts ----------
echo "  ${BLD}System utilities (PATH hijacking / wrapper scripts)${RST}"
UTILS="ps ss netstat ls top htop lsof ip ifconfig find who w last lastb pgrep pkill kill ssh sshd sudo su login cat grep dmesg lsmod journalctl systemctl crontab"
HIJ_A=""; HIJ_W=""; WRAP=""
for u in $UTILS; do
  for d in /usr/local/sbin /usr/local/bin; do
    [ -f "$d/$u" ] && [ -x "$d/$u" ] && HIJ_A="${HIJ_A}${d}/${u} shadows the system ${u}${NL}"
  done
  for h in $ALL_HOMES; do
    for d in "$h/bin" "$h/.local/bin" "$h/.cargo/bin"; do
      [ -f "$d/$u" ] && [ -x "$d/$u" ] && HIJ_W="${HIJ_W}${d}/${u} shadows the system ${u} when that folder is first in PATH${NL}"
    done
  done
  p=$(PATH=/usr/bin:/bin:/usr/sbin:/sbin command -v "$u" 2>/dev/null)
  [ -n "$p" ] && [ "$(head -c 2 "$p" 2>/dev/null)" = "#!" ] && WRAP="${WRAP}${p}${NL}"
done
PATH_BAD=""
OLDIFS=$IFS; IFS=:
for d in $ORIG_PATH; do
  case "$d" in
    ""|.) PATH_BAD="${PATH_BAD}PATH contains an empty or '.' entry (current directory is searched first)${NL}"; continue;;
    /tmp*|/var/tmp*|/dev/shm*) PATH_BAD="${PATH_BAD}PATH contains a temp folder: $d${NL}"; continue;;
  esac
  [ -d "$d" ] && [ -n "$(find -L "$d" -maxdepth 0 -perm -0002 ! -perm -1000 2>/dev/null)" ] && PATH_BAD="${PATH_BAD}PATH folder is world-writable: $d${NL}"
done
IFS=$OLDIFS
if [ -n "$HIJ_A" ]; then alert "System utilities replaced via /usr/local:"; printf '%s' "$HIJ_A" | sed 's/^/    /'; fi
if [ -n "$WRAP" ]; then alert "System utilities that are scripts instead of binaries (wrapper that can hide output):"; printf '%s' "$WRAP" | sed 's/^/    /'; fi
if [ -n "$HIJ_W" ]; then warn "User-level copies of system tools (aliases/wrappers you wrote are fine):"; printf '%s' "$HIJ_W" | sed 's/^/    /'; fi
if [ -n "$PATH_BAD" ]; then warn "Unsafe PATH of this shell:"; printf '%s' "$PATH_BAD" | sed 's/^/    /'; fi
[ -z "$HIJ_A$WRAP$HIJ_W$PATH_BAD" ] && ok "System utilities resolve to the system binaries"

# ---------- unix sockets in temp folders, raw/packet sockets ----------
echo "  ${BLD}Unix sockets in temp folders and raw/packet sockets${RST}"
if [ $IS_ROOT -eq 1 ] && command -v ss >/dev/null 2>&1; then
  USOCK=$(ss -xlnpH 2>/dev/null | awk '$5 ~ /^\/(tmp|var\/tmp|dev\/shm|run\/shm)\// {print $5, $9}' \
          | grep -vE '^/(tmp|var/tmp|dev/shm)/(\.X11-unix|\.ICE-unix|\.font-unix|\.XIM-unix|tmux-|ssh-|systemd-private|snap\.|\.org\.chromium|dbus-|pulse-|\.s\.PGSQL)')
  if [ -n "$USOCK" ]; then
    warn "Unix sockets listening in temp folders (local C2/backdoor channels, or per-user app sockets):"
    echo "$USOCK" | cut -c1-180 | sed 's/^/    /'
  else ok "No unusual unix sockets in /tmp, /var/tmp, /dev/shm"; fi
  RAW_WL='^(dhclient|dhcpcd|NetworkManager|systemd-network|wpa_supplicant|chronyd|ntpd|lldpd|radvd|dhcpd|udhcpc|ping|ping6|keepalived|bird|bird6|zebra|ospfd|dnsmasq|avahi-daemon|tcpdump|dumpcap)$'
  RAW_ODD=""; RAW_TMP=""
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    pid=$(echo "$l" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2); [ -n "$pid" ] || continue
    pname=$(echo "$l" | sed -e 's/.*(("//' -e 's/".*//')
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    case "$exe" in /tmp/*|/var/tmp/*|/dev/shm/*|*/.*) RAW_TMP="${RAW_TMP}${pname} (pid $pid) ${exe}${NL}"; continue;; esac
    echo "$pname" | grep -qE "$RAW_WL" || RAW_ODD="${RAW_ODD}${pname} (pid $pid) ${exe}${NL}"
  done < <( { ss -wpaH 2>/dev/null; ss -0paH 2>/dev/null; } | grep 'users:' )
  if [ -n "$RAW_TMP" ]; then alert "Raw/packet socket held by a process from a temp/hidden path (sniffer or ICMP/raw backdoor):"; printf '%s' "$RAW_TMP" | sort -u | sed 's/^/    /'; fi
  if [ -n "$RAW_ODD" ]; then warn "Raw/packet sockets opened by uncommon processes (sniffers, ICMP tunnels; or monitoring tools):"; printf '%s' "$RAW_ODD" | sort -u | sed 's/^/    /'; fi
  [ -z "$RAW_TMP$RAW_ODD" ] && ok "No uncommon raw/packet sockets"
else
  info "Skipped: requires sudo (and ss)."
fi

# =====================================================================
section "4. Accounts & remote access"

# UID 0 accounts
UID0=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd)
if [ -n "$UID0" ]; then alert "Extra accounts with UID 0 (root rights): $UID0"
else ok "Only root has UID 0"; fi

# Empty passwords
if [ $IS_ROOT -eq 1 ]; then
  EMPTYPW=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null)
  if [ -n "$EMPTYPW" ]; then alert "Accounts with EMPTY password: $EMPTYPW"
  else ok "No accounts with empty password"; fi
else
  info "Empty-password check requires sudo."
fi

# Login-capable users
show "Users with a login shell" "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1, \"uid=\"\$3, \$7}' /etc/passwd" 30
for g in sudo wheel admin; do
  M=$(getent group "$g" 2>/dev/null | cut -d: -f4)
  [ -n "$M" ] && echo "  ${BLD}Group $g:${RST} $M"
done
command -v last >/dev/null 2>&1 && show "Recent logins" "last -n 20 -w 2>/dev/null || last -20" 20
show "Currently logged in" "w -h" 10

# Recently created/changed accounts
RECENT_ACC=$(find /etc/passwd /etc/shadow /etc/group /etc/sudoers -mtime -14 2>/dev/null)
[ -n "$RECENT_ACC" ] && warn "Account files modified in last 14 days: $(echo $RECENT_ACC)"

# ---------- SSH ----------
SSH_ON=0
if command -v ss >/dev/null 2>&1 && ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE '[:.]22$'; then
  SSH_ON=1; warn "SSH server is listening (port 22)"
elif [ $HAVE_SYSTEMD -eq 1 ] && systemctl is-active --quiet ssh sshd 2>/dev/null; then
  SSH_ON=1; warn "SSH service is active"
else ok "SSH not listening on port 22"; fi

PW=""; KBD=""; ROOTLOGIN=""
if [ $IS_ROOT -eq 1 ] && command -v sshd >/dev/null 2>&1; then
  EFF=$(sshd -T 2>/dev/null)
  PW=$(echo "$EFF"  | awk 'tolower($1)=="passwordauthentication"{print tolower($2); exit}')
  KBD=$(echo "$EFF" | awk 'tolower($1)=="kbdinteractiveauthentication"||tolower($1)=="challengeresponseauthentication"{print tolower($2); exit}')
  ROOTLOGIN=$(echo "$EFF" | awk 'tolower($1)=="permitrootlogin"{print tolower($2); exit}')
fi
if [ -z "$PW" ]; then
  # sshd_config.d is included first; first value wins; default is yes
  CFG=$(cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | grep -vE '^[[:space:]]*#')
  PW=$(echo "$CFG"  | awk 'tolower($1)=="passwordauthentication"{print tolower($2); exit}')
  KBD=$(echo "$CFG" | awk 'tolower($1)=="kbdinteractiveauthentication"||tolower($1)=="challengeresponseauthentication"{print tolower($2); exit}')
  ROOTLOGIN=$(echo "$CFG" | awk 'tolower($1)=="permitrootlogin"{print tolower($2); exit}')
fi
[ -z "$PW" ] && PW="yes"
[ -z "$KBD" ] && KBD="yes"
[ -z "$ROOTLOGIN" ] && ROOTLOGIN="prohibit-password"

if [ -e /etc/ssh/sshd_config ]; then
  if [ "$PW" = "yes" ] || [ "$KBD" = "yes" ]; then
    if [ $SSH_ON -eq 1 ]; then
      alert "SSH accepts PASSWORD login (PasswordAuthentication=$PW, KbdInteractiveAuthentication=$KBD) — brute-force risk, switch to key-only"
    else
      warn "sshd config allows password login (PasswordAuthentication=$PW, KbdInteractiveAuthentication=$KBD) — a risk if SSH is turned on"
    fi
  else
    ok "SSH password login disabled (key-only)"
  fi
  if [ "$ROOTLOGIN" = "yes" ]; then
    [ $SSH_ON -eq 1 ] && alert "SSH allows direct root login with password (PermitRootLogin yes)" \
                      || warn "sshd config: PermitRootLogin yes"
  fi
fi

# ---------- sshd directives that widen access ----------
if [ -e /etc/ssh/sshd_config ]; then
  SSHD_TXT="${EFF:-}"; [ -n "$SSHD_TXT" ] || SSHD_TXT="${CFG:-}"
  sshv() { echo "$SSHD_TXT" | awk -v k="$1" 'tolower($1)==k {sub(/^[^ \t]+[ \t]+/,""); print tolower($0); exit}'; }
  SSHD_HIT=0
  V=$(sshv authorizedkeyscommand)
  case "$V" in ""|none) ;; *) SSHD_HIT=1; warn "sshd AuthorizedKeysCommand is set ($V) — it supplies login keys dynamically; verify it is yours";; esac
  V=$(sshv forcecommand)
  case "$V" in ""|none|internal-sftp*) ;; *) SSHD_HIT=1; warn "sshd ForceCommand is set: $V";; esac
  V=$(sshv permitemptypasswords)
  if [ "$V" = "yes" ]; then
    SSHD_HIT=1
    if [ $SSH_ON -eq 1 ]; then alert "sshd PermitEmptyPasswords yes — accounts with empty passwords can log in"
    else warn "sshd config: PermitEmptyPasswords yes"; fi
  fi
  V=$(sshv gatewayports)
  case "$V" in yes|clientspecified) SSHD_HIT=1; warn "sshd GatewayPorts $V — remote forwards are exposed on all interfaces";; esac
  V=$(sshv permittunnel)
  case "$V" in yes|point-to-point|ethernet) SSHD_HIT=1; warn "sshd PermitTunnel $V — allows VPN-style tun devices over SSH";; esac
  V=$(sshv permituserenvironment)
  case "$V" in ""|no) ;; *) SSHD_HIT=1; warn "sshd PermitUserEnvironment $V — users can inject LD_PRELOAD and similar via ~/.ssh/environment";; esac
  for kw in ciphers macs kexalgorithms hostkeyalgorithms pubkeyacceptedalgorithms; do
    V=$(sshv $kw)
    [ -n "$V" ] || continue
    W=$(echo "$V" | tr ',' '\n' | grep -E '^(3des-cbc|arcfour|arcfour128|arcfour256|blowfish-cbc|cast128-cbc|rijndael-cbc@lysator.liu.se|aes128-cbc|aes192-cbc|aes256-cbc|hmac-md5.*|hmac-sha1-96.*|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|ssh-dss.*|ssh-rsa|ssh-rsa-cert-v01@openssh.com)$' | tr '\n' ' ')
    [ -n "$W" ] && SSHD_HIT=1 && warn "sshd $kw includes weak/legacy algorithms: $W"
  done
  [ $SSHD_HIT -eq 0 ] && ok "sshd: no AuthorizedKeysCommand/ForceCommand/tunnel/empty-password directives, no weak algorithms"
fi

# VNC / RDP / telnet
if command -v ss >/dev/null 2>&1; then
  for spec in "5900:VNC" "3389:RDP (xrdp)" "23:Telnet" "5901:VNC"; do
    port=${spec%%:*}; label=${spec#*:}
    ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$" && warn "$label is listening (port $port)"
  done
fi

# authorized_keys for all users
for h in $ALL_HOMES; do
  k="$h/.ssh/authorized_keys"
  if [ -s "$k" ]; then
    n=$(grep -cvE '^[[:space:]]*(#|$)' "$k")
    warn "$n SSH key(s) authorized for login in $k — verify they're yours"
    grep -vE '^[[:space:]]*(#|$)' "$k" | awk '{print "    " $1, substr($2,1,20) "...", $NF}'
  fi
  if [ -n "$(find "$k" -mtime -14 2>/dev/null)" ]; then
    warn "$k modified in last 14 days"
  fi
done

# ---------- permissions of critical files ----------
echo "  ${BLD}Permissions of critical files${RST}"
PERM_A=""; PERM_W=""
perm_audit() {
  local f="$1" kind="$2" m o g oct
  [ -e "$f" ] && [ ! -L "$f" ] || return 0
  read -r m o g < <(stat -c '%a %U %G' "$f" 2>/dev/null) || return 0
  oct=$((8#$m))
  if [ $((oct & 8#002)) -ne 0 ]; then PERM_A="${PERM_A}${f}: world-writable (mode $m)${NL}"; return 0; fi
  case "$kind" in
    shadow)
      [ "$o" != "root" ] && PERM_A="${PERM_A}${f}: owner is $o, expected root${NL}"
      [ $((oct & 8#007)) -ne 0 ] && PERM_A="${PERM_A}${f}: readable by everyone (mode $m) — password hashes exposed${NL}"
      [ $((oct & 8#020)) -ne 0 ] && PERM_A="${PERM_A}${f}: writable by group $g (mode $m)${NL}"
      [ $((oct & 8#040)) -ne 0 ] && [ "$g" != "shadow" ] && [ "$g" != "root" ] && PERM_A="${PERM_A}${f}: readable by group $g (mode $m)${NL}";;
    passwd)
      [ "$o" != "root" ] && PERM_A="${PERM_A}${f}: owner is $o, expected root${NL}"
      [ $((oct & 8#022)) -ne 0 ] && PERM_A="${PERM_A}${f}: writable by group/others (mode $m)${NL}";;
    sudoers)
      [ "$o" != "root" ] && PERM_A="${PERM_A}${f}: owner is $o, expected root${NL}"
      [ $((oct & 8#022)) -ne 0 ] && PERM_A="${PERM_A}${f}: writable by group/others (mode $m)${NL}"
      [ $((oct & 8#004)) -ne 0 ] && PERM_W="${PERM_W}${f}: readable by everyone (mode $m, expected 440)${NL}";;
    sshkey)
      [ "$o" != "root" ] && PERM_A="${PERM_A}${f}: owner is $o, expected root${NL}"
      [ $((oct & 8#007)) -ne 0 ] && PERM_A="${PERM_A}${f}: private host key readable by everyone (mode $m)${NL}"
      [ $((oct & 8#070)) -ne 0 ] && [ "$g" != "ssh_keys" ] && [ "$g" != "root" ] && PERM_A="${PERM_A}${f}: private host key accessible by group $g (mode $m)${NL}";;
    sshcfg)
      [ $((oct & 8#022)) -ne 0 ] && PERM_A="${PERM_A}${f}: writable by group/others (mode $m)${NL}";;
    authkeys)
      [ $((oct & 8#022)) -ne 0 ] && PERM_A="${PERM_A}${f}: writable by group/others (mode $m) — anyone can add a login key${NL}";;
  esac
  return 0
}
for f in /etc/shadow /etc/gshadow /etc/shadow- /etc/gshadow-; do perm_audit "$f" shadow; done
perm_audit /etc/passwd passwd; perm_audit /etc/group passwd
perm_audit /etc/sudoers sudoers
for f in /etc/sudoers.d/*; do perm_audit "$f" sudoers; done
perm_audit /etc/ssh/sshd_config sshcfg
for f in /etc/ssh/ssh_host_*_key; do perm_audit "$f" sshkey; done
for h in $ALL_HOMES; do
  perm_audit "$h/.ssh" sshcfg
  perm_audit "$h/.ssh/authorized_keys" authkeys
  perm_audit "$h/.ssh/authorized_keys2" authkeys
done
if [ -n "$PERM_A" ]; then alert "Critical files with unsafe permissions/ownership:"; printf '%s' "$PERM_A" | head -20 | sed 's/^/    /'; fi
if [ -n "$PERM_W" ]; then warn "Critical files with looser permissions than expected:"; printf '%s' "$PERM_W" | head -20 | sed 's/^/    /'; fi
[ -z "$PERM_A$PERM_W" ] && ok "shadow, passwd, sudoers, sshd_config, host keys and authorized_keys have expected permissions"

# ---------- sudoers ----------
echo "  ${BLD}sudoers${RST}"
if need_root; then
  if grep -Eqs '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*; then
    alert "sudoers contains a NOPASSWD rule (sudo without password)"
  fi
  SD=$(ls -A /etc/sudoers.d 2>/dev/null | grep -v README)
  [ -n "$SD" ] && warn "Extra sudo rules in /etc/sudoers.d: $SD"
  grep -hvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^Defaults' | sed 's/^/    /'
fi

# =====================================================================
section "5. Files, shell profiles, SUID"

SHELL_HIT=0
for h in $ALL_HOMES; do
  for f in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zshenv .zlogin .bash_logout; do
    fp="$h/$f"; [ -f "$fp" ] || continue
    HITS=$(grep -nE 'curl|wget|base64|nc |ncat|/tmp/|/dev/shm/|/dev/tcp/|python[0-9.]* -c|\| *(ba|z)?sh|alias (sudo|ssh|su)=' "$fp" 2>/dev/null)
    if [ -n "$HITS" ]; then
      SHELL_HIT=1
      warn "Suspicious lines in $fp (fine if you added them yourself)"
      echo "$HITS" | cut -c1-200 | sed 's/^/    /'
    fi
  done
done
for fp in /etc/profile /etc/bash.bashrc /etc/zsh/zshrc /etc/profile.d/*.sh; do
  [ -f "$fp" ] || continue
  HITS=$(grep -nE '(^|[^[:alnum:]_./-])(curl|wget)[[:space:]]|base64 -d|/dev/tcp/|nc -e|python[0-9.]* -c' "$fp" 2>/dev/null)
  if [ -n "$HITS" ]; then
    SHELL_HIT=1
    warn "Suspicious lines in $fp"
    echo "$HITS" | cut -c1-200 | sed 's/^/    /'
  fi
done
[ $SHELL_HIT -eq 0 ] && ok "Shell profiles look clean"

EXECS=$(find /tmp /var/tmp /dev/shm -type f -perm -u+x 2>/dev/null | head -50)
if [ -n "$EXECS" ]; then
  warn "Executable files in temp folders:"
  echo "$EXECS" | sed 's/^/    /'
else ok "No executables in /tmp, /var/tmp, /dev/shm"; fi

HIDDEN_TMP=$(find /tmp /var/tmp /dev/shm -name ".*" ! -name ".X*" ! -name ".ICE-unix" ! -name ".font-unix" ! -name ".Test-unix" ! -name ".XIM-unix" -maxdepth 2 2>/dev/null | head -30)
[ -n "$HIDDEN_TMP" ] && warn "Hidden files in temp folders: $(echo $HIDDEN_TMP)"

# SUID/SGID binaries outside packages
if need_root; then
  echo "  ${BLD}SUID/SGID files not owned by any package${RST}"
  SUIDS=$(find / -xdev \( -path /proc -o -path /sys -o -path /snap -o -path /var/lib/docker \) -prune -o \
          -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  ODD=""
  for f in $SUIDS; do
    case "$f" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*) ODD="${ODD}${f} (user/temp folder!)${NL}"; continue;; esac
    if [ "$(pkg_owner "$f")" = "NONE" ]; then ODD="${ODD}${f}${NL}"; fi
  done
  if [ -n "$ODD" ]; then
    alert "SUID/SGID files outside package management:"
    printf '%s' "$ODD" | head -20 | sed 's/^/    /'
  else ok "All SUID/SGID files belong to packages"; fi

  # Capabilities
  if command -v getcap >/dev/null 2>&1; then
    CAPS=$(getcap -r /usr /opt /home /tmp 2>/dev/null | grep -vE 'ping|gst-ptp-helper|newuidmap|newgidmap|mtr-packet|arping|clockdiff|traceroute')
    [ -n "$CAPS" ] && warn "Files with Linux capabilities (verify):" && echo "$CAPS" | head -15 | sed 's/^/    /'
  fi
fi

# World-writable files in system paths
WW=$(find /etc /usr/bin /usr/sbin /bin /sbin /usr/local -xdev -type f -perm -0002 2>/dev/null | head -20)
[ -n "$WW" ] && alert "World-writable files in system paths:" && echo "$WW" | sed 's/^/    /'

# ---------- package integrity ----------
# NOTE: checksums live on the same disk. This catches careless tampering (a replaced
# binary), not an attacker with root who also edits the package database.
SYSPATH='(^|[[:space:]:])/((usr/)?(s?bin|lib(64|exec|32)?)|boot)/'
echo "  ${BLD}Integrity of system binaries (package checksums)${RST}"
if need_root; then
  if command -v debsums >/dev/null 2>&1; then
    DS=$(debsums -c 2>&1)
    # changed files are printed as bare paths; anything else is a tool diagnostic (e.g. "dpkg-query: no path found ...")
    BAD=$(echo "$DS" | grep -E '^/' | grep -E "$SYSPATH" | head -20)
    DSERR=$(echo "$DS" | grep -E '^(debsums|dpkg-query):' | grep -v 'missing file' | head -5)
    GONE=$(echo "$DS" | grep -E '^debsums: missing file ' | sed -E 's/^debsums: missing file ([^ ]+).*/\1/' | grep -E "$SYSPATH" | head -20)
    NOSUM=$(debsums -l 2>/dev/null | grep -c .)
    if [ -n "$BAD" ]; then alert "Modified system files (debsums):"; echo "$BAD" | sed 's/^/    /'
    else ok "debsums: no modified system files"; fi
    [ -n "$DSERR" ] && info "debsums diagnostics (not treated as modifications):" && echo "$DSERR" | cut -c1-160 | sed 's/^/      /'
    [ -n "$GONE" ] && warn "System files listed by packages but missing on disk:" && echo "$GONE" | sed 's/^/    /'
    [ "$NOSUM" -gt 0 ] && info "$NOSUM package(s) ship no checksum list and were NOT verified (debsums -l)."
  elif command -v rpm >/dev/null 2>&1; then
    BAD=$(rpm -Va --nomtime 2>/dev/null | awk '$1 ~ /^..5/ && $2 != "c" {print}' | grep -E "$SYSPATH" | head -20)
    if [ -n "$BAD" ]; then alert "Modified system files (rpm -V):"; echo "$BAD" | sed 's/^/    /'
    else ok "rpm -V: no modified system files"; fi
  elif command -v pacman >/dev/null 2>&1; then
    BAD=$(pacman -Qkk 2>&1 | grep -E 'checksum mismatch' | grep -E "[: ]/(usr/)?(s?bin|lib)" | head -20)
    if [ -n "$BAD" ]; then alert "Modified system files (pacman -Qkk):"; echo "$BAD" | sed 's/^/    /'
    else ok "pacman -Qkk: no modified system files"; fi
  else
    info "No debsums/rpm/pacman — checksum check skipped (on Debian/Ubuntu: apt install debsums)."
  fi
  info "Checksums are stored on this system: an attacker with root can falsify them."

  # ---------- executables no package owns ----------
  echo "  ${BLD}Executables in system folders not owned by any package${RST}"
  norm() { sed -E 's#^/(s?bin|lib(64)?)/#/usr/\1/#' | sort -u; }
  OWNED=""
  if command -v dpkg >/dev/null 2>&1; then OWNED=$(cat /var/lib/dpkg/info/*.list 2>/dev/null | norm)
  elif command -v rpm >/dev/null 2>&1; then OWNED=$(rpm -qal 2>/dev/null | norm)
  elif command -v pacman >/dev/null 2>&1; then OWNED=$(pacman -Ql 2>/dev/null | cut -d' ' -f2 | norm)
  fi
  if [ -n "$OWNED" ]; then
    FOUND=$(find /usr/bin /usr/sbin /usr/libexec /usr/lib /usr/lib64 -xdev -type f -perm /111 2>/dev/null | norm)
    UNOWNED=$(comm -13 <(echo "$OWNED") <(echo "$FOUND"))
    # policy-rc.d is created by Debian container images and some installers to block service starts
    TOPU=$(echo "$UNOWNED" | grep -E '^/usr/s?bin/' | grep -v '^/usr/sbin/policy-rc.d$')
    RESTU=$(echo "$UNOWNED" | grep -vE '^/usr/s?bin/' | grep -v '^$')
    if [ -n "$TOPU" ]; then alert "Executables in /usr/bin or /usr/sbin that no package owns:"; echo "$TOPU" | head -20 | sed 's/^/    /'; fi
    if [ -n "$RESTU" ]; then warn "Executables in /usr/lib* or /usr/libexec that no package owns (may be generated by installers):"; echo "$RESTU" | head -20 | sed 's/^/    /'; fi
    [ -z "$TOPU$RESTU" ] && ok "All executables in system folders belong to packages"
  else
    info "No package database found — ownership check skipped."
  fi
fi

# ---------- hidden files in system folders ----------
echo "  ${BLD}Hidden files and folders in system locations (not owned by any package)${RST}"
if need_root; then
  if [ -n "${OWNED:-}" ]; then
    HIDE='! -name .build-id ! -name .pwd.lock ! -name .updated ! -name .java ! -name .keep ! -name .gitkeep ! -name .placeholder ! -name .empty'
    BINDIRS="/usr/bin /usr/sbin /usr/lib /usr/lib64 /usr/libexec /usr/local/bin /usr/local/sbin /usr/local/lib /boot"
    for d in /bin /sbin /lib /lib64; do [ -L "$d" ] || BINDIRS="$BINDIRS $d"; done
    HID_TOP=$(find $BINDIRS -xdev -maxdepth 1 -name '.*' $HIDE -print 2>/dev/null | norm | comm -13 <(echo "$OWNED") -)
    HID_REST=$(find /usr /etc /boot /var -xdev -maxdepth 3 \( -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/snapd -o -path /var/cache -o -path /var/log -o -path /var/tmp -o -path /usr/local/share/ca-certificates \) -prune \
               -o -name '.*' $HIDE -print 2>/dev/null | norm | comm -13 <(echo "$OWNED") - | grep -vxF -f <(echo "$HID_TOP") | grep -v '^$' | head -30)
    if [ -n "$HID_TOP" ]; then alert "Hidden entries in binary/library folders (classic way to hide a payload):"; echo "$HID_TOP" | head -20 | sed 's/^/    /'; fi
    if [ -n "$HID_REST" ]; then warn "Hidden entries elsewhere under /usr, /etc, /boot, /var that no package owns (services create some; verify unknown ones):"; echo "$HID_REST" | sed 's/^/    /'; fi
    [ -z "$HID_TOP$HID_REST" ] && ok "No unowned hidden files/folders in system locations"
  else
    info "No package database found — skipped."
  fi
fi

# Core tools replaced recently
RECENT_BIN=$(find /bin /sbin /usr/bin /usr/sbin -type f -mtime -3 2>/dev/null | head -20)
[ -n "$RECENT_BIN" ] && info "Binaries modified in last 3 days (normal after package updates): $(echo $RECENT_BIN | wc -w) file(s)"

# Containers
if command -v docker >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  show "Running Docker containers" "docker ps --format '{{.Names}}  {{.Image}}  {{.Ports}}'" 15
  CIDS=$(docker ps -q 2>/dev/null)
  if [ -n "$CIDS" ]; then
    CRISK=""
    INS=$(docker inspect --format '{{.Name}}|{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.CapAdd}}|{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' $CIDS 2>/dev/null)
    while IFS='|' read -r cname priv pidm netm caps mounts; do
      [ -n "$cname" ] || continue
      issues=""
      [ "$priv" = "true" ] && issues="${issues}privileged "
      [ "$pidm" = "host" ] && issues="${issues}host-PID "
      [ "$netm" = "host" ] && issues="${issues}host-network "
      case "$caps" in *SYS_ADMIN*|*ALL*|*SYS_PTRACE*|*SYS_MODULE*|*NET_ADMIN*|*DAC_READ_SEARCH*) issues="${issues}capabilities${caps} ";; esac
      for mt in $mounts; do
        src="${mt%%:*}"
        case "$src" in
          /var/run/docker.sock|/run/docker.sock|/var/run/containerd*|/run/containerd*) issues="${issues}docker-socket ";;
          /|/etc|/etc/*|/root|/root/*|/proc|/proc/*|/sys|/sys/*|/boot|/boot/*|/dev|/home|/var/lib/docker|/var/lib/kubelet|/usr|/lib|/bin|/sbin) issues="${issues}host-mount:${src} ";;
        esac
      done
      [ -n "$issues" ] && CRISK="${CRISK}${cname#/}: ${issues}${NL}"
    done <<< "$INS"
    if [ -n "$CRISK" ]; then
      warn "Containers with host-level access (each is a container-escape path; needed by some tools like Portainer, Traefik, CI runners):"
      printf '%s' "$CRISK" | sed 's/^/    /'
    else ok "No privileged containers, host namespaces, docker.sock or sensitive host mounts"; fi
  fi
fi

# ---------- container runtime exposure ----------
echo "  ${BLD}Container runtime exposure (Docker; see k8s_audit.sh for Kubernetes)${RST}"
CT_HIT=0
DSOCK=/var/run/docker.sock; [ -S "$DSOCK" ] || DSOCK=/run/docker.sock
if [ -S "$DSOCK" ]; then
  read -r dmode downer dgroup < <(stat -c '%a %U %G' "$DSOCK")
  doct=$((8#$dmode))
  if [ $((doct & 8#006)) -ne 0 ]; then
    CT_HIT=1; alert "Docker socket is accessible to everyone (mode $dmode) — any local user gets root through it"
  elif [ "$dgroup" != "root" ] && [ "$dgroup" != "docker" ]; then
    CT_HIT=1; warn "Docker socket group is '$dgroup' (mode $dmode)"
  fi
  DGM=$(getent group docker 2>/dev/null | cut -d: -f4)
  [ -n "$DGM" ] && CT_HIT=1 && warn "Members of group 'docker' have root-equivalent access: $DGM"
fi
DCONF=$(ls /etc/docker/daemon.json /etc/systemd/system/docker.service /etc/systemd/system/docker.service.d/*.conf /lib/systemd/system/docker.service /usr/lib/systemd/system/docker.service 2>/dev/null)
if [ -n "$DCONF" ] && grep -qE 'tcp://' $DCONF 2>/dev/null; then
  CT_HIT=1
  if grep -qE 'tlsverify' $DCONF 2>/dev/null; then warn "Docker daemon listens on TCP with TLS verification (verify client certs are managed)"
  else alert "Docker daemon is configured to listen on TCP without tlsverify — remote unauthenticated root"; fi
fi
if command -v ss >/dev/null 2>&1; then
  EXPS=$(ss -tlnpH 2>/dev/null | awk '{print $4, $6}' | grep -E '[:]((2375)|(2376))( |$)' | grep -vE '^(127\.|\[::1\]|::1)')
  if [ -n "$EXPS" ]; then
    CT_HIT=1
    echo "$EXPS" | grep -qE ':2375( |$)' && alert "Unauthenticated Docker API port 2375 is exposed" \
                                                  || warn "Docker TLS API port 2376 is exposed beyond localhost (verify client certificates):"
    echo "$EXPS" | cut -c1-150 | sed 's/^/    /'
  fi
fi
[ $CT_HIT -eq 0 ] && ok "No exposed Docker socket or API"


# Trusted CA certificates added manually
CUSTOM_CA=$(find /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors /etc/ca-certificates/trust-source/anchors -type f 2>/dev/null)
if [ -n "$CUSTOM_CA" ]; then
  warn "Manually added root certificates (allow HTTPS interception; OK only if corporate/debug):"
  echo "$CUSTOM_CA" | sed 's/^/    /'
else ok "No manually added root certificates"; fi

# ---------- trusted root certificates: system, Firefox, Java ----------
echo "  ${BLD}Trusted root certificates (system store, Firefox, Java)${RST}"
CA_HIT=0
if command -v openssl >/dev/null 2>&1 && [ -d /etc/ssl/certs ]; then
  CUTOFF=$(( $(date +%s) - 30*86400 ))
  NEWCA=""
  for c in /etc/ssl/certs/*.pem; do
    [ -f "$c" ] || continue
    sd=$(openssl x509 -noout -startdate -in "$c" 2>/dev/null | cut -d= -f2)
    [ -n "$sd" ] || continue
    se=$(date -d "$sd" +%s 2>/dev/null) || continue
    [ "$se" -ge "$CUTOFF" ] && NEWCA="${NEWCA}$(basename "$c") (valid from $sd)${NL}"
  done
  if [ -n "$NEWCA" ]; then
    CA_HIT=1; warn "System root certificates issued in the last 30 days (new public roots appear rarely; verify):"
    printf '%s' "$NEWCA" | head -10 | sed 's/^/    /'
  fi
fi
if [ -n "${OWNED:-}" ] && [ -d /usr/share/ca-certificates ]; then
  FOREIGN=$(find /usr/share/ca-certificates -type f 2>/dev/null | norm | comm -13 <(echo "$OWNED") -)
  if [ -n "$FOREIGN" ]; then
    CA_HIT=1; warn "Certificate files in /usr/share/ca-certificates that no package owns (planted trusted root?):"
    echo "$FOREIGN" | head -10 | sed 's/^/    /'
  fi
fi
FF_PROFILES=""
for h in $ALL_HOMES; do
  for prof in "$h"/.mozilla/firefox/*/ "$h"/snap/firefox/common/.mozilla/firefox/*/ "$h"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/; do
    [ -f "${prof}cert9.db" ] && FF_PROFILES="${FF_PROFILES}${prof%/}${NL}"
  done
done
if [ -n "$FF_PROFILES" ]; then
  if command -v certutil >/dev/null 2>&1; then
    while IFS= read -r prof; do
      [ -n "$prof" ] || continue
      L=$(certutil -L -d "sql:${prof}" 2>/dev/null | grep -E '[[:space:]][A-Za-z]*,[A-Za-z]*,[A-Za-z]*$' | cut -c1-90)
      if [ -n "$L" ]; then
        CA_HIT=1; warn "Firefox profile $prof has imported certificates (a user-added root allows HTTPS interception):"
        echo "$L" | head -10 | sed 's/^/    /'
      fi
    done <<< "$FF_PROFILES"
  else
    info "Firefox profiles found but certutil is not installed — imported certificates not inspected (apt install libnss3-tools)."
  fi
fi
FFPOL=$(grep -lsE '"(Install|ImportEnterpriseRoots|Certificates)"' /etc/firefox/policies/policies.json /usr/lib/firefox/distribution/policies.json /usr/lib/firefox-esr/distribution/policies.json /usr/lib64/firefox/distribution/policies.json /var/lib/snapd/hostfs/etc/firefox/policies/policies.json 2>/dev/null)
[ -n "$FFPOL" ] && CA_HIT=1 && warn "Firefox enterprise policy installs certificates / imports system roots: $(echo $FFPOL)"
JKS=$(ls /etc/ssl/certs/java/cacerts /usr/lib/jvm/*/lib/security/cacerts /usr/lib/jvm/*/jre/lib/security/cacerts "${JAVA_HOME:-/nonexistent}"/lib/security/cacerts 2>/dev/null | sort -u)
if [ -n "$JKS" ]; then
  if command -v keytool >/dev/null 2>&1; then
    for k in $JKS; do
      ALIASES=$(keytool -list -keystore "$k" -storepass changeit 2>/dev/null | grep -E ', (trustedCertEntry|PrivateKeyEntry),' | sed 's/, [A-Z][a-z][a-z] [0-9]*, [0-9]*, .*//')
      TOT=$(echo "$ALIASES" | grep -c .)
      [ "$TOT" -gt 0 ] || continue
      MARKED=$(echo "$ALIASES" | grep -cE '^debian:|\[jdk\]$')
      if [ $((MARKED * 2)) -ge "$TOT" ]; then
        CUSTOMJ=$(echo "$ALIASES" | grep -vE '^debian:|\[jdk\]$')
        if [ -n "$CUSTOMJ" ]; then
          CA_HIT=1; warn "Java trust store $k has entries that are not part of the stock set (imported by someone):"
          echo "$CUSTOMJ" | head -10 | sed 's/^/    /'
        fi
      else
        info "Java trust store $k: $TOT entries (alias scheme unknown, not compared)"
      fi
    done
  else
    info "Java trust stores found but keytool is not available — not inspected."
  fi
fi
[ $CA_HIT -eq 0 ] && ok "No suspicious additions to the system, Firefox or Java trust stores"

# Recently installed packages
if [ -f /var/log/dpkg.log ]; then
  show "Packages installed in last 14 days" "grep ' install ' /var/log/dpkg.log* 2>/dev/null | awk '{print \$1, \$4}' | sort -r | head -30" 30
elif command -v rpm >/dev/null 2>&1; then
  show "Packages installed in last 14 days" "rpm -qa --last | awk -v d=\$(date -d '14 days ago' +%s) '{print}' | head -20" 20
fi

# ---------- pending security updates (cached metadata only; nothing is refreshed) ----------
echo "  ${BLD}Pending security updates${RST} ${DIM}(from cached package metadata; nothing is refreshed)${RST}"
UPD_SEEN=0
if command -v apt >/dev/null 2>&1; then
  UPD_SEEN=1
  UPD=$(apt list --upgradable 2>/dev/null | grep -v '^Listing')
  NUP=$(echo "$UPD" | grep -c .)
  NSEC=$(echo "$UPD" | grep -cE '^[^ ]*/[^ ]*security')
  STAMP=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null || stat -c %Y /var/lib/apt/lists 2>/dev/null)
  if [ -n "$STAMP" ]; then
    AGE=$(( ($(date +%s) - STAMP) / 86400 ))
    [ "$AGE" -gt 7 ] && info "Package index is $AGE days old — results may be stale (apt update refreshes it)."
  fi
  if [ "$NSEC" -gt 0 ]; then
    warn "$NSEC pending security update(s) of $NUP upgradable packages (apt list --upgradable)"
    echo "$UPD" | grep -E '^[^ ]*/[^ ]*security' | cut -d/ -f1 | head -15 | tr '\n' ' ' | sed 's/^/    /'; echo
  else ok "No pending security updates in the apt cache ($NUP other upgradable)"; fi
fi
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  UPD_SEEN=1
  PM=dnf; command -v dnf >/dev/null 2>&1 || PM=yum
  NSEC=$($PM -q -C updateinfo list security 2>/dev/null | grep -c 'Sec\.')
  if [ "${NSEC:-0}" -gt 0 ]; then warn "$NSEC pending security advisory update(s) ($PM updateinfo list security, cached)"
  else ok "No pending security updates in the $PM cache (run '$PM makecache' to refresh)"; fi
fi
if command -v zypper >/dev/null 2>&1; then
  UPD_SEEN=1
  NSEC=$(zypper -q --no-refresh list-patches --category security 2>/dev/null | grep -c 'needed')
  if [ "${NSEC:-0}" -gt 0 ]; then warn "$NSEC pending security patch(es) (zypper list-patches, cached)"
  else ok "No pending security patches in the zypper cache"; fi
fi
if command -v pacman >/dev/null 2>&1; then
  UPD_SEEN=1
  NUP=$(pacman -Qu 2>/dev/null | wc -l)
  [ "$NUP" -gt 0 ] && warn "$NUP package(s) have newer versions in the synced database (pacman -Qu)" || ok "No pending pacman updates in the synced database"
fi
[ $UPD_SEEN -eq 0 ] && info "No supported package manager found for the update check."
[ -f /var/run/reboot-required ] && warn "Reboot required: $(tr '\n' ' ' < /var/run/reboot-required.pkgs 2>/dev/null)"
if command -v needrestart >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  NRB=$(needrestart -b -r l 2>/dev/null)
  [ "$(echo "$NRB" | awk -F': ' '/NEEDRESTART-KSTA/{print $2}')" = "3" ] && warn "needrestart: a newer kernel is installed than the one running — reboot"
  NRS=$(echo "$NRB" | awk -F': ' '/NEEDRESTART-SVC/{print $2}')
  [ -n "$NRS" ] && warn "needrestart: services still using outdated libraries: $(echo $NRS)"
fi
if command -v needs-restarting >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  needs-restarting -r >/dev/null 2>&1 || warn "needs-restarting: a reboot is required to apply updates"
fi

info "Reminder: review browser extensions manually in each browser."

# =====================================================================
section "6. User environment: SSH, secrets, git, package sources"

# ---------- SSH client configuration, hooks, recent changes ----------
echo "  ${BLD}SSH client configuration and login hooks${RST}"
SSHC_HIT=0
for f in /etc/ssh/ssh_config /etc/ssh/ssh_config.d/*.conf $(for h in $ALL_HOMES; do echo "$h/.ssh/config"; done); do
  [ -f "$f" ] || continue
  H=$(grep -inE '^[[:space:]]*(ProxyCommand|LocalCommand|KnownHostsCommand)|^[[:space:]]*PermitLocalCommand[[:space:]]+yes|^[[:space:]]*Match[[:space:]]+exec' "$f" 2>/dev/null | grep -v 'systemd-ssh-proxy')
  if [ -n "$H" ]; then
    SSHC_HIT=1
    warn "Command-executing directives in $f (ProxyCommand is common for jump hosts; verify):"
    echo "$H" | cut -c1-200 | sed 's/^/    /'
  fi
done
[ $SSHC_HIT -eq 0 ] && ok "No ProxyCommand/LocalCommand directives in ssh_config files"
[ -f /etc/ssh/sshrc ] && warn "/etc/ssh/sshrc exists — runs on every SSH login"
for h in $ALL_HOMES; do
  for f in "$h/.ssh/rc" "$h/.ssh/environment"; do
    [ -f "$f" ] && warn "$f exists — runs/applies on every SSH login (persistence vector)"
  done
  R=$(find "$h/.ssh" -maxdepth 2 -type f -mtime -14 ! -name 'known_hosts*' ! -name authorized_keys 2>/dev/null)
  [ -n "$R" ] && warn "Files in $h/.ssh changed in last 14 days: $(echo $R)"
  if [ -d "$h/.gnupg" ]; then
    R=$(find "$h/.gnupg" -maxdepth 1 -type f -name '*.conf' -mtime -14 2>/dev/null)
    [ -n "$R" ] && warn "GnuPG config changed in last 14 days: $(echo $R)"
    P=$(grep -hE '^[[:space:]]*pinentry-program' "$h/.gnupg/gpg-agent.conf" 2>/dev/null | grep -vE '/usr/(bin|lib)')
    [ -n "$P" ] && warn "gpg-agent pinentry-program points outside /usr ($h): $P"
  fi
  if [ -d "$h/.config" ]; then
    R=$(find "$h/.config" -maxdepth 4 -type f -perm -u+x -mtime -14 ! -name '*.so*' 2>/dev/null | head -15)
    [ -n "$R" ] && warn "Executable files in $h/.config changed in last 14 days (app updates can do this; verify):" && echo "$R" | sed 's/^/    /'
  fi
done

# ---------- credential files and permissions ----------
echo "  ${BLD}Credential files and permissions${RST} ${DIM}(contents are never read or printed)${RST}"
SECRETS=".aws/credentials .kube/config .docker/config.json .netrc .pgpass .git-credentials .npmrc .pypirc .config/gh/hosts.yml .azure/accessTokens.json .config/gcloud/application_default_credentials.json .s3cfg .vault-token .terraform.d/credentials.tfrc.json"
SEC_N=0; SEC_WIDE=""; KEY_OPEN=""; ENV_N=0
for h in $ALL_HOMES; do
  for rel in $SECRETS; do
    f="$h/$rel"; [ -f "$f" ] || continue
    SEC_N=$((SEC_N+1))
    m=$(stat -c '%a' "$f" 2>/dev/null)
    [ -n "$m" ] && [ "${m: -2}" != "00" ] && SEC_WIDE="${SEC_WIDE}${f} (mode $m)${NL}"
  done
  if [ -d "$h/.ssh" ]; then
    m=$(stat -c '%a' "$h/.ssh" 2>/dev/null)
    [ -n "$m" ] && [ "${m: -2}" != "00" ] && SEC_WIDE="${SEC_WIDE}${h}/.ssh directory (mode $m)${NL}"
    for k in "$h"/.ssh/id_*; do
      [ -f "$k" ] || continue
      case "$k" in *.pub) continue;; esac
      head -c 200 "$k" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
      SEC_N=$((SEC_N+1))
      m=$(stat -c '%a' "$k" 2>/dev/null)
      [ -n "$m" ] && [ "${m: -2}" != "00" ] && SEC_WIDE="${SEC_WIDE}${k} (mode $m)${NL}"
      if command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -y -P "" -f "$k" </dev/null >/dev/null 2>&1; then
        KEY_OPEN="${KEY_OPEN}${k}${NL}"
      fi
    done
  fi
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    ENV_N=$((ENV_N+1))
    m=$(stat -c '%a' "$f" 2>/dev/null)
    [ -n "$m" ] && [ "${m: -2}" != "00" ] && SEC_WIDE="${SEC_WIDE}${f} (mode $m)${NL}"
  done < <(find "$h" -maxdepth 4 \( -name node_modules -o -name .git -o -name .cache -o -name .npm -o -name .cargo -o -name .rustup -o -name snap \) -prune \
           -o -type f \( -name '.env' -o -name '.env.*' \) ! -name '*.example' ! -name '*.sample' ! -name '*.template' -print 2>/dev/null | head -100)
done
info "Credential files found: $SEC_N · .env files found: $ENV_N"
if [ -n "$SEC_WIDE" ]; then
  warn "Credential files readable by group/others (should be 600):"
  printf '%s' "$SEC_WIDE" | head -20 | sed 's/^/    /'
else ok "Credential files are private (no group/other access)"; fi
if [ -n "$KEY_OPEN" ]; then
  warn "SSH private keys without a passphrase (anyone who reads the file can use them):"
  printf '%s' "$KEY_OPEN" | sed 's/^/    /'
fi

# ---------- git hooks and configuration ----------
echo "  ${BLD}Git hooks and configuration${RST}"
GIT_KEYS='^[[:space:]]*(hookspath|sshcommand|fsmonitor|gitproxy|askpass)[[:space:]]*='
GIT_HIT=0; GIT_HOOKS=""; GIT_EVIL=""; NREPO=0
for gc in /etc/gitconfig $(for h in $ALL_HOMES; do echo "$h/.gitconfig $h/.config/git/config"; done); do
  [ -f "$gc" ] || continue
  H=$(grep -inE "$GIT_KEYS" "$gc" 2>/dev/null)
  [ -n "$H" ] && GIT_HIT=1 && warn "Command-executing git settings in $gc:" && echo "$H" | cut -c1-200 | sed 's/^/    /'
done
for h in $ALL_HOMES; do
  while IFS= read -r g; do
    [ -n "$g" ] || continue
    NREPO=$((NREPO+1))
    H=$(grep -inE "$GIT_KEYS" "$g/config" 2>/dev/null)
    [ -n "$H" ] && GIT_HIT=1 && warn "Command-executing git settings in $g/config:" && echo "$H" | cut -c1-200 | sed 's/^/    /'
    for hk in "$g"/hooks/*; do
      [ -f "$hk" ] && [ -x "$hk" ] || continue
      case "$hk" in *.sample) continue;; esac
      GIT_HOOKS="${GIT_HOOKS}${hk}${NL}"
      grep -qE 'curl|wget|base64|/dev/tcp/|nc -e|bash -i|eval ' "$hk" 2>/dev/null && GIT_EVIL="${GIT_EVIL}${hk}${NL}"
    done
  done < <(find "$h" -maxdepth 5 \( -name node_modules -o -name .cache -o -name .npm -o -name .cargo -o -name .rustup -o -name .local -o -name snap -o -name go \) -prune \
           -o -type d -name .git -print 2>/dev/null | head -300)
done
if [ -n "$GIT_EVIL" ]; then
  alert "Git hooks containing download/obfuscation/shell patterns:"
  printf '%s' "$GIT_EVIL" | sed 's/^/    /'
fi
if [ -n "$GIT_HOOKS" ]; then
  warn "Active git hooks in $NREPO repo(s) (pre-commit/husky/lfs install these; verify unknown ones):"
  printf '%s' "$GIT_HOOKS" | head -15 | sed 's/^/    /'
fi
[ $GIT_HIT -eq 0 ] && [ -z "$GIT_HOOKS" ] && ok "No suspicious git hooks/config in $NREPO repo(s)"

# ---------- package sources ----------
echo "  ${BLD}Package sources and signing keys${RST}"
SRC_BAD=0
APT_FILES=$(ls /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null)
if [ -n "$APT_FILES" ]; then
  INSEC=$(grep -liE 'trusted=yes|allow-insecure=yes|allow-downgrade-to-insecure=yes|^[[:space:]]*Trusted:[[:space:]]*yes' $APT_FILES 2>/dev/null)
  [ -n "$INSEC" ] && SRC_BAD=1 && alert "apt source with signature checks disabled: $(echo $INSEC)"
  if grep -rqiE '(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)[^;]*(true|yes|1)' /etc/apt/apt.conf /etc/apt/apt.conf.d 2>/dev/null; then
    SRC_BAD=1; alert "apt is configured to accept unauthenticated/insecure repositories"
  fi
  APT_OFFICIAL='debian\.org|ubuntu\.com|canonical\.com|kali\.org|linuxmint\.com|raspberrypi\.(com|org)|raspbian\.org|pop-os\.org'
  APT_URLS=$(grep -hv '^[[:space:]]*#' $APT_FILES 2>/dev/null | grep -oE '[a-z]+://[^/[:space:]]+' | sort -u)
  THIRD=$(echo "$APT_URLS" | grep -vE "$APT_OFFICIAL")
  PLAIN=$(echo "$THIRD" | grep '^http://')
  [ -n "$PLAIN" ] && SRC_BAD=1 && warn "Non-official apt repositories over plain HTTP: $(echo $PLAIN)"
  [ -n "$THIRD" ] && info "Third-party apt repositories: $(echo $THIRD | sed 's#[a-z]*://##g')"
  [ -s /etc/apt/trusted.gpg ] && SRC_BAD=1 && warn "/etc/apt/trusted.gpg is non-empty — legacy global trust for every repository"
  R=$(find /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/trusted.gpg.d /etc/apt/keyrings -type f -mtime -30 2>/dev/null)
  [ -n "$R" ] && SRC_BAD=1 && warn "apt sources/keys changed in last 30 days: $(echo $R)"
fi
REPOS=$(ls /etc/yum.repos.d/*.repo /etc/zypp/repos.d/*.repo 2>/dev/null)
if [ -n "$REPOS" ]; then
  NOGPG=$(grep -liE '^[[:space:]]*(gpgcheck|repo_gpgcheck)[[:space:]]*=[[:space:]]*0' $REPOS /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null)
  [ -n "$NOGPG" ] && SRC_BAD=1 && warn "Repositories with gpgcheck disabled (normal only for internal repos): $(echo $NOGPG)"
  NOSSL=$(grep -liE '^[[:space:]]*sslverify[[:space:]]*=[[:space:]]*(0|false)' $REPOS /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null)
  [ -n "$NOSSL" ] && SRC_BAD=1 && warn "Repositories with TLS verification disabled: $(echo $NOSSL)"
  RPM_OFFICIAL='fedoraproject|redhat\.com|centos|rockylinux|almalinux|oracle\.com|opensuse|suse\.com|amazonaws\.com'
  THIRD=$(grep -hE '^[[:space:]]*(baseurl|mirrorlist|metalink)' $REPOS 2>/dev/null | grep -oE '[a-z]+://[^/[:space:]]+' | sed 's#[a-z]*://##' | sort -u | grep -vE "$RPM_OFFICIAL")
  [ -n "$THIRD" ] && info "Third-party rpm repositories: $(echo $THIRD)"
  R=$(find /etc/yum.repos.d /etc/zypp/repos.d -type f -mtime -30 2>/dev/null)
  [ -n "$R" ] && SRC_BAD=1 && warn "Repository files changed in last 30 days: $(echo $R)"
fi
if [ -f /etc/pacman.conf ]; then
  grep -E '^[[:space:]]*(SigLevel|LocalFileSigLevel|RemoteFileSigLevel)' /etc/pacman.conf | grep -qi never && SRC_BAD=1 && alert "pacman SigLevel includes Never — package signatures are not checked"
  CUSTOM=$(grep -E '^\[' /etc/pacman.conf | grep -vE '^\[(options|core|extra|multilib|community|testing|.*-testing)\]')
  [ -n "$CUSTOM" ] && SRC_BAD=1 && warn "Custom pacman repositories: $(echo $CUSTOM)"
fi
[ $SRC_BAD -eq 0 ] && ok "System package sources look standard"

echo "  ${BLD}Language package indexes (pip / npm / yarn / cargo / gem)${RST}"
IDX_FILES="/etc/pip.conf /etc/xdg/pip/pip.conf /etc/npmrc /usr/etc/npmrc"
for h in $ALL_HOMES; do
  IDX_FILES="$IDX_FILES $h/.pip/pip.conf $h/.config/pip/pip.conf $h/.pypirc $h/.npmrc $h/.yarnrc $h/.yarnrc.yml $h/.cargo/config.toml $h/.cargo/config $h/.gemrc $h/.bundle/config $h/.config/uv/uv.toml"
done
IDX_OFFICIAL='pypi\.org|pythonhosted\.org|registry\.npmjs\.org|registry\.yarnpkg\.com|crates\.io|rubygems\.org|github\.com'
IDX_HIT=0
for f in $IDX_FILES; do
  [ -f "$f" ] || continue
  L=$(grep -iE 'index-url|extra-index|trusted-host|find-links|registry|repository|replace-with|^[[:space:]]*(source|mirror|proxy)' "$f" 2>/dev/null \
      | grep -viE 'token|_auth|password|secret' | sed 's#://[^/@ ]*@#://***@#' | grep -v '^[[:space:]]*#')
  [ -n "$L" ] || continue
  ODD=$(echo "$L" | grep -oE '[a-z]+://[^/[:space:]"]+' | grep -vE "$IDX_OFFICIAL")
  if echo "$L" | grep -qiE 'extra-index-url|trusted-host' || [ -n "$ODD" ]; then
    IDX_HIT=1
    warn "Custom package index/registry in $f (internal mirrors are normal; unknown ones allow dependency substitution):"
    echo "$L" | cut -c1-160 | sed 's/^/    /'
  fi
done
ENVIDX=$(grep -nE '^[[:space:]]*(export[[:space:]]+)?(PIP_(EXTRA_)?INDEX_URL|NPM_CONFIG_REGISTRY|UV_(EXTRA_)?INDEX_URL|CARGO_REGISTRIES_[A-Z_]+_INDEX)=' /etc/environment /etc/profile /etc/profile.d/* $(for h in $ALL_HOMES; do echo "$h/.profile $h/.bashrc $h/.bash_profile $h/.zshrc $h/.zprofile $h/.zshenv"; done) 2>/dev/null | sed 's#://[^/@ ]*@#://***@#')
[ -n "$ENVIDX" ] && IDX_HIT=1 && warn "Package index overridden via environment in shell files:" && echo "$ENVIDX" | cut -c1-180 | sed 's/^/    /'
[ $IDX_HIT -eq 0 ] && ok "No custom language package indexes"

# =====================================================================
section "7. Logs (last 7 days)"

LOGS_OK=1
if [ $HAVE_SYSTEMD -eq 1 ] && command -v journalctl >/dev/null 2>&1 && journalctl -n 1 >/dev/null 2>&1; then
  jlog() { journalctl --no-pager -q --since "7 days ago" "$@" 2>/dev/null; }
  SSH_OK=$(jlog -t sshd -t sshd-session | grep "Accepted")
  SUDO_LOG=$(jlog _COMM=sudo | grep "COMMAND=")
  FAILS=$(jlog -t sshd -t sshd-session -t sudo -t su | grep -ciE 'failed password|authentication failure|invalid user')
else
  LOGS=$(ls /var/log/auth.log* /var/log/secure* 2>/dev/null)
  if [ -n "$LOGS" ] && [ $IS_ROOT -eq 1 ]; then
    ALL=$(zcat -f $LOGS 2>/dev/null)
    SSH_OK=$(echo "$ALL" | grep "sshd.*Accepted")
    SUDO_LOG=$(echo "$ALL" | grep "COMMAND=")
    FAILS=$(echo "$ALL" | grep -ciE 'failed password|authentication failure|invalid user')
  else
    SSH_OK=""; SUDO_LOG=""; FAILS=0; LOGS_OK=0
    info "Cannot read journal/auth.log — run with sudo (or add user to systemd-journal/adm group)."
  fi
fi

if [ $LOGS_OK -eq 0 ]; then
  info "Log checks skipped."
elif [ -n "$SSH_OK" ]; then
  alert "Successful SSH logins in last 7 days: $(echo "$SSH_OK" | wc -l | tr -d ' ') (serious if not you)"
  echo "$SSH_OK" | tail -20 | cut -c1-200 | sed 's/^/    /'
else ok "No successful SSH logins"; fi

SUDO_N=$(printf '%s' "$SUDO_LOG" | grep -c "COMMAND=")
[ $LOGS_OK -eq 1 ] && echo "  ${BLD}sudo commands in last 7 days: $SUDO_N${RST} (verify all are yours)"
[ -n "$SUDO_LOG" ] && echo "$SUDO_LOG" | tail -20 | sed -E 's/^(.{15}|[0-9T:+-]{25}).*sudo\[?[0-9]*\]?: *([^ ]+) : .*COMMAND=(.*)/\1  \2  \3/' | cut -c1-200 | sed 's/^/    /'

if [ $LOGS_OK -eq 0 ]; then :
elif [ "${FAILS:-0}" -gt 20 ]; then warn "Many failed authentication attempts in last 7 days: $FAILS"
else ok "Failed authentication attempts: ${FAILS:-0}"; fi

if [ $IS_ROOT -eq 1 ] && command -v lastb >/dev/null 2>&1; then
  show "Top sources of failed logins (lastb)" "lastb -i 2>/dev/null | awk 'NF>2 {print \$(NF-5)}' | sort | uniq -c | sort -nr | head -5" 5
fi

# Shell history of root/users: suspicious one-liners
HHIT=""
for h in $ALL_HOMES; do
  for hf in .bash_history .zsh_history; do
    [ -r "$h/$hf" ] && HHIT="${HHIT}$(grep -nE 'curl[^|]*\| *(ba)?sh|wget[^|]*\| *(ba)?sh|/dev/tcp/|nc -e|base64 -d|chmod \+x /tmp|xmrig' "$h/$hf" 2>/dev/null | cut -c1-160 | sed "s|^|[$h/$hf] |")${NL}"
  done
done
HHIT=$(echo "$HHIT" | grep -v '^$')
[ -n "$HHIT" ] && warn "Suspicious commands in shell history (fine if you ran them):" && echo "$HHIT" | head -15 | sed 's/^/    /'

# ---------- logging health and tampering ----------
echo "  ${BLD}Logging health and tampering${RST}"
LOGBAD=0
UPS=$(cut -d. -f1 /proc/uptime 2>/dev/null); UPS=${UPS:-0}
IN_CT=0; { [ -f /.dockerenv ] || grep -qE 'docker|lxc|kubepods' /proc/1/cgroup 2>/dev/null; } && IN_CT=1
if [ $HAVE_SYSTEMD -eq 1 ]; then
  if ! systemctl is-active --quiet systemd-journald 2>/dev/null; then LOGBAD=1; alert "systemd-journald is not running — system logging is off"; fi
  for svc in rsyslog syslog-ng auditd; do
    if systemctl cat "$svc" >/dev/null 2>&1 && ! systemctl is-active --quiet "$svc" 2>/dev/null; then
      LOGBAD=1; warn "$svc is installed but not running"
    fi
  done
fi
if grep -rhiE '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none' /etc/systemd/journald.conf /etc/systemd/journald.conf.d 2>/dev/null | grep -q .; then
  LOGBAD=1; warn "journald is configured with Storage=none — logs are discarded"
fi
if command -v auditctl >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  AE=$(auditctl -s 2>/dev/null | awk '$1=="enabled"{print $2}')
  case "$AE" in
    0) LOGBAD=1; warn "auditd is installed but audit logging is disabled (enabled=0)";;
    1|2) ok "auditd enabled (enabled=$AE)";;
  esac
fi
ZERO=""
for f in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure /var/log/kern.log /var/log/audit/audit.log; do
  [ -e "$f" ] && [ ! -s "$f" ] && ZERO="${ZERO}${f}${NL}"
done
if [ $IN_CT -eq 0 ] && [ "$UPS" -gt 172800 ]; then
  [ -e /var/log/wtmp ] && [ ! -s /var/log/wtmp ] && [ ! -s /var/log/wtmp.1 ] && ZERO="${ZERO}/var/log/wtmp (no login history although up for $((UPS/86400)) days)${NL}"
  [ -e /var/log/lastlog ] && [ ! -s /var/log/lastlog ] && ZERO="${ZERO}/var/log/lastlog${NL}"
fi
if [ -n "$ZERO" ]; then
  LOGBAD=1; warn "Log files that are empty although they are normally busy (cleared?):"
  printf '%s' "$ZERO" | sed 's/^/    /'
fi
NULLLOG=$(find /var/log -maxdepth 2 -type l -lname /dev/null 2>/dev/null)
if [ -n "$NULLLOG" ]; then LOGBAD=1; alert "Log files redirected to /dev/null:"; echo "$NULLLOG" | sed 's/^/    /'; fi
NULLHIST=""
for h in $ALL_HOMES; do
  for hf in .bash_history .zsh_history .python_history .mysql_history .psql_history .lesshst; do
    [ -L "$h/$hf" ] && [ "$(readlink "$h/$hf")" = "/dev/null" ] && NULLHIST="${NULLHIST}$h/$hf${NL}"
  done
done
if [ -n "$NULLHIST" ]; then LOGBAD=1; warn "Shell/tool history redirected to /dev/null (done by privacy-minded users and by intruders):"; printf '%s' "$NULLHIST" | sed 's/^/    /'; fi
if [ $HAVE_SYSTEMD -eq 1 ] && command -v journalctl >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  LASTJ=$(journalctl -n 1 --no-pager -o short-unix -q 2>/dev/null | awk '{print int($1)}')
  if [ -n "$LASTJ" ] && [ "$LASTJ" -gt 0 ] 2>/dev/null; then
    JAGE=$(( ($(date +%s) - LASTJ) / 3600 ))
    if [ "$JAGE" -gt 24 ]; then LOGBAD=1; warn "The newest journal entry is $JAGE hours old — logging may have been stopped"; fi
  fi
fi
[ $LOGBAD -eq 0 ] && ok "Logging services are running and no cleared/redirected logs found"

# ---------- file-integrity monitoring ----------
echo "  ${BLD}File-integrity monitoring (AIDE / Tripwire)${RST}"
FIM=0
if command -v aide >/dev/null 2>&1 || command -v aide.wrapper >/dev/null 2>&1; then
  FIM=1
  ALOG=$(ls -t /var/log/aide/*.log /var/log/aide.log 2>/dev/null | head -1)
  if [ -n "$ALOG" ]; then
    AAGE=$(( ($(date +%s) - $(stat -c %Y "$ALOG")) / 86400 ))
    ASUM=$(grep -hE 'found differences|found NO differences|Added entries|Removed entries|Changed entries|Total number of entries' "$ALOG" 2>/dev/null | tail -6)
    if echo "$ASUM" | grep -q 'found differences'; then
      warn "AIDE: last report ($AAGE days ago) found differences:"; echo "$ASUM" | sed 's/^/    /'
    elif echo "$ASUM" | grep -q 'found NO differences'; then
      ok "AIDE: last report ($AAGE days ago) found no differences"
    else info "AIDE log $ALOG has no summary lines"; fi
    [ "$AAGE" -gt 8 ] && warn "The last AIDE report is $AAGE days old — periodic checks may not be running"
  else
    warn "AIDE is installed but no report was found in /var/log/aide — no integrity check has run"
  fi
fi
TWR=$(ls -t /var/lib/tripwire/report/*.twr 2>/dev/null | head -1)
if command -v tripwire >/dev/null 2>&1 || [ -n "$TWR" ]; then
  FIM=1
  if [ -n "$TWR" ]; then
    TAGE=$(( ($(date +%s) - $(stat -c %Y "$TWR")) / 86400 ))
    TV=""; command -v twprint >/dev/null 2>&1 && TV=$(twprint --print-report --twrfile "$TWR" 2>/dev/null | grep -E 'Total violations found' | head -1)
    info "Tripwire: newest report is $TAGE days old ${TV:+($TV)}"
    echo "$TV" | grep -qE ':[[:space:]]*[1-9]' && warn "Tripwire reports violations: $TV"
    [ "$TAGE" -gt 8 ] && warn "The last Tripwire report is $TAGE days old"
  else warn "Tripwire is installed but no report exists"; fi
fi
[ $FIM -eq 0 ] && info "No file-integrity tool (AIDE/Tripwire) installed — worth adding on systems that matter."

# ---------- kernel messages ----------
echo "  ${BLD}Kernel messages (dmesg)${RST}"
if need_root; then
  DM=$(dmesg 2>/dev/null)
  if [ -z "$DM" ]; then
    info "  dmesg is not readable here (restricted or containerized)."
  else
    DMHIT=0
    MODV=$(echo "$DM" | grep -iE 'module verification failed|taints kernel|signature and/or required key missing|Loading of unsigned module' | tail -5)
    if [ -n "$MODV" ]; then DMHIT=1; warn "Unsigned/out-of-tree kernel module loads (DKMS drivers such as NVIDIA/VirtualBox are normal):"; echo "$MODV" | cut -c1-170 | sed 's/^/    /'; fi
    DEN=$(echo "$DM" | grep -ciE 'apparmor="DENIED"|avc: +denied')
    if [ "$DEN" -gt 20 ]; then DMHIT=1; warn "$DEN AppArmor/SELinux denials in the kernel log (a blocked attack or a misconfigured profile; see audit log for details)"
    elif [ "$DEN" -gt 0 ]; then info "$DEN AppArmor/SELinux denial(s) in the kernel log"; fi
    THERM=$(echo "$DM" | grep -iE 'thermal|throttl|temperature above threshold' | tail -3)
    if [ -n "$THERM" ]; then DMHIT=1; warn "Thermal/throttling messages (sustained 100% CPU such as mining overheats machines):"; echo "$THERM" | cut -c1-170 | sed 's/^/    /'; fi
    SEGF=$(echo "$DM" | grep -ciE 'segfault at|general protection fault|traps: .*(trap|ip:)')
    if [ "$SEGF" -gt 10 ]; then DMHIT=1; warn "$SEGF crashes (segfault/protection fault) in the kernel log — repeated crashes can mean exploitation attempts"; fi
    OOM=$(echo "$DM" | grep -ciE 'out of memory|oom-kill')
    [ "$OOM" -gt 0 ] && info "$OOM out-of-memory event(s) in the kernel log"
    [ $DMHIT -eq 0 ] && ok "dmesg: no unsigned modules, denial storms, thermal or crash bursts"
  fi
fi


# =====================================================================
section "SUMMARY"
echo "  ${RED}$ALERTS alert(s)${RST}  ·  ${YEL}$WARNS item(s) to check${RST}"
echo
[ -n "$SUMMARY_ALERTS" ] && printf '%s' "$SUMMARY_ALERTS"
[ -n "$SUMMARY_WARNS" ]  && printf '%s' "$SUMMARY_WARNS"
[ $ALERTS -eq 0 ] && [ $WARNS -eq 0 ] && echo "  ${GRN}No obvious signs of compromise found.${RST}"
echo
info "CHECK does not mean infected: many legitimate apps install services, proxies and certificates."
info "A clean result is not a guarantee: advanced malware (rootkits) can hide from checks run on the same system."
