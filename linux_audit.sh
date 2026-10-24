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
    if grep -qiE 'curl|wget|base64 -d|/dev/tcp/|nc -e|bash -i|stratum\+|xmrig' "$u" 2>/dev/null; then
      alert "Unit $name contains suspicious commands (download/reverse shell/miner)"
    fi
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

# Promiscuous interfaces (sniffers)
PROMISC=$(ip -o link 2>/dev/null | grep -i PROMISC | awk -F': ' '{print $2}')
[ -n "$PROMISC" ] && warn "Interfaces in promiscuous mode (sniffing?): $PROMISC"

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
  HITS=$(grep -nE 'curl|wget|base64 -d|/dev/tcp/|nc -e|python[0-9.]* -c' "$fp" 2>/dev/null)
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
echo "  ${BLD}Integrity of system binaries${RST}"
if need_root; then
  if command -v debsums >/dev/null 2>&1; then
    BAD=$(debsums -c 2>/dev/null | grep -E '^/(usr/)?(s?bin|lib)/' | head -20)
    if [ -n "$BAD" ]; then alert "Modified system binaries (debsums):"; echo "$BAD" | sed 's/^/    /'
    else ok "debsums: system binaries unchanged"; fi
  elif command -v rpm >/dev/null 2>&1; then
    BAD=$(rpm -Va --nomtime 2>/dev/null | grep -E '^..5.*\s/(usr/)?(s?bin|lib)' | head -20)
    if [ -n "$BAD" ]; then alert "Modified system binaries (rpm -V):"; echo "$BAD" | sed 's/^/    /'
    else ok "rpm -V: system binaries unchanged"; fi
  elif command -v pacman >/dev/null 2>&1; then
    BAD=$(pacman -Qkq 2>/dev/null | grep -E '/(s?bin|lib)/.*(checksum|mismatch)' | head -20)
    if [ -n "$BAD" ]; then alert "Modified system binaries (pacman -Qk):"; echo "$BAD" | sed 's/^/    /'
    else ok "pacman -Qk: system binaries unchanged"; fi
  else
    info "No debsums/rpm/pacman — integrity check skipped (on Debian/Ubuntu: apt install debsums)."
  fi
fi

# Core tools replaced recently
RECENT_BIN=$(find /bin /sbin /usr/bin /usr/sbin -type f -mtime -3 2>/dev/null | head -20)
[ -n "$RECENT_BIN" ] && info "Binaries modified in last 3 days (normal after package updates): $(echo $RECENT_BIN | wc -w) file(s)"

# Containers
if command -v docker >/dev/null 2>&1 && [ $IS_ROOT -eq 1 ]; then
  show "Running Docker containers" "docker ps --format '{{.Names}}  {{.Image}}  {{.Ports}}'" 15
  PRIV=$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null | grep 'privileged=true')
  [ -n "$PRIV" ] && warn "Privileged containers running:" && echo "$PRIV" | sed 's/^/    /'
fi

# Trusted CA certificates added manually
CUSTOM_CA=$(find /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors /etc/ca-certificates/trust-source/anchors -type f 2>/dev/null)
if [ -n "$CUSTOM_CA" ]; then
  warn "Manually added root certificates (allow HTTPS interception; OK only if corporate/debug):"
  echo "$CUSTOM_CA" | sed 's/^/    /'
else ok "No manually added root certificates"; fi

# Recently installed packages
if [ -f /var/log/dpkg.log ]; then
  show "Packages installed in last 14 days" "grep ' install ' /var/log/dpkg.log* 2>/dev/null | awk '{print \$1, \$4}' | sort -r | head -30" 30
elif command -v rpm >/dev/null 2>&1; then
  show "Packages installed in last 14 days" "rpm -qa --last | awk -v d=\$(date -d '14 days ago' +%s) '{print}' | head -20" 20
fi

info "Reminder: review browser extensions manually in each browser."

# =====================================================================
section "6. Logs (last 7 days)"

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
