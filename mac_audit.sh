#!/bin/bash
# =====================================================================
#  mac_audit.sh — standalone macOS compromise audit (console output only)
#
#  READ-ONLY: nothing is deleted, changed, disabled or written to disk.
#
#  Usage:   sudo bash mac_audit.sh
#           (without sudo some checks are skipped)
#
#  For full coverage grant Terminal "Full Disk Access":
#  System Settings -> Privacy & Security -> Full Disk Access -> Terminal
# =====================================================================

set -u
export LC_ALL=C
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/libexec:$PATH

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
USER_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$USER_HOME" ] || USER_HOME="$HOME"

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

# show "title" "command" — run and print indented output (max N lines)
show() {
  local title="$1" cmd="$2" max="${3:-40}" out
  echo "  ${BLD}$title${RST}"
  out=$(bash -c "$cmd" 2>&1 | head -n "$max")
  if [ -n "$out" ]; then echo "$out" | sed 's/^/    /'; else info "  (empty)"; fi
}

need_root() {
  [ $IS_ROOT -eq 1 ] && return 0
  info "Skipped: requires sudo."
  return 1
}

# Signature: UNSIGNED / INVALID / MISSING / ad-hoc / developer authority
check_sig() {
  local f="$1" i a
  [ -n "$f" ] && [ -e "$f" ] || { echo "MISSING"; return; }
  i=$(codesign -dv --verbose=2 "$f" 2>&1)
  if echo "$i" | grep -q "not signed"; then echo "UNSIGNED"; return; fi
  if ! codesign --verify "$f" >/dev/null 2>&1; then echo "INVALID"; return; fi
  a=$(echo "$i" | grep -m1 "^Authority=" | sed 's/^Authority=//')
  [ -n "$a" ] && echo "$a" || echo "ad-hoc"
}

# Executable launched by a launchd .plist
plist_prog() {
  local p="$1" prog
  prog=$(PlistBuddy -c "Print :Program" "$p" 2>/dev/null)
  [ -z "$prog" ] && prog=$(PlistBuddy -c "Print :ProgramArguments:0" "$p" 2>/dev/null)
  echo "$prog"
}

echo "${BLD}macOS Security Audit${RST}"
echo "Host: $(scutil --get ComputerName 2>/dev/null)  |  macOS $(sw_vers -productVersion)  |  $(date '+%Y-%m-%d %H:%M')"
echo "User: $REAL_USER  |  Mode: $([ $IS_ROOT -eq 1 ] && echo 'full (sudo)' || echo 'limited (no sudo)')"
[ $IS_ROOT -eq 0 ] && echo "${YEL}Running without sudo — some checks will be skipped.${RST}"

# =====================================================================
section "1. Built-in protection"

if csrutil status 2>&1 | grep -q "status: enabled"; then ok "SIP enabled"
else alert "SIP (System Integrity Protection) is disabled"; fi

AR=$(csrutil authenticated-root status 2>&1)
if echo "$AR" | grep -qi "status: enabled"; then ok "Sealed system volume (authenticated root) enabled"
elif echo "$AR" | grep -qi "status: disabled"; then alert "Sealed system volume protection is disabled — system files are no longer cryptographically verified"
fi

if spctl --status 2>&1 | grep -q "assessments enabled"; then ok "Gatekeeper enabled"
else alert "Gatekeeper is disabled — any app can run"; fi

if fdesetup status 2>&1 | grep -q "is On"; then ok "FileVault enabled"
else warn "FileVault (disk encryption) is off"; fi

if socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled" || \
   /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled"; then
  ok "Application firewall enabled"
else warn "Application firewall is off (macOS default, but recommended on)"; fi

# =====================================================================
section "2. Persistence: LaunchAgents / LaunchDaemons"

for dir in "$USER_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
  [ -d "$dir" ] || continue
  echo "  ${BLD}$dir${RST}"
  found=0
  for p in "$dir"/*.plist; do
    [ -e "$p" ] || continue
    found=1
    name=$(basename "$p")
    prog=$(plist_prog "$p")
    if [ -z "$prog" ]; then
      printf '    %-50s %s\n' "$name" "(cannot read)"
      continue
    fi
    sig=$(check_sig "$prog")
    printf '    %-50s %s\n' "$name" "${DIM}[$sig]${RST}"
    printf '      -> %s\n' "$prog"

    case "$sig" in
      UNSIGNED) alert "Unsigned launch item: $prog ($name)";;
      INVALID)  alert "Invalid signature on launch item: $prog ($name)";;
      MISSING)  warn  "Launch item points to missing file: $prog ($name)";;
      ad-hoc)   warn  "Ad-hoc signed launch item (normal for Homebrew, otherwise suspicious): $prog ($name)";;
    esac
    case "$prog" in
      /tmp/*|/private/tmp/*|/private/var/tmp/*|/Users/Shared/*)
        alert "Launch item runs from temp/shared folder: $prog ($name)";;
      */.*)
        warn "Launch item runs from hidden folder: $prog ($name)";;
    esac
    case "$(basename "$prog")" in
      bash|sh|zsh|python*|perl|ruby|osascript|curl|node)
        args=$(PlistBuddy -c "Print :ProgramArguments" "$p" 2>/dev/null | tr '\n' ' ' | tr -s ' ' | head -c 300)
        warn "Launch item $name runs an interpreter/script: $args";;
    esac
  done
  [ $found -eq 0 ] && info "  (empty)"
done

RECENT=$(find "$USER_HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons -name "*.plist" -mtime -14 2>/dev/null)
[ -n "$RECENT" ] && warn "Launch items created/modified in last 14 days: $(echo $RECENT)"

# =====================================================================
section "3. Other persistence mechanisms"

if [ $IS_ROOT -eq 1 ]; then
  CRON=$(crontab -l -u "$REAL_USER" 2>/dev/null; crontab -l 2>/dev/null)
else
  CRON=$(crontab -l 2>/dev/null)
fi
CRON=$(echo "$CRON" | grep -vE '^[[:space:]]*(#|$)')
if [ -n "$CRON" ]; then
  warn "Cron jobs found — make sure you created them"
  echo "$CRON" | sed 's/^/    /'
else ok "No cron jobs"; fi

echo "  ${BLD}Configuration profiles${RST}"
if need_root; then
  PROF=$(profiles list 2>&1)
  if echo "$PROF" | grep -qi "no configuration profiles"; then ok "No configuration profiles"
  else
    warn "Configuration profiles installed — suspicious unless this is a work/managed Mac"
    echo "$PROF" | head -30 | sed 's/^/    /'
  fi
fi

echo "  ${BLD}Login items / background tasks (third-party)${RST}"
if need_root; then
  BTM=$(sfltool dumpbtm 2>/dev/null | grep -E '^\s*(Name|Developer Name|URL|Executable Path):' \
        | grep -v -i 'com.apple' | sed 's/^[[:space:]]*/    /' | head -80)
  if [ -n "$BTM" ]; then echo "$BTM"; else info "  (none or unavailable)"; fi
fi

KEXT=$(kextstat 2>/dev/null | tail -n +2 | grep -v com.apple)
if [ -n "$KEXT" ]; then
  warn "Third-party kernel extensions loaded"
  echo "$KEXT" | sed 's/^/    /'
else ok "No third-party kernel extensions"; fi

show "System extensions" "systemextensionsctl list" 30

# =====================================================================
section "4. Processes & network"

UNSIGNED_PROCS=""
while IFS= read -r exe; do
  case "$exe" in /System/*|/usr/bin/*|/usr/sbin/*|/usr/libexec/*|/bin/*|/sbin/*|/Library/Apple/*|"") continue;; esac
  [ -f "$exe" ] || continue
  case "$(check_sig "$exe")" in
    UNSIGNED|INVALID) UNSIGNED_PROCS="${UNSIGNED_PROCS}${exe}${NL}";;
  esac
done < <(ps -axo comm= | sort -u)
if [ -n "$UNSIGNED_PROCS" ]; then
  alert "Unsigned processes running:"
  printf '%s' "$UNSIGNED_PROCS" | sed 's/^/    /'
else ok "No unsigned running processes"; fi

# ---------- crypto-miner detection ----------
echo "  ${BLD}Crypto-miner detection${RST}"
MINER_NAMES='xmrig|xmr-stak|minerd|cpuminer|ccminer|cgminer|bfgminer|ethminer|nbminer|t-rex|phoenixminer|lolminer|gminer|nanominer|srbminer|teamredminer|kdevtmpfsi|kinsing|minergate|nicehash'
MINER_ARGS='stratum\+(tcp|ssl|tls)://|--donate-level|--cpu-priority|randomx|cryptonight|minexmr|supportxmr|nanopool|moneroocean|hashvault|c3pool|2miners|f2pool|herominers|unmineable'
MINER_PORTS='3333|4444|5555|6666|7777|14433|14444|45560|45700'
MINER_FOUND=0

# 1) running processes by name or command-line arguments
MINERS=$(ps -axww -o pid=,user=,%cpu=,command= | grep -iE "$MINER_NAMES|$MINER_ARGS" | grep -v grep)
if [ -n "$MINERS" ]; then
  MINER_FOUND=1
  alert "Possible crypto-miner process running:"
  echo "$MINERS" | cut -c1-220 | sed 's/^/    /'
fi

# 2) connections to typical mining-pool ports
MCONN=$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk 'NR>1 {print $1, $2, $9}' | grep -E ":($MINER_PORTS)\$")
if [ -n "$MCONN" ]; then
  MINER_FOUND=1
  warn "Connections to ports typical for mining pools ($MINER_PORTS):"
  echo "$MCONN" | sed 's/^/    /'
fi

# 3) miner binaries/configs on disk
MFILES=$(find /private/tmp /private/var/tmp /Users/Shared "$USER_HOME/Library" "/Library/Application Support" \
         "$USER_HOME/.local" "$USER_HOME/.config" "$USER_HOME/.cache" /usr/local/bin /opt -maxdepth 4 \
         \( -iname '*xmrig*' -o -iname '*minerd*' -o -iname '*cpuminer*' -o -iname '*xmr-stak*' -o -iname '*kdevtmpfsi*' \) 2>/dev/null | head -20)
if [ -n "$MFILES" ]; then
  MINER_FOUND=1
  alert "Miner-like files found on disk:"
  echo "$MFILES" | sed 's/^/    /'
fi

# 4) miners in launch items / cron
MLAUNCH=$(grep -liE "$MINER_NAMES|stratum\+" "$USER_HOME"/Library/LaunchAgents/*.plist /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist 2>/dev/null)
if [ -n "$MLAUNCH" ]; then
  MINER_FOUND=1
  alert "Launch items referencing a miner: $(echo $MLAUNCH)"
fi
if echo "${CRON:-}" | grep -qiE "$MINER_NAMES|stratum\+"; then
  MINER_FOUND=1
  alert "Cron job referencing a miner"
fi

[ $MINER_FOUND -eq 0 ] && ok "No crypto-miner indicators"

# 5) sustained high CPU (miners keep CPU near 100%)
HICPU=$(ps -axo pid=,%cpu=,user=,comm= | awk '$2>=80 && $4!~/(^|\/)(ps|awk|sort|head)$/' | sort -k2 -nr | head -10)
if [ -n "$HICPU" ]; then
  warn "Processes using >=80% CPU right now (re-check later; miners keep CPU high constantly):"
  echo "$HICPU" | sed 's/^/    /'
fi

show "Listening TCP ports" "lsof -nP -iTCP -sTCP:LISTEN | awk 'NR==1 || !seen[\$1\$9]++'" 40
show "Established connections" "lsof -nP -iTCP -sTCP:ESTABLISHED | awk '{print \$1, \$2, \$3, \$9}' | column -t" 50

if scutil --proxy | grep -Eq '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable) : 1'; then
  warn "System proxy configured — make sure it's yours (VPN/corporate)"
  scutil --proxy | sed 's/^/    /'
else ok "No system proxy"; fi

show "DNS servers" "scutil --dns | grep nameserver | sort -u" 10

HOSTS=$(grep -vE '^[[:space:]]*(#|$)' /etc/hosts | grep -vE 'localhost|broadcasthost')
if [ -n "$HOSTS" ]; then
  warn "Non-default entries in /etc/hosts:"
  echo "$HOSTS" | sed 's/^/    /'
else ok "/etc/hosts is default"; fi

# =====================================================================
section "5. Accounts & remote access"

show "Local users" "dscl . list /Users | grep -v '^_'"
echo "  ${BLD}Admins:${RST}$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2)"
show "Recent logins" "last -20" 20

SSH_ON=0
if nc -z -G 1 127.0.0.1 22 >/dev/null 2>&1; then SSH_ON=1; warn "Remote Login (SSH) is enabled (port 22)"
else ok "SSH disabled"; fi

# ---------- SSH password authentication ----------
PW=""; KBD=""
if [ $IS_ROOT -eq 1 ]; then
  EFF=$(sshd -T 2>/dev/null)   # effective sshd configuration
  PW=$(echo "$EFF"  | awk 'tolower($1)=="passwordauthentication"{print tolower($2); exit}')
  KBD=$(echo "$EFF" | awk 'tolower($1)=="kbdinteractiveauthentication"||tolower($1)=="challengeresponseauthentication"{print tolower($2); exit}')
fi
if [ -z "$PW" ]; then
  # fallback: parse config files (sshd_config.d is included first; first value wins; default is yes)
  CFG=$(cat /etc/ssh/sshd_config.d/* /etc/ssh/sshd_config 2>/dev/null | grep -vE '^[[:space:]]*#')
  PW=$(echo "$CFG"  | awk 'tolower($1)=="passwordauthentication"{print tolower($2); exit}')
  KBD=$(echo "$CFG" | awk 'tolower($1)=="kbdinteractiveauthentication"||tolower($1)=="challengeresponseauthentication"{print tolower($2); exit}')
fi
[ -z "$PW" ] && PW="yes"
[ -z "$KBD" ] && KBD="yes"

if [ "$PW" = "yes" ] || [ "$KBD" = "yes" ]; then
  if [ $SSH_ON -eq 1 ]; then
    alert "SSH accepts PASSWORD login (PasswordAuthentication=$PW, KbdInteractiveAuthentication=$KBD) — brute-force risk, switch to key-only"
  else
    warn "sshd config allows password login (PasswordAuthentication=$PW, KbdInteractiveAuthentication=$KBD) — becomes a risk if Remote Login is turned on"
  fi
else
  ok "SSH password login disabled (key-only)"
fi
if nc -z -G 1 127.0.0.1 5900 >/dev/null 2>&1; then warn "Screen Sharing / Remote Management is enabled (port 5900)"
else ok "Screen Sharing / Remote Management disabled"; fi

for k in "$USER_HOME/.ssh/authorized_keys" /var/root/.ssh/authorized_keys; do
  if [ -s "$k" ]; then
    n=$(grep -cvE '^[[:space:]]*(#|$)' "$k")
    warn "$n SSH key(s) authorized for login in $k — verify they're yours"
    grep -vE '^[[:space:]]*(#|$)' "$k" | awk '{print "    " $1, substr($2,1,20) "...", $3}'
  fi
done

echo "  ${BLD}sudoers${RST}"
if need_root; then
  if grep -Eqs '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*; then
    alert "sudoers contains a NOPASSWD rule (sudo without password)"
  fi
  SD=$(ls -A /etc/sudoers.d 2>/dev/null)
  [ -n "$SD" ] && warn "Extra sudo rules in /etc/sudoers.d: $SD"
  grep -hvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^Defaults' | sed 's/^/    /'
fi

echo "  ${BLD}App permissions (TCC): screen, accessibility, input, full disk, mic, camera${RST}"
Q="SELECT service, client FROM access WHERE auth_value=2 AND service IN ('kTCCServiceScreenCapture','kTCCServiceAccessibility','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceSystemPolicyAllFiles','kTCCServiceMicrophone','kTCCServiceCamera') ORDER BY service;"
for db in "/Library/Application Support/com.apple.TCC/TCC.db" "$USER_HOME/Library/Application Support/com.apple.TCC/TCC.db"; do
  if res=$(sqlite3 -readonly -separator '  ' "$db" "$Q" 2>/dev/null); then
    info "  $db"
    if [ -n "$res" ]; then echo "$res" | sed 's/kTCCService//; s/^/    /'; else info "    (none)"; fi
  else
    info "  No access to $db — grant Terminal Full Disk Access or review in System Settings."
  fi
done

# =====================================================================
section "6. User profile, files, certificates"

SHELL_HIT=0
for f in .zshrc .zprofile .zshenv .zlogin .bashrc .bash_profile .profile; do
  fp="$USER_HOME/$f"; [ -f "$fp" ] || continue
  HITS=$(grep -nE 'curl|wget|base64|osascript|nc |/tmp/|python[0-9.]* -c|\| *(ba|z)?sh' "$fp" 2>/dev/null)
  if [ -n "$HITS" ]; then
    SHELL_HIT=1
    warn "Suspicious lines in ~/$f (fine if you added them yourself)"
    echo "$HITS" | cut -c1-200 | sed 's/^/    /'
  fi
done
[ $SHELL_HIT -eq 0 ] && ok "Shell profiles look clean"

EXECS=$(find /private/tmp /private/var/tmp /Users/Shared -type f -perm -u+x 2>/dev/null | head -50)
if [ -n "$EXECS" ]; then
  warn "Executable files in temp/shared folders:"
  echo "$EXECS" | sed 's/^/    /'
else ok "No executables in /tmp, /var/tmp, /Users/Shared"; fi

HIDDEN=$(find /Users/Shared -name ".*" ! -name ".localized" ! -name ".DS_Store" 2>/dev/null | head -50)
[ -n "$HIDDEN" ] && warn "Hidden files in /Users/Shared: $(echo $HIDDEN)"

show "Apps installed/modified in last 14 days" \
  "find /Applications '$USER_HOME/Applications' -maxdepth 1 -name '*.app' -mtime -14 2>/dev/null" 30

# ---------- signature integrity of installed software ----------
# Apple's own files are covered by the sealed system volume; this covers third-party apps/binaries.
# Like package checksums on Linux, this catches modification after install, not a re-signed binary.
echo "  ${BLD}Signature integrity of installed apps and Homebrew binaries${RST}"
info "Verifying signatures (can take a minute)..."
BROKEN=""; UNSIGNED_APPS=""; NSIGNED=0
for app in /Applications/*.app "$USER_HOME"/Applications/*.app; do
  [ -d "$app" ] || continue
  r=$(codesign --verify --deep --strict "$app" 2>&1)
  if [ $? -eq 0 ]; then NSIGNED=$((NSIGNED+1))
  elif echo "$r" | grep -q "not signed"; then UNSIGNED_APPS="${UNSIGNED_APPS}${app}${NL}"
  else BROKEN="${BROKEN}${app}: $(echo "$r" | head -1 | cut -c1-120)${NL}"; fi
done
for f in /opt/homebrew/bin/* /usr/local/bin/*; do
  [ -f "$f" ] || continue
  file -bL "$f" 2>/dev/null | grep -q "Mach-O" || continue
  r=$(codesign --verify "$f" 2>&1)
  if [ $? -eq 0 ]; then NSIGNED=$((NSIGNED+1))
  elif echo "$r" | grep -q "not signed"; then UNSIGNED_APPS="${UNSIGNED_APPS}${f}${NL}"
  else BROKEN="${BROKEN}${f}: $(echo "$r" | head -1 | cut -c1-120)${NL}"; fi
done
if [ -n "$BROKEN" ]; then
  alert "Apps/binaries whose signature no longer verifies (modified after install?):"
  printf '%s' "$BROKEN" | head -20 | sed 's/^/    /'
else ok "$NSIGNED signed app(s)/binary(ies) verified, none modified"; fi
if [ -n "$UNSIGNED_APPS" ]; then
  warn "Unsigned apps/binaries installed (normal for some open-source tools):"
  printf '%s' "$UNSIGNED_APPS" | head -20 | sed 's/^/    /'
fi

TRUST_ADMIN=$(security dump-trust-settings -d 2>&1 | grep '^Cert ')
if [ $IS_ROOT -eq 1 ]; then TRUST_USER=$(sudo -u "$REAL_USER" security dump-trust-settings 2>&1 | grep '^Cert ')
else TRUST_USER=$(security dump-trust-settings 2>&1 | grep '^Cert '); fi
if [ -n "$TRUST_ADMIN$TRUST_USER" ]; then
  warn "Manually trusted root certificates (allow HTTPS interception; OK only if corporate/debug):"
  printf '%s\n%s\n' "$TRUST_ADMIN" "$TRUST_USER" | grep -v '^$' | sed 's/^/    /'
else ok "No manually trusted root certificates"; fi

info "Reminder: review browser extensions manually in each browser."

# =====================================================================
section "7. Logs (last 7 days)"
info "Reading unified logs, this may take a few minutes..."

SSH_OK=$(log show --last 7d --style syslog --predicate 'process == "sshd" AND eventMessage CONTAINS "Accepted"' 2>/dev/null | grep "Accepted")
if [ -n "$SSH_OK" ]; then
  alert "Successful SSH logins in last 7 days: $(echo "$SSH_OK" | wc -l | tr -d ' ') (serious if not you)"
  echo "$SSH_OK" | tail -20 | cut -c1-200 | sed 's/^/    /'
else ok "No successful SSH logins"; fi

SUDO_LOG=$(log show --last 7d --style syslog --predicate 'process == "sudo"' 2>/dev/null | grep "COMMAND=")
SUDO_N=$(printf '%s' "$SUDO_LOG" | grep -c "COMMAND=")
echo "  ${BLD}sudo commands in last 7 days: $SUDO_N${RST} (verify all are yours)"
[ -n "$SUDO_LOG" ] && echo "$SUDO_LOG" | tail -20 | sed -E 's/^([0-9-]+ [0-9:]+).*: ([^ ]+) : .*COMMAND=(.*)/\1  \2  \3/' | cut -c1-200 | sed 's/^/    /'

FAILS=$(log show --last 7d --style syslog --predicate 'eventMessage CONTAINS[c] "authentication failed" OR eventMessage CONTAINS "Failed password"' 2>/dev/null \
        | grep -ciE 'authentication failed|failed password')
if [ "$FAILS" -gt 20 ]; then warn "Many failed authentication attempts in last 7 days: $FAILS"
else ok "Failed authentication attempts: $FAILS"; fi

# =====================================================================
section "SUMMARY"
echo "  ${RED}$ALERTS alert(s)${RST}  ·  ${YEL}$WARNS item(s) to check${RST}"
echo
[ -n "$SUMMARY_ALERTS" ] && printf '%s' "$SUMMARY_ALERTS"
[ -n "$SUMMARY_WARNS" ]  && printf '%s' "$SUMMARY_WARNS"
[ $ALERTS -eq 0 ] && [ $WARNS -eq 0 ] && echo "  ${GRN}No obvious signs of compromise found.${RST}"
echo
info "CHECK does not mean infected: many legitimate apps install agents, proxies and certificates."
info "A clean result is not a guarantee: advanced malware can hide from checks run on the same system."
