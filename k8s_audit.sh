#!/bin/bash
# =====================================================================
#  k8s_audit.sh — standalone Kubernetes exposure audit (console output only)
#
#  READ-ONLY: nothing is deleted, changed, applied or written to disk.
#
#  Two parts, each runs only where it can:
#    1. Node components  — run ON a Kubernetes node (control-plane or worker):
#                          exposed kubelet/etcd ports, static pod manifests.
#    2. Cluster workloads — run ANYWHERE kubectl is configured:
#                          privileged pods, host namespaces, sensitive hostPath mounts.
#
#  Usage:   sudo bash k8s_audit.sh [kube-context]
#           (sudo is only needed for part 1; part 2 uses the invoking user's
#            ~/.kube/config, or $KUBECONFIG, and prints which cluster it queries)
# =====================================================================

set -u
export LC_ALL=C
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:/opt/homebrew/bin:$PATH

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
[ -n "$USER_HOME" ] || USER_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$USER_HOME" ] || USER_HOME="$HOME"
KCONTEXT="${1:-}"

ALERTS=0; WARNS=0; RAN=0   # RAN: set once any check actually ran (never report "clean" otherwise)
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

# run a command with a hard time limit when timeout/gtimeout exists
with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$secs" "$@"
  else "$@"; fi
}

# Host paths that give a pod (and anyone who escapes it) control of the node
SENSITIVE_PATHS='/|/etc|/root|/proc|/sys|/home|/var/run/docker.sock|/run/docker.sock|/var/run/containerd/containerd.sock|/run/containerd/containerd.sock'

echo "${BLD}Kubernetes Security Audit${RST}"
echo "Host: $(hostname 2>/dev/null)  |  $(uname -sr)  |  $(date '+%Y-%m-%d %H:%M')"
echo "User: $REAL_USER  |  Mode: $([ $IS_ROOT -eq 1 ] && echo 'full (sudo)' || echo 'limited (no sudo)')"
[ $IS_ROOT -eq 0 ] && echo "${YEL}Running without sudo — node manifests may be unreadable and are skipped.${RST}"

# =====================================================================
section "1. Node components (run on a Kubernetes node)"

NODE=0
[ -d /etc/kubernetes ] && NODE=1
ps -eo comm= 2>/dev/null | grep -qE '^(kubelet|kube-apiserver|k3s|k3s-server|k0s|microk8s|rke2)$' && NODE=1
if [ $NODE -eq 0 ]; then
  info "No /etc/kubernetes and no kubelet/k3s/rke2 process — this machine is not a Kubernetes node; node checks skipped."
else
  NODE_HIT=0; RAN=1

  echo "  ${BLD}API ports exposed beyond localhost${RST}"
  if command -v ss >/dev/null 2>&1; then
    # 10250 kubelet API, 10255 kubelet read-only, 2379/2380 etcd client/peer
    EXPS=$(ss -tlnpH 2>/dev/null | awk '{print $4, $6}' | grep -E '[:]((10250)|(10255)|(2379)|(2380))( |$)' | grep -vE '^(127\.|\[::1\]|::1)')
    if [ -n "$EXPS" ]; then
      NODE_HIT=1
      if echo "$EXPS" | grep -qE ':10255( |$)'; then
        alert "Kubelet read-only port 10255 is exposed — unauthenticated pod/node information"
      fi
      if echo "$EXPS" | grep -qE ':(10250|2379|2380)( |$)'; then
        warn "Kubelet API (10250) or etcd (2379/2380) listens beyond localhost — must be firewalled and require client certificates:"
      fi
      echo "$EXPS" | cut -c1-150 | sed 's/^/    /'
    else ok "Kubelet/etcd ports are not exposed beyond localhost"; fi
  else
    info "ss not available — port check skipped."
  fi

  echo "  ${BLD}Static pod manifests (/etc/kubernetes/manifests)${RST}"
  MFS=0
  for mf in /etc/kubernetes/manifests/*.yaml /etc/kubernetes/manifests/*.yml; do
    [ -f "$mf" ] || continue
    if [ ! -r "$mf" ]; then info "  $mf is not readable (run with sudo)"; continue; fi
    MFS=$((MFS+1))
    KP=$(grep -nE '^[[:space:]-]*(privileged|hostPID|hostIPC):[[:space:]]*true' "$mf" 2>/dev/null)
    KH=$(awk '/hostPath:/ {hp=1; next} hp && /path:/ {print $NF; hp=0}' "$mf" | grep -xE "$SENSITIVE_PATHS")
    if [ -n "$KP$KH" ]; then
      NODE_HIT=1
      warn "Static pod manifest $mf grants host-level access:"
      [ -n "$KP" ] && echo "$KP" | sed 's/^/    /'
      [ -n "$KH" ] && echo "$KH" | sed 's/^/    hostPath: /'
    fi
  done
  RECENT=$(find /etc/kubernetes/manifests -type f -mtime -14 2>/dev/null)
  [ -n "$RECENT" ] && NODE_HIT=1 && warn "Static pod manifests changed in the last 14 days (a changed manifest restarts a control-plane component): $(echo $RECENT)"
  if [ $MFS -eq 0 ]; then info "  No readable static pod manifests (worker node, or run with sudo)."
  elif [ $NODE_HIT -eq 0 ]; then ok "$MFS static pod manifest(s) request no privileged mode, host PID/IPC or sensitive hostPath"; fi
fi

# =====================================================================
section "2. Cluster workloads (kubectl)"

if ! command -v kubectl >/dev/null 2>&1; then
  info "kubectl is not installed — cluster checks skipped."
else
  KCFG="${KUBECONFIG:-}"; [ -f "$USER_HOME/.kube/config" ] && KCFG="$USER_HOME/.kube/config"
  KC="kubectl"; [ -n "$KCONTEXT" ] && KC="kubectl --context=$KCONTEXT"
  CTX=$(KUBECONFIG="$KCFG" $KC config current-context 2>/dev/null)
  if [ -z "$CTX" ]; then
    info "No kubectl context configured for $REAL_USER (looked in ${KCFG:-\$KUBECONFIG, ~/.kube/config}) — cluster checks skipped."
  else
    SERVER=$(KUBECONFIG="$KCFG" $KC config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null)
    echo "  Querying context ${BLD}$CTX${RST} (${SERVER:-unknown server}) — read-only GET of pods"
    KPODS=$(KUBECONFIG="$KCFG" with_timeout 20 $KC --request-timeout=15s get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"|"}{.spec.containers[*].securityContext.privileged}{"|"}{.spec.hostPID}{"|"}{.spec.volumes[*].hostPath.path}{"\n"}{end}' 2>&1)
    RC=$?
    if [ $RC -ne 0 ] || echo "$KPODS" | grep -qiE '^(error|unable|the connection|forbidden|Unauthorized)'; then
      info "  Cluster not reachable or access denied — workload checks skipped:"
      echo "$KPODS" | head -2 | cut -c1-160 | sed 's/^/    /'
    else
      RAN=1
      NPODS=$(echo "$KPODS" | grep -c .)
      KRISK=""; KSYS=0
      while IFS='|' read -r pn pv ph phost; do
        [ -n "$pn" ] || continue
        pissue=""
        case "$pv" in *true*) pissue="${pissue}privileged ";; esac
        [ "$ph" = "true" ] && pissue="${pissue}hostPID "
        for hp in $phost; do
          case "$hp" in /|/etc|/etc/*|/root|/proc|/sys|/home|/var/run/docker.sock|/run/docker.sock|/var/run/containerd/*|/run/containerd/*) pissue="${pissue}hostPath:${hp} ";; esac
        done
        [ -n "$pissue" ] || continue
        case "$pn" in kube-system/*) KSYS=$((KSYS+1));; *) KRISK="${KRISK}${pn}: ${pissue}${NL}";; esac
      done <<< "$KPODS"
      if [ -n "$KRISK" ]; then
        warn "Pods with host-level access outside kube-system (each is a node-escape path):"
        printf '%s' "$KRISK" | head -20 | sed 's/^/    /'
      else ok "No privileged pods, hostPID or sensitive hostPath mounts outside kube-system ($NPODS pods checked)"; fi
      [ $KSYS -gt 0 ] && info "$KSYS kube-system pod(s) are privileged/use host paths (CNI, kube-proxy and node agents normally do)"
    fi
  fi
fi

# =====================================================================
section "SUMMARY"
echo "  ${RED}$ALERTS alert(s)${RST}  ·  ${YEL}$WARNS item(s) to check${RST}"
echo
[ -n "$SUMMARY_ALERTS" ] && printf '%s' "$SUMMARY_ALERTS"
[ -n "$SUMMARY_WARNS" ]  && printf '%s' "$SUMMARY_WARNS"
if [ $RAN -eq 0 ]; then echo "  ${YEL}Nothing was checked: this is not a Kubernetes node and no cluster was reachable via kubectl.${RST}"
elif [ $ALERTS -eq 0 ] && [ $WARNS -eq 0 ]; then echo "  ${GRN}No obvious exposure found by these checks.${RST}"; fi
echo
info "CHECK does not mean compromised: CNI plugins, monitoring agents and CSI drivers legitimately need host access."
info "Scope is narrow: no RBAC, secrets, NetworkPolicy, initContainers, capabilities, hostNetwork or kubelet config checks."
