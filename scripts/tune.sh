#!/usr/bin/env bash
# tune.sh — OS-level tuning for Tsunami.
#
# Applies the host settings the tracker can't set itself:
#   * sysctl network buffers/backlog/NAPI budget (deploy/99-tsunami.sysctl.conf
#     values, or whatever is installed at /etc/sysctl.d/99-tsunami.conf)
#   * CPU governor -> performance
#   * Transparent Huge Pages -> madvise (override with THP= in tune.conf)
#   * Optional extras from /etc/tsunami/tune.conf (see below)
#
# Usage:
#   tune.sh                 apply tuning now (reads /etc/tsunami/tune.conf)
#   tune.sh --check         report current vs target, change nothing
#   tune.sh --set K=V       record an option in tune.conf AND apply now
#   tune.sh --persist       install+enable tsunami-tuning.service (re-run at boot)
#   tune.sh --unpersist     disable/remove that unit
#   tune.sh --boot          quiet apply for the boot unit (reads tune.conf only)
#
# tune.conf options (all optional):
#   GOVERNOR=performance|powersave|schedutil|...   default: performance
#   THP=madvise|always|never                       default: madvise
#   HUGEPAGES=<count>      reserve <count> 2MiB hugepages (peer-store TLB relief;
#                         only useful once the app uses them — see DEPLOYMENT.md)
#   BUSY_POLL=<usec>       net.core.busy_poll/busy_read (NAPI busy-poll; burns a
#                         core, can cut latency under sustained load)
#   RPS_IFACE=<iface>      enable Receive Packet Steering on <iface> (helps
#                         single-queue virtio NICs spread RX across cores)
#
# Requires root. NIC channel/IRQ changes are NOT automated — they reset the
# interface; the script prints the commands for you to run deliberately.

set -euo pipefail

CONF=/etc/tsunami/tune.conf
SYSCTL_DROPIN=/etc/sysctl.d/99-tsunami.conf
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
SCRIPT_DIR="$(cd "$(dirname "$SELF")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd 2>/dev/null || echo "$SCRIPT_DIR")"
DROPIN_SRC="$REPO_ROOT/deploy/99-tsunami.sysctl.conf"
# install.sh exports TSUNAMI_LIBEXECDIR when using a non-default --prefix.
LIBEXECDIR="${TSUNAMI_LIBEXECDIR:-/usr/local/libexec}"
UNIT_NAME=tsunami-tuning.service
APPLY=1 CHECK=0 PERSIST=0 UNPERSIST=0 BOOT=0
declare -a SETS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --check)     CHECK=1; APPLY=0 ;;
    --persist)   PERSIST=1 ;;
    --unpersist) UNPERSIST=1 ;;
    --boot)      BOOT=1; APPLY=1 ;;
    --set)       shift; SETS+=("$1") ;;
    -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || { echo "tune.sh must run as root" >&2; exit 1; }

# --- tune.conf handling ----------------------------------------------------
load_conf() {
  GOVERNOR=performance; THP=madvise; HUGEPAGES=""; BUSY_POLL=""; RPS_IFACE=""
  if [ -f "$CONF" ]; then . "$CONF"; fi
  return 0
}

if [ "${#SETS[@]}" -gt 0 ]; then
  mkdir -p "$(dirname "$CONF")"
  touch "$CONF"
  for kv in "${SETS[@]}"; do
    k="${kv%%=*}"; v="${kv#*=}"
    case "$k" in
      GOVERNOR|THP|HUGEPAGES|BUSY_POLL|RPS_IFACE) ;;
      *) echo "unknown tune.conf key: $k" >&2; exit 2 ;;
    esac
    if grep -q "^${k}=" "$CONF"; then
      sed -i "s|^${k}=.*|${k}=${v}|" "$CONF"
    else
      echo "${k}=${v}" >> "$CONF"
    fi
    echo "tune.conf: ${k}=${v}"
  done
fi

load_conf

# --- helpers ----------------------------------------------------------------
gov_available() { ls /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor >/dev/null 2>&1; }
cur_gov()        { cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "n/a"; }
thp_path=/sys/kernel/mm/transparent_hugepage/enabled
cur_thp()        { cat "$thp_path" 2>/dev/null | grep -o '\[[a-z]*\]' | tr -d '[]' || echo "n/a"; }

say()  { [ "$BOOT" = 1 ] || echo "$@"; }
ok()   { [ "$BOOT" = 1 ] || echo "  [ok] $@"; }
skip() { [ "$BOOT" = 1 ] || echo "  [--] $@"; }

sysctl_set() { # key value
  if [ "$CHECK" = 1 ]; then
    cur="$(sysctl -n "$1" 2>/dev/null || echo '?')"
    [ "$cur" = "$2" ] && ok "$1 already $cur" || echo "  [..] $1: $cur -> $2"
  else
    sysctl -qw "$1=$2" && ok "$1=$2"
  fi
}

# --- 1. sysctl network tuning ----------------------------------------------
say "== sysctl =="
if [ -f "$SYSCTL_DROPIN" ]; then
  if [ "$CHECK" = 1 ]; then
    while read -r line; do
      case "$line" in ''|\#*) continue;; esac
      k="${line%%=*}"; v="${line#*= }"
      cur="$(sysctl -n "$k" 2>/dev/null || echo '?')"
      [ "$cur" = "$v" ] && ok "$k already $cur" || echo "  [..] $k: $cur -> $v"
    done < "$SYSCTL_DROPIN"
  else
    sysctl -q -p "$SYSCTL_DROPIN" && ok "applied $SYSCTL_DROPIN"
  fi
elif [ -f "$DROPIN_SRC" ]; then
  say "  (no $SYSCTL_DROPIN yet — applying built-in preset; install.sh would persist it)"
  for kv in \
    "net.core.rmem_max=268435456" "net.core.wmem_max=268435456" \
    "net.core.netdev_max_backlog=250000" \
    "net.core.netdev_budget=1200" "net.core.netdev_budget_usecs=16000" \
    "net.core.somaxconn=65535" "net.ipv4.udp_rmem_min=16384" \
    "vm.swappiness=10"; do
    sysctl_set "${kv%%=*}" "${kv#*=}"
  done
else
  skip "no sysctl preset found ($SYSCTL_DROPIN / $DROPIN_SRC)"
fi

# --- 2. CPU governor ---------------------------------------------------------
say "== CPU governor ($GOVERNOR) =="
if gov_available; then
  if [ "$CHECK" = 1 ]; then
    cur="$(cur_gov)"
    [ "$cur" = "$GOVERNOR" ] && ok "already $cur" || echo "  [..] scaling_governor: $cur -> $GOVERNOR"
  else
    n=0
    for g in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
      [ -w "$g" ] && echo "$GOVERNOR" > "$g" && n=$((n+1))
    done
    ok "set $n CPUs to $GOVERNOR"
  fi
else
  skip "no cpufreq interface (VM/bare metal without scaling) — nothing to do"
fi

# --- 3. Transparent huge pages ----------------------------------------------
say "== Transparent huge pages ($THP) =="
if [ -w "$thp_path" ]; then
  cur="$(cur_thp)"
  if [ "$CHECK" = 1 ]; then
    [ "$cur" = "$THP" ] && ok "already $cur" || echo "  [..] THP: $cur -> $THP"
  else
    echo "$THP" > "$thp_path" && ok "THP=$THP (was $cur)"
  fi
else
  skip "THP control not writable"
fi

# --- 4. Optional extras -------------------------------------------------------
if [ -n "$HUGEPAGES" ]; then
  say "== Hugepages ($HUGEPAGES x 2MiB) =="
  sysctl_set vm.nr_hugepages "$HUGEPAGES"
fi
if [ -n "$BUSY_POLL" ]; then
  say "== NAPI busy-poll (${BUSY_POLL}us) =="
  sysctl_set net.core.busy_poll "$BUSY_POLL"
  sysctl_set net.core.busy_read "$BUSY_POLL"
fi
if [ -n "$RPS_IFACE" ]; then
  say "== RPS on $RPS_IFACE =="
  if [ -d "/sys/class/net/$RPS_IFACE" ]; then
    # rps_cpus is a hex cpumask; all-ones sized to the CPU count. Writing a
    # fixed-width mask can EOVERFLOW on kernels that bounds-check the value.
    ncpus="$(nproc 2>/dev/null || echo 32)"
    digits=$(( (ncpus + 3) / 4 ))
    mask="$(printf '%*s' "$digits" '' | tr ' ' 'f')"
    for q in /sys/class/net/"$RPS_IFACE"/queues/rx-*/rps_cpus; do
      [ -w "$q" ] || continue
      if [ "$CHECK" = 1 ]; then
        echo "  [..] would set $q -> $mask"
      else
        echo "$mask" > "$q" && ok "RPS enabled: $q ($mask)"
      fi
    done
  else
    skip "interface $RPS_IFACE not found"
  fi
fi

# --- 5. persist / unpersist ---------------------------------------------------
if [ "$PERSIST" = 1 ]; then
  mkdir -p "$LIBEXECDIR"
  # Self-install only when we're not already the installed copy.
  if [ "$SELF" != "$LIBEXECDIR/tsunami-tune" ]; then
    install -m 0755 "$SELF" "$LIBEXECDIR/tsunami-tune"
  fi
  cat > /etc/systemd/system/"$UNIT_NAME" <<EOF
[Unit]
Description=Tsunami OS tuning (governor/THP/sysctl extras)
After=multi-user.target
Before=tsunami.service

[Service]
Type=oneshot
ExecStart=$LIBEXECDIR/tsunami-tune --boot
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 /etc/systemd/system/"$UNIT_NAME"
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME" >/dev/null 2>&1 || systemctl enable "$UNIT_NAME"
  ok "installed + enabled $UNIT_NAME -> $LIBEXECDIR/tsunami-tune --boot (reads $CONF)"
fi
if [ "$UNPERSIST" = 1 ]; then
  systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$UNIT_NAME"
  systemctl daemon-reload
  ok "removed $UNIT_NAME"
fi

# --- 6. advisory (never automated — they reset the NIC / need judgment) -------
if [ "$CHECK" = 0 ] && [ "$BOOT" = 0 ]; then
  cat <<'EOF'

== manual steps worth doing on bare metal / tuned hosts ==
  * NIC channels across cores:   ethtool -l <iface> combined <N>
    (WARNING: resets the link briefly — do it in a maintenance window)
  * IRQ affinity: let irqbalance handle it, or pin NIC queues:
      /proc/irq/<n>/smp_affinity_list
  * NUMA (bare metal): run under
      numactl --cpunodebind=<node> --membind=<node> tsunami ...
    and keep socket_workers on that node's cores.
  * TSUNAMI_CQ_SIZE=32768-65536 in the unit's Environment= if you see
    cqe_overflow_total growing under sustained flood.
  * af_packet backend needs CAP_NET_RAW — already granted via the unit's
    AmbientCapabilities; or `setcap cap_net_raw+ep /path/to/tsunami`.
EOF
fi

[ "$CHECK" = 1 ] && say "(check only — nothing changed)" || true
exit 0
