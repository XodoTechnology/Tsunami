#!/usr/bin/env bash
# install.sh — build, install, and wire up Tsunami on a Linux host.
#
# What it does:
#   1. cargo build --release (or installs --binary / --no-build)
#   2. Creates a `tsunami` system user (unless --user root)
#   3. Installs binary, config, systemd units, sysctl tuning drop-in
#   4. Optionally: OS tuning (--tune), af_packet capability (--af-packet),
#      enable/start the service
#
# Usage:
#   sudo scripts/install.sh [options]
#
# Options:
#   --prefix DIR        install prefix           (default /usr/local)
#   --config-dir DIR    config directory         (default /etc/tsunami)
#   --state-dir DIR     working/snapshot dir     (default /var/lib/tsunami)
#   --user NAME         service user             (default tsunami; "root" to skip)
#   --repo DIR          source checkout          (default: parent of scripts/)
#   --binary PATH       install this prebuilt binary instead of cargo build
#   --no-build          require existing target/release/tsunami
#   --with-loadgen      also install tsunami-loadgen (testing tool)
#   --no-sysctl         don't install/apply /etc/sysctl.d/99-tsunami.conf
#   --tune              run scripts/tune.sh --apply-equivalent after install
#   --tune-persist      like --tune, plus re-apply at boot (tsunami-tuning.service)
#   --af-packet         setcap cap_net_raw+ep on the binary (rx_backend=af_packet)
#   --enable            systemctl enable (start with --start)
#   --start             systemctl enable --now
#   -h, --help          this text
#
# Examples:
#   sudo scripts/install.sh --tune                 # typical VPS/bare-metal
#   sudo scripts/install.sh --user root --no-sysctl  # container/test box
#   sudo scripts/install.sh --with-loadgen --start   # bench box, run now

set -euo pipefail

PREFIX=/usr/local
CONFIG_DIR=/etc/tsunami
STATE_DIR=/var/lib/tsunami
SVC_USER=tsunami
REPO=""
BINARY=""
NO_BUILD=0 WITH_LOADGEN=0 NO_SYSCTL=0 TUNE=0 TUNE_PERSIST=0 AF_PACKET=0 ENABLE=0 START=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)       PREFIX="$2"; shift 2 ;;
    --config-dir)   CONFIG_DIR="$2"; shift 2 ;;
    --state-dir)    STATE_DIR="$2"; shift 2 ;;
    --user)         SVC_USER="$2"; shift 2 ;;
    --repo)         REPO="$2"; shift 2 ;;
    --binary)       BINARY="$2"; shift 2 ;;
    --no-build)     NO_BUILD=1; shift ;;
    --with-loadgen) WITH_LOADGEN=1; shift ;;
    --no-sysctl)    NO_SYSCTL=1; shift ;;
    --tune)         TUNE=1; shift ;;
    --tune-persist) TUNE_PERSIST=1; TUNE=1; shift ;;
    --af-packet)    AF_PACKET=1; shift ;;
    --enable)       ENABLE=1; shift ;;
    --start)        START=1; ENABLE=1; shift ;;
    -h|--help)      sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "install.sh must run as root (use sudo)" >&2; exit 1; }

# Repo root: explicit --repo, else the checkout containing this script.
if [ -z "$REPO" ]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
[ -f "$REPO/Cargo.toml" ] || { echo "no Cargo.toml at $REPO — pass --repo" >&2; exit 1; }

LIBEXECDIR="$PREFIX/libexec"
BIN_DIR="$PREFIX/bin"
SYSCTL_DEST=/etc/sysctl.d/99-tsunami.conf
UNIT_DIR=/etc/systemd/system

say() { echo "== $*"; }

# --- 1. build / locate binary ------------------------------------------------
say "binary"
# sudo strips ~/.cargo/bin from PATH — look for cargo in the usual spots.
if ! command -v cargo >/dev/null 2>&1; then
  for d in /root/.cargo/bin "$HOME/.cargo/bin" /usr/local/cargo/bin \
           "${SUDO_USER:+/home/$SUDO_USER/.cargo/bin}"; do
    if [ -x "$d/cargo" ]; then export PATH="$d:$PATH"; break; fi
  done
fi
if [ -n "$BINARY" ]; then
  [ -f "$BINARY" ] || { echo "--binary not found: $BINARY" >&2; exit 1; }
elif [ "$NO_BUILD" = 1 ]; then
  BINARY="$REPO/target/release/tsunami"
  [ -f "$BINARY" ] || { echo "no prebuilt binary at $BINARY (run cargo build --release)" >&2; exit 1; }
else
  command -v cargo >/dev/null 2>&1 || \
    { echo "cargo not found — install Rust, or pass --binary/--no-build" >&2; exit 1; }
  say "cargo build --release (in $REPO)"
  (cd "$REPO" && cargo build --release --bin tsunami)
  BINARY="$REPO/target/release/tsunami"
fi
LOADGEN_BIN="$REPO/target/release/tsunami-loadgen"
[ "$WITH_LOADGEN" = 1 ] && [ ! -f "$LOADGEN_BIN" ] && \
  (cd "$REPO" && cargo build --release --bin tsunami-loadgen) || true

# --- 2. service user ----------------------------------------------------------
if [ "$SVC_USER" != "root" ]; then
  say "service user: $SVC_USER"
  getent group "$SVC_USER" >/dev/null || groupadd --system "$SVC_USER"
  id "$SVC_USER" >/dev/null 2>&1 || \
    useradd --system --gid "$SVC_USER" --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin "$SVC_USER"
else
  say "service user: root"
fi

# --- 3. directories + files ----------------------------------------------------
say "installing to $PREFIX / $CONFIG_DIR / $STATE_DIR"
install -d -m 0755 "$BIN_DIR" "$LIBEXECDIR"
install -d -m 0750 "$CONFIG_DIR"
if [ "$SVC_USER" != "root" ]; then
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$STATE_DIR"
else
  install -d -m 0750 "$STATE_DIR"
fi

install -m 0755 "$BINARY" "$BIN_DIR/tsunami"
[ "$WITH_LOADGEN" = 1 ] && [ -f "$LOADGEN_BIN" ] && \
  install -m 0755 "$LOADGEN_BIN" "$BIN_DIR/tsunami-loadgen"
install -m 0755 "$REPO/scripts/tune.sh" "$LIBEXECDIR/tsunami-tune"

# Config: seed from example on first install only — never clobber edits.
if [ ! -f "$CONFIG_DIR/tsunami.toml" ]; then
  install -m 0640 "$REPO/tsunami.toml.example" "$CONFIG_DIR/tsunami.toml"
  [ "$SVC_USER" != "root" ] && chown "root:$SVC_USER" "$CONFIG_DIR/tsunami.toml"
  say "wrote $CONFIG_DIR/tsunami.toml (edit before starting!)"
else
  say "config exists: $CONFIG_DIR/tsunami.toml (left untouched)"
fi

# systemd units — render path/user placeholders.
render() { sed -e "s|@PREFIX@|$PREFIX|g" \
              -e "s|@CONFIG@|$CONFIG_DIR|g" \
              -e "s|@STATE@|$STATE_DIR|g" \
              -e "s|@USER@|$SVC_USER|g" \
              -e "s|@LIBEXECDIR@|$LIBEXECDIR|g" "$1"; }
render "$REPO/deploy/tsunami.service" > "$UNIT_DIR/tsunami.service"
render "$REPO/deploy/tsunami-tuning.service" > "$UNIT_DIR/tsunami-tuning.service"
chmod 0644 "$UNIT_DIR/tsunami.service" "$UNIT_DIR/tsunami-tuning.service"

# --- 4. sysctl tuning -----------------------------------------------------------
if [ "$NO_SYSCTL" = 0 ]; then
  say "sysctl tuning -> $SYSCTL_DEST"
  install -m 0644 "$REPO/deploy/99-tsunami.sysctl.conf" "$SYSCTL_DEST"
  sysctl -q --system 2>/dev/null || sysctl -q -p "$SYSCTL_DEST" || true
  say "applied (affects the whole host — see deploy/99-tsunami.sysctl.conf)"
else
  say "skipping sysctl (--no-sysctl)"
fi

# --- 5. optional extras ----------------------------------------------------------
if [ "$AF_PACKET" = 1 ]; then
  if command -v setcap >/dev/null; then
    setcap 'cap_net_raw+ep' "$BIN_DIR/tsunami" && say "setcap cap_net_raw+ep on binary"
  else
    echo "!! setcap not found — install libcap2-bin or rely on unit AmbientCapabilities" >&2
  fi
fi

if [ "$TUNE" = 1 ]; then
  say "running tune.sh"
  if [ "$TUNE_PERSIST" = 1 ]; then
    TSUNAMI_LIBEXECDIR="$LIBEXECDIR" "$LIBEXECDIR/tsunami-tune" --persist
  else
    TSUNAMI_LIBEXECDIR="$LIBEXECDIR" "$LIBEXECDIR/tsunami-tune"
  fi
fi

systemctl daemon-reload
if [ "$ENABLE" = 1 ] || [ "$START" = 1 ]; then
  systemctl enable tsunami.service
  [ "$START" = 1 ] && systemctl restart tsunami.service && say "tsunami started"
fi

# --- 6. summary -------------------------------------------------------------------
say "done"
cat <<EOF
  binary     : $BIN_DIR/tsunami
  config     : $CONFIG_DIR/tsunami.toml   <-- EDIT BEFORE STARTING
  state dir  : $STATE_DIR  (snapshots/logs land here via WorkingDirectory)
  units      : tsunami.service, tsunami-tuning.service
  sysctl     : $SYSCTL_DEST

Next steps:
  1. Edit $CONFIG_DIR/tsunami.toml — set admin_user/admin_password before
     exposing port 8080, choose rx_backend, size socket_recv_buffer.
  2. $([ "$START" = 1 ] || echo "systemctl enable --now tsunami")
  3. Dashboard: http://<host>:8080/   UDP tracker: udp://<host>:6881

Socket-buffer memory ceiling (worst case, all workers):
EOF
# Parse the effective config values for a real estimate.
CFG="$CONFIG_DIR/tsunami.toml"
recv_buf="$(grep -E '^\s*socket_recv_buffer\s*=' "$CFG" | head -1 | sed -E 's/.*=\s*([0-9]+).*/\1/')"
sock_wrk="$(grep -E '^\s*socket_workers\s*=' "$CFG" | head -1 | sed -E 's/.*=\s*([0-9]+).*/\1/')"
fam=0
grep -qE '^\s*use_ipv4\s*=\s*true' "$CFG" && fam=$((fam+1))
grep -qE '^\s*use_ipv6\s*=\s*true' "$CFG" && fam=$((fam+1))
recv_buf="${recv_buf:-8000000}"; sock_wrk="${sock_wrk:-0}"; fam="${fam:-1}"
[ "$sock_wrk" = "0" ] && sock_wrk="$(nproc 2>/dev/null || echo 4)"
# kernel doubles SO_RCVBUF and clamps at rmem_max (256MiB in our drop-in);
# each worker binds one socket per enabled IP family.
eff=$(( recv_buf * 2 )); [ "$eff" -gt 268435456 ] && eff=268435456
total_mb=$(( eff * sock_wrk * fam / 1048576 ))
echo "  $sock_wrk workers x $fam socket(s) x min(2 x ${recv_buf}B, rmem_max) ≈ ${total_mb} MiB max UDP socket buffers"
echo "  (buffers fill only under load; ring_size adds ~25MiB/worker — see config comments)"
