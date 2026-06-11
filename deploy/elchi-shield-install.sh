#!/usr/bin/env bash
#
# elchi-shield-install.sh
# --------------------------------------------------------------------------
# Installs elchi-shield — the local Envoy ext_proc API-security / WAF sidecar —
# as a hardened systemd service on an edge host, next to Envoy and elchi-client.
#
#   • elchi system user/group (shared with the rest of the Elchi stack)
#   • /etc/elchi/elchi-shield hierarchy (watched conf.d + data files)
#   • the elchi-shield binary (downloaded from the GitHub release, sha256-verified;
#     or built from this checkout with --build)
#   • a systemd unit that talks to Envoy over a /run UDS and exposes health/metrics
#     on loopback only — the sidecar is never reachable off-box
#
# Unlike elchi-client, elchi-shield has NO central connection of its own: its
# policy is delivered as files into the watched conf.d (by elchi-client), so this
# installer takes no --host/--token. It only places the binary + service.
#
# Usage:
#   sudo ./elchi-shield-install.sh [--version=vX.Y.Z] [--build] [--user=elchi] [--no-start]
#
set -euo pipefail

###############################################################################
# GLOBAL VARIABLES AND CONFIGURATION
###############################################################################

# Command-line options
PIN_VERSION=""          # --version=vX.Y.Z (default: latest release)
BUILD_FROM_SOURCE=false # --build (compile this checkout instead of downloading)
START_SERVICE=true      # --no-start to install without enabling/starting

# System users (shared stack identities; created idempotently)
ELCHI_USER="elchi"
ELCHI_GROUP="elchi"
ENVOY_USER="envoyuser"  # Envoy's user — joined to the elchi group for UDS access

# Directory paths
ELCHI_DIR="/etc/elchi"
ELCHI_BIN_DIR="$ELCHI_DIR/bin"
BINARY_PATH="$ELCHI_BIN_DIR/elchi-shield"
SHIELD_DIR="$ELCHI_DIR/elchi-shield"
CONF_DIR="$SHIELD_DIR/conf.d"          # watched config directory (files from elchi-client)
FILES_DIR="$SHIELD_DIR/files"          # data files (feeds, JWKS, OpenAPI specs, …)
LOG_DIR="/var/log/elchi"
AUDIT_FILE="$LOG_DIR/elchi-shield.audit.ndjson"

# Runtime socket lives on /run (tmpfs, systemd-managed) so Envoy can reach it.
RUN_DIR_NAME="elchi-shield"            # → /run/elchi-shield (systemd RuntimeDirectory)
SOCKET_PATH="/run/$RUN_DIR_NAME/extproc.sock"
HTTP_ADDR="127.0.0.1:9001"            # loopback health/metrics

SERVICE_FILE="/etc/systemd/system/elchi-shield.service"

# Release source
GITHUB_REPO="CloudNativeWorks/elchi-shield"

# This script's directory and the repo root (for --build)
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SOURCE_DIR/.." && pwd)"

# ANSI colors
C_RST='\033[0m'; C_INF='\033[1;34m'; C_OK='\033[1;32m'; C_WRN='\033[1;33m'; C_ERR='\033[1;31m'

###############################################################################
# UTILITY FUNCTIONS
###############################################################################

info() { printf "${C_INF}[INFO] %s${C_RST}\n" "$*"; }
ok()   { printf "${C_OK}[ OK ] %s${C_RST}\n"  "$*"; }
warn() { printf "${C_WRN}[WARN] %s${C_RST}\n" "$*"; }
fail() { printf "${C_ERR}[FAIL] %s${C_RST}\n" "$*"; exit 1; }

# Run a command, printing a colorized OK/FAIL.
run() {
  if "$@"; then ok "$*"; else fail "command failed: $*"; fi
}

###############################################################################
# COMMAND-LINE ARGUMENT PARSING
###############################################################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version=*) PIN_VERSION="${1#*=}"; shift ;;
    --build)     BUILD_FROM_SOURCE=true; shift ;;
    --user=*)    ELCHI_USER="${1#*=}"; ELCHI_GROUP="$ELCHI_USER"; shift ;;
    --no-start)  START_SERVICE=false; shift ;;
    --help|-h)
      echo "Usage: sudo $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --version=vX.Y.Z   Install a specific release (default: latest)"
      echo "  --build            Build from this checkout instead of downloading a release"
      echo "  --user=NAME        Service user/group (default: elchi)"
      echo "  --no-start         Install but do not enable/start the service"
      echo "  --help, -h         Show this help"
      echo ""
      echo "Examples:"
      echo "  sudo $0                       # download the latest release and start"
      echo "  sudo $0 --version=v0.2.0      # pin a release"
      echo "  sudo $0 --build               # compile this checkout (needs Go 1.26+)"
      exit 0
      ;;
    *) fail "Unknown argument: $1 (use --help)" ;;
  esac
done

###############################################################################
# MAIN EXECUTION FLOW
###############################################################################

trap 'fail "line $LINENO (exit code $?)"' ERR
[[ $EUID -eq 0 ]] || fail "Run this script as root (sudo …)"

info "=== Elchi Shield Installer ==="

# --- System user/group (shared with the rest of the stack) -------------------
if getent group "$ELCHI_GROUP" >/dev/null; then
  ok "group $ELCHI_GROUP exists"
else
  run groupadd --system "$ELCHI_GROUP"
fi
if id "$ELCHI_USER" &>/dev/null; then
  ok "user $ELCHI_USER exists"
else
  run useradd --system --no-create-home --shell /usr/sbin/nologin -g "$ELCHI_GROUP" "$ELCHI_USER"
fi

# Envoy connects to the UDS; if its user exists, add it to the elchi group so it
# can traverse /run/elchi-shield and open the (group-rw) socket.
if id "$ENVOY_USER" &>/dev/null; then
  if id -nG "$ENVOY_USER" | tr ' ' '\n' | grep -qx "$ELCHI_GROUP"; then
    ok "$ENVOY_USER already in group $ELCHI_GROUP"
  else
    run usermod -aG "$ELCHI_GROUP" "$ENVOY_USER"
    warn "added $ENVOY_USER to $ELCHI_GROUP — restart Envoy so it picks up the new group"
  fi
else
  warn "$ENVOY_USER not found — ensure Envoy's user is in the '$ELCHI_GROUP' group to reach the ext_proc socket"
fi

# --- Directory hierarchy -----------------------------------------------------
info "creating /etc/elchi/elchi-shield tree"
run mkdir -p "$ELCHI_BIN_DIR" "$CONF_DIR" "$FILES_DIR" "$LOG_DIR"
# /etc/elchi itself: traversable by the elchi group, not world.
run chown root:"$ELCHI_GROUP" "$ELCHI_DIR" "$ELCHI_BIN_DIR"
run chmod 750 "$ELCHI_DIR" "$ELCHI_BIN_DIR"
# Shield's own tree is owned by the service user (it reads conf.d, writes nothing
# there itself — elchi-client populates it).
run chown -R "$ELCHI_USER:$ELCHI_GROUP" "$SHIELD_DIR" "$LOG_DIR"
run chmod -R u=rwX,g=rX,o= "$SHIELD_DIR"
run chmod 750 "$LOG_DIR"
if [[ ! -e "$CONF_DIR/README" ]]; then
  cat >"$CONF_DIR/README" <<'EOF'
# elchi-shield watches this directory for *.yaml / *.json policy files.
# Files here are managed by elchi-client (pushed from the Elchi control plane).
# An empty directory means "no policy" → the configured default posture applies.
EOF
  chown "$ELCHI_USER:$ELCHI_GROUP" "$CONF_DIR/README"
fi

# --- Binary: build from source OR download the release -----------------------
install_from_source() {
  command -v go >/dev/null 2>&1 || fail "--build requires Go (1.26+) on PATH"
  [[ -d "$REPO_ROOT/cmd/elchi-shield" ]] || fail "--build must run from the elchi-shield checkout (cmd/elchi-shield not found)"
  local version commit
  version=$(cat "$REPO_ROOT/VERSION" 2>/dev/null || echo dev)
  commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo none)
  info "building elchi-shield v$version ($commit) from source (static, CGO off)"
  CGO_ENABLED=0 go build -C "$REPO_ROOT" -trimpath -buildvcs=true \
    -ldflags="-s -w -X main.version=v$version -X main.commit=$commit" \
    -o "$BINARY_PATH" ./cmd/elchi-shield
  ok "built $BINARY_PATH"
}

install_from_release() {
  local tag arch suffix url checksum_url tmp_bin tmp_sum expected actual
  if [[ -n "$PIN_VERSION" ]]; then
    tag="$PIN_VERSION"
  else
    info "resolving the latest release of $GITHUB_REPO"
    tag=$(curl -fsSL "https://api.github.com/repos/$GITHUB_REPO/releases/latest" \
            | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")
    [[ -n "$tag" ]] || fail "could not resolve the latest release tag (try --version=… or --build)"
  fi
  info "release: $tag"

  arch=$(dpkg --print-architecture 2>/dev/null || uname -m)
  case "$arch" in
    amd64|x86_64) suffix="linux-amd64" ;;
    arm64|aarch64) suffix="linux-arm64" ;;
    *) warn "unsupported architecture '$arch' — defaulting to amd64"; suffix="linux-amd64" ;;
  esac

  url="https://github.com/$GITHUB_REPO/releases/download/$tag/elchi-shield-${suffix}"
  checksum_url="${url}.sha256"
  tmp_bin="$(mktemp)"; tmp_sum="$(mktemp)"
  trap 'rm -f "$tmp_bin" "$tmp_sum"' RETURN

  info "downloading $url"
  curl -fsSL --retry 3 --retry-delay 2 --max-time 120 "$url" -o "$tmp_bin" \
    || fail "binary download failed (try --build to compile locally)"

  if curl -fsSL --retry 3 --retry-delay 2 --max-time 30 "$checksum_url" -o "$tmp_sum"; then
    expected=$(awk '{print $1}' "$tmp_sum")
    if command -v sha256sum >/dev/null 2>&1; then
      actual=$(sha256sum "$tmp_bin" | awk '{print $1}')
    else
      actual=$(shasum -a 256 "$tmp_bin" | awk '{print $1}')
    fi
    [[ "$expected" == "$actual" ]] || fail "checksum mismatch (expected $expected, got $actual)"
    ok "sha256 verified"
  else
    warn "no checksum published — skipping verification"
  fi

  install -m 0755 -o root -g "$ELCHI_GROUP" "$tmp_bin" "$BINARY_PATH"
  ok "installed $BINARY_PATH"
}

if [[ "$BUILD_FROM_SOURCE" == true ]]; then
  install_from_source
else
  install_from_release
fi
run chown root:"$ELCHI_GROUP" "$BINARY_PATH"
run chmod 755 "$BINARY_PATH"

# --- systemd unit ------------------------------------------------------------
# The socket lives under a systemd-managed RuntimeDirectory (/run/elchi-shield),
# group-owned by elchi so Envoy (in that group) can connect. Health/metrics bind
# loopback only. Hardening keeps the sidecar from being a foothold.
info "writing systemd unit $SERVICE_FILE"
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Elchi Shield — Envoy ext_proc API security / WAF sidecar
Documentation=https://github.com/$GITHUB_REPO
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$ELCHI_USER
Group=$ELCHI_GROUP

# systemd creates/cleans /run/elchi-shield, group-owned so Envoy can reach the UDS.
RuntimeDirectory=$RUN_DIR_NAME
RuntimeDirectoryMode=2750

# Validate the watched config dir at boot (non-fatal: shield tolerates a bad file
# and applies the default posture rather than blackholing traffic).
ExecStartPre=-$BINARY_PATH validate $CONF_DIR
ExecStart=$BINARY_PATH \\
  --config-dir $CONF_DIR \\
  --extproc-network unix \\
  --extproc-addr $SOCKET_PATH \\
  --http-addr $HTTP_ADDR \\
  --audit-exporter file \\
  --audit-file $AUDIT_FILE \\
  --log-format json \\
  --log-level info

Restart=always
RestartSec=5

# --- Hardening (loopback + UDS only; never exposed off-box) ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=$SHIELD_DIR $LOG_DIR
UMask=0007
LimitNOFILE=262144

StandardOutput=journal
StandardError=journal
SyslogIdentifier=elchi-shield

[Install]
WantedBy=multi-user.target
EOF
run chmod 644 "$SERVICE_FILE"
run systemctl daemon-reload

if [[ "$START_SERVICE" == true ]]; then
  run systemctl enable --now elchi-shield.service
else
  run systemctl enable elchi-shield.service
  info "service enabled but not started (--no-start)"
fi

###############################################################################
# COMPLETION SUMMARY
###############################################################################

echo ""
printf "${C_OK}╔════════════════════════════════════════════════════════════════════╗${C_RST}\n"
printf "${C_OK}║                  🛡️  ELCHI SHIELD INSTALLED!  🛡️                    ║${C_RST}\n"
printf "${C_OK}╚════════════════════════════════════════════════════════════════════╝${C_RST}\n"
echo ""
printf "${C_INF}┌─ 📄 LAYOUT ────────────────────────────────────────────────────────┐${C_RST}\n"
printf "${C_INF}│${C_RST} Binary    : ${C_OK}%s${C_RST}\n" "$BINARY_PATH"
printf "${C_INF}│${C_RST} Config dir: ${C_OK}%s${C_RST} (watched; managed by elchi-client)\n" "$CONF_DIR"
printf "${C_INF}│${C_RST} Data files: ${C_OK}%s${C_RST}\n" "$FILES_DIR"
printf "${C_INF}│${C_RST} ext_proc  : ${C_OK}unix:%s${C_RST}\n" "$SOCKET_PATH"
printf "${C_INF}│${C_RST} Health    : ${C_OK}http://%s/healthz${C_RST} (loopback)\n" "$HTTP_ADDR"
printf "${C_INF}│${C_RST} Audit log : ${C_OK}%s${C_RST}\n" "$AUDIT_FILE"
printf "${C_INF}│${C_RST} Service   : ${C_OK}%s${C_RST}\n" "$SERVICE_FILE"
printf "${C_INF}└────────────────────────────────────────────────────────────────────┘${C_RST}\n"
echo ""
printf "${C_INF}┌─ 🎯 NEXT STEPS ────────────────────────────────────────────────────┐${C_RST}\n"
printf "${C_INF}│${C_RST} 1️⃣  Point Envoy's ext_proc cluster at: ${C_OK}unix://%s${C_RST}\n" "$SOCKET_PATH"
printf "${C_INF}│${C_RST}     (ensure Envoy's user is in the '${C_OK}%s${C_RST}' group)\n" "$ELCHI_GROUP"
printf "${C_INF}│${C_RST} 2️⃣  Status : ${C_OK}systemctl status elchi-shield${C_RST}\n"
printf "${C_INF}│${C_RST} 3️⃣  Logs   : ${C_OK}journalctl -u elchi-shield -f${C_RST}\n"
printf "${C_INF}│${C_RST} 4️⃣  Health : ${C_OK}curl -s http://%s/healthz${C_RST}\n" "$HTTP_ADDR"
printf "${C_INF}└────────────────────────────────────────────────────────────────────┘${C_RST}\n"
echo ""

SERVICE_STATE=$(systemctl is-active elchi-shield.service 2>/dev/null || echo inactive)
if [[ "$SERVICE_STATE" == "active" ]]; then
  ok "elchi-shield.service is running"
else
  warn "elchi-shield.service is $SERVICE_STATE — check: journalctl -u elchi-shield -e"
fi
