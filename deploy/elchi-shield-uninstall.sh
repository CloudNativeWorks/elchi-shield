#!/usr/bin/env bash
#
# elchi-shield-uninstall.sh
# --------------------------------------------------------------------------
# Removes the elchi-shield sidecar (service, binary, and its /etc/elchi/elchi-shield
# tree) from an edge host.
#
# SCOPE: this removes ONLY elchi-shield's own artifacts. The elchi user/group,
# /etc/elchi, /etc/elchi/bin and /var/log/elchi are SHARED with elchi-client and
# the rest of the Elchi stack, so they are deliberately left intact.
#
# Usage: sudo ./elchi-shield-uninstall.sh [--yes]
#
set -euo pipefail

###############################################################################
# GLOBAL VARIABLES
###############################################################################

ELCHI_DIR="/etc/elchi"
BINARY_PATH="$ELCHI_DIR/bin/elchi-shield"
SHIELD_DIR="$ELCHI_DIR/elchi-shield"
LOG_DIR="/var/log/elchi"
AUDIT_FILE="$LOG_DIR/elchi-shield.audit.ndjson"
RUN_DIR="/run/elchi-shield"
SERVICE_FILE="/etc/systemd/system/elchi-shield.service"

ASSUME_YES=false

# ANSI colors
C_RST='\033[0m'; C_INF='\033[1;34m'; C_OK='\033[1;32m'; C_WRN='\033[1;33m'; C_ERR='\033[1;31m'

info() { printf "${C_INF}[INFO] %s${C_RST}\n" "$*"; }
ok()   { printf "${C_OK}[ OK ] %s${C_RST}\n"  "$*"; }
warn() { printf "${C_WRN}[WARN] %s${C_RST}\n" "$*"; }
fail() { printf "${C_ERR}[FAIL] %s${C_RST}\n" "$*"; exit 1; }

confirm() {
  $ASSUME_YES && return 0
  local response
  printf "${C_WRN}%s [y/N]: ${C_RST}" "$1"
  read -r response
  [[ "$response" =~ ^[yY]([eE][sS])?$ ]]
}

###############################################################################
# ARGS + SAFETY CHECKS
###############################################################################

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) ASSUME_YES=true; shift ;;
    --help|-h) echo "Usage: sudo $0 [--yes]"; exit 0 ;;
    *) fail "Unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "This script must be run as root (sudo)"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "                ELCHI SHIELD UNINSTALL"
echo "════════════════════════════════════════════════════════════════"
echo ""
warn "This will remove:"
echo "  • the elchi-shield systemd service and binary"
echo "  • $SHIELD_DIR (config dir + data files + audit.env if present)"
echo "  • any legacy local audit log ($AUDIT_FILE — pre-ClickHouse installs)"
echo ""
info "Left intact (shared with elchi-client / the Elchi stack):"
echo "  • the elchi user/group, $ELCHI_DIR, $ELCHI_DIR/bin, $LOG_DIR"
echo ""

if ! confirm "Proceed with uninstalling elchi-shield?"; then
  info "Uninstall cancelled"; exit 0
fi

###############################################################################
# STOP & DISABLE SERVICE
###############################################################################

info "Stopping elchi-shield service..."
if systemctl list-units --full --all 2>/dev/null | grep -Fq "elchi-shield.service"; then
  systemctl stop elchi-shield.service 2>/dev/null || true
  systemctl disable elchi-shield.service 2>/dev/null || true
  ok "service stopped and disabled"
else
  info "elchi-shield.service not found"
fi

if [[ -f "$SERVICE_FILE" ]]; then
  rm -f "$SERVICE_FILE"
  ok "removed $SERVICE_FILE"
fi
systemctl daemon-reload
# RuntimeDirectory is cleaned by systemd on stop; remove any leftover.
[[ -d "$RUN_DIR" ]] && rm -rf "$RUN_DIR" && ok "removed $RUN_DIR"

###############################################################################
# REMOVE BINARY
###############################################################################

if [[ -f "$BINARY_PATH" ]]; then
  rm -f "$BINARY_PATH"
  ok "removed $BINARY_PATH"
else
  info "binary not found at $BINARY_PATH"
fi

###############################################################################
# REMOVE SHIELD DIRECTORY (with optional config backup)
###############################################################################

if [[ -d "$SHIELD_DIR" ]]; then
  if [[ -d "$SHIELD_DIR/conf.d" ]] && find "$SHIELD_DIR/conf.d" -mindepth 1 -not -name README -print -quit 2>/dev/null | grep -q .; then
    warn "Found policy files in $SHIELD_DIR/conf.d"
    if confirm "Back up the config dir before removal?"; then
      backup="$HOME/elchi-shield-conf-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
      tar -czf "$backup" -C "$SHIELD_DIR" conf.d files 2>/dev/null || tar -czf "$backup" -C "$SHIELD_DIR" conf.d 2>/dev/null || true
      ok "backed up to $backup"
    fi
  fi
  rm -rf "$SHIELD_DIR"
  ok "removed $SHIELD_DIR"
fi

###############################################################################
# REMOVE AUDIT LOG (the shield-specific file only; keep the shared log dir)
###############################################################################

for f in "$AUDIT_FILE" "$AUDIT_FILE".*; do
  [[ -e "$f" ]] && rm -f "$f" && ok "removed $(basename "$f")"
done

###############################################################################
# COMPLETION SUMMARY
###############################################################################

echo ""
printf "${C_OK}╔════════════════════════════════════════════════════════════════════╗${C_RST}\n"
printf "${C_OK}║                🧹 ELCHI SHIELD UNINSTALLED 🧹                      ║${C_RST}\n"
printf "${C_OK}╚════════════════════════════════════════════════════════════════════╝${C_RST}\n"
echo ""
info "elchi-shield has been removed."
warn "Remember to remove the ext_proc cluster/filter from Envoy's config so it"
warn "stops dialing the (now absent) socket."
echo ""
info "Shared stack components (elchi user, $ELCHI_DIR, $LOG_DIR) were left intact."
echo ""
info "To reinstall: sudo ./elchi-shield-install.sh"
echo ""
