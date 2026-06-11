#!/usr/bin/env bash
#
# go.sh — elchi-shield developer build/deploy loop (run ON an edge host).
# --------------------------------------------------------------------------
# Builds the binary from this checkout straight into /etc/elchi/bin, validates
# the watched config dir, restarts the systemd service, and tails the journal.
# Mirrors elchi-client's go.sh but is much simpler: elchi-shield is a single,
# fully static binary (CGO disabled), so there are no apt / gcc / libsystemd
# prerequisites to install.
#
# Prereqs: the service must already be installed once via elchi-shield-install.sh
#          (creates the user, dirs, and systemd unit). After that, `./go.sh`
#          is the fast inner loop for iterating on the binary.
#
set -euo pipefail

# -------------------------------
# 📁 Paths & variables
# -------------------------------
APP_NAME="elchi-shield"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CMD_DIR="$SOURCE_DIR/cmd/elchi-shield"
INSTALL_DIR="/etc/elchi"
BIN_DIR="$INSTALL_DIR/bin"
BUILD_OUTPUT="$BIN_DIR/$APP_NAME"
CONF_DIR="$INSTALL_DIR/$APP_NAME/conf.d"
SYSTEMD_SERVICE_NAME="elchi-shield"
RUN_OWNER="elchi:elchi"

# -------------------------------
# 📂 Ensure target dir exists
# -------------------------------
echo "[+] Ensuring $BIN_DIR exists..."
sudo mkdir -p "$BIN_DIR"

# -------------------------------
# 🔨 Build the static Go binary into /etc/elchi/bin/
# -------------------------------
VERSION=$(cat "$SOURCE_DIR/VERSION" 2>/dev/null || echo "dev")
COMMIT=$(git -C "$SOURCE_DIR" rev-parse --short HEAD 2>/dev/null || echo "none")
echo "[+] Building $APP_NAME v$VERSION ($COMMIT) into $BUILD_OUTPUT..."

# Preserve the developer's Go environment; force a static (CGO-off) build so the
# artifact matches the release/distroless build exactly.
BUILD_ENV=( "PATH=$PATH" "CGO_ENABLED=0" )
[[ -n "${GOPATH:-}" ]]     && BUILD_ENV+=("GOPATH=$GOPATH")
[[ -n "${GOROOT:-}" ]]     && BUILD_ENV+=("GOROOT=$GOROOT")
[[ -n "${GOCACHE:-}" ]]    && BUILD_ENV+=("GOCACHE=$GOCACHE")
[[ -n "${GOMODCACHE:-}" ]] && BUILD_ENV+=("GOMODCACHE=$GOMODCACHE")
[[ -n "${GOFLAGS:-}" ]]    && BUILD_ENV+=("GOFLAGS=$GOFLAGS")

sudo env "${BUILD_ENV[@]}" \
  go build -trimpath -buildvcs=true \
    -ldflags="-s -w -X main.version=v$VERSION -X main.commit=$COMMIT" \
    -o "$BUILD_OUTPUT" "$CMD_DIR"

# -------------------------------
# 🔐 Permissions for binary
# -------------------------------
sudo chown "$RUN_OWNER" "$BUILD_OUTPUT"
sudo chmod 755 "$BUILD_OUTPUT"

# -------------------------------
# ✅ Validate the watched config dir before restarting (non-fatal: shield keeps
#    its last good config on a reload, but surface problems early in dev).
# -------------------------------
if [[ -d "$CONF_DIR" ]]; then
  echo "[+] Validating config dir $CONF_DIR..."
  "$BUILD_OUTPUT" validate "$CONF_DIR" || echo "[!] config validation reported problems (continuing)"
fi

# -------------------------------
# 🔁 Reload & restart the systemd service
# -------------------------------
echo "[+] Reloading systemd and restarting $SYSTEMD_SERVICE_NAME..."
sudo systemctl daemon-reload
sudo systemctl restart "$SYSTEMD_SERVICE_NAME"

# -------------------------------
# ✅ Done
# -------------------------------
echo "[✓] Build + deploy + restart complete."
echo "    Binary : $BUILD_OUTPUT"
echo "    Config : $CONF_DIR"

# -------------------------------
# 📜 Tail logs
# -------------------------------
echo "[+] Tailing logs for $SYSTEMD_SERVICE_NAME (Ctrl-C to stop)..."
sudo journalctl -u "$SYSTEMD_SERVICE_NAME" -f --no-pager
