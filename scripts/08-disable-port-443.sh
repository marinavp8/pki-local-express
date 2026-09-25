#!/usr/bin/env bash
# Quita la redirección 443 → $PORT creada por 07-enable-port-443.sh (requiere sudo).
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
ANCHOR="com.apple/pki-local-443"
TOKEN_FILE="$PROJECT_DIR/.pf-token"

log "Vaciando el anchor $ANCHOR (sudo)"
sudo pfctl -a "$ANCHOR" -F all 2>/dev/null

if [[ -s "$TOKEN_FILE" ]]; then
  sudo pfctl -X "$(cat "$TOKEN_FILE")" 2>/dev/null || true
  rm -f "$TOKEN_FILE"
fi
ok "Redirección del puerto 443 eliminada"
