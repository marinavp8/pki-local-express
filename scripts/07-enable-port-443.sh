#!/usr/bin/env bash
# Redirige 127.0.0.1:443 → 127.0.0.1:$PORT con pf (requiere sudo). El servidor sigue sin root.
# Regla en un anchor bajo com.apple/* (no se toca /etc/pf.conf); se pierde al reiniciar.
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
PORT="${PORT:-17433}"
ANCHOR="com.apple/pki-local-443"
TOKEN_FILE="$PROJECT_DIR/.pf-token"

log "Cargando regla rdr 127.0.0.1:443 → 127.0.0.1:$PORT en el anchor $ANCHOR (sudo)"
echo "rdr pass on lo0 inet proto tcp from any to 127.0.0.1 port 443 -> 127.0.0.1 port $PORT" \
  | sudo pfctl -a "$ANCHOR" -f - 2>/dev/null

if [[ ! -s "$TOKEN_FILE" ]]; then
  # -E cuenta referencias: pf solo se apaga cuando se liberan todas (no afecta a otros usuarios de pf).
  sudo pfctl -E 2>&1 | awk '/Token/ {print $NF}' > "$TOKEN_FILE"
fi

sudo pfctl -a "$ANCHOR" -s nat 2>/dev/null
ok "https://$SERVER_CN/ → puerto $PORT (desactivar: scripts/08-disable-port-443.sh)"
