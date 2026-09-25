#!/usr/bin/env bash
# Borra del llavero de inicio de sesión la identidad de cada cliente y la contraseña de su .p12.
# Uso: 11-uninstall-client-macos.sh <nombre>...
NAMES=("$@"); set --
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
[[ ${#NAMES[@]} -gt 0 ]] || die "uso: $0 <nombre>..."
LOGIN_KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

for name in "${NAMES[@]}"; do
  crt="$CLI_DIR/$name.crt"
  [[ -f "$crt" ]] || die "no existe $crt"
  log "[$name] borrando la identidad del llavero"
  security delete-identity -Z "$(sha1_fingerprint "$crt")" "$LOGIN_KEYCHAIN" || true
  security delete-generic-password -a "$USER" -s "pki-local-p12-$name" >/dev/null 2>&1 || true
  ok "[$name] desinstalado"
done
