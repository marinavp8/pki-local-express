#!/usr/bin/env bash
# F8 — Importa la identidad (clave + certificado) de cada cliente en el llavero de inicio de sesión.
# Uso: 10-install-client-macos.sh <nombre>...
NAMES=("$@"); set --
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
[[ ${#NAMES[@]} -gt 0 ]] || die "uso: $0 <nombre>..."
LOGIN_KEYCHAIN="$HOME/Library/Keychains/login.keychain-db"

for name in "${NAMES[@]}"; do
  p12="$CLI_DIR/$name.p12"
  [[ -f "$p12" ]] || die "no existe $p12; ejecuta 09-create-client-cert.sh $name"
  if security find-identity "$LOGIN_KEYCHAIN" | grep -q "\"$name\""; then
    ok "[$name] ya está en el llavero"; continue
  fi
  pass="$(security find-generic-password -a "$USER" -s "pki-local-p12-$name" -w)"
  log "[$name] importando $p12 en el llavero de inicio de sesión"
  # -T: curl puede usar la clave sin diálogo; el resto de apps (Chrome, Safari) pedirán permiso.
  security import "$p12" -k "$LOGIN_KEYCHAIN" -f pkcs12 -P "$pass" -T /usr/bin/curl
  # Sin -v: macOS no da la identidad por "válida" (nameConstraints de la intermedia), pero quien valida es el servidor.
  security find-identity "$LOGIN_KEYCHAIN" | grep -q "\"$name\"" \
    || die "[$name] la identidad no aparece en el llavero"
  ok "[$name] identidad instalada (curl --cert $name ...)"
done
