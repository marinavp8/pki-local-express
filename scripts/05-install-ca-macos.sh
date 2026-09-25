#!/usr/bin/env bash
# F6 — Instala la CA raíz como ancla de confianza en el System keychain (requiere sudo).
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
[[ -f "$ROOT_CRT" ]] || die "no existe $ROOT_CRT"

SHA1="$(sha1_fingerprint "$ROOT_CRT")"
if security find-certificate -a -Z "$SYSTEM_KEYCHAIN" 2>/dev/null | grep -q "SHA-1 hash: $SHA1"; then
  log "La raíz ya está en el System keychain; se reaplica la confianza"
fi

log "Instalando $ROOT_CN en $SYSTEM_KEYCHAIN (sudo; macOS puede pedir confirmación gráfica)"
sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic -k "$SYSTEM_KEYCHAIN" "$ROOT_CRT"

if [[ -f "$SRV_CRT" ]]; then
  log "Verificando el certificado de servidor contra el trust store del sistema"
  security verify-cert -c "$SRV_CRT" -c "$INT_CRT" -p ssl -s "$SERVER_CN"
fi
ok "CA raíz instalada y confiable (SHA-1 $SHA1)"
