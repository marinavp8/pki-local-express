#!/usr/bin/env bash
# Elimina la CA raíz del System keychain y su configuración de confianza (requiere sudo).
source "$(dirname "$0")/common.sh"

[[ "$(uname)" == "Darwin" ]] || die "solo para macOS"
[[ -f "$ROOT_CRT" ]] || die "no existe $ROOT_CRT"

SHA1="$(sha1_fingerprint "$ROOT_CRT")"
log "Quitando la confianza de $ROOT_CN"
sudo security remove-trusted-cert -d "$ROOT_CRT" || true
log "Borrando el certificado del System keychain"
sudo security delete-certificate -Z "$SHA1" "$SYSTEM_KEYCHAIN" || true

if security find-certificate -a -Z "$SYSTEM_KEYCHAIN" 2>/dev/null | grep -q "SHA-1 hash: $SHA1"; then
  die "la raíz sigue en el System keychain"
fi
ok "CA raíz desinstalada"
