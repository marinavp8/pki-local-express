#!/usr/bin/env bash
# F1 — Crea la CA raíz (EC P-256, clave cifrada, 10 años).
source "$(dirname "$0")/common.sh"

if [[ -f "$ROOT_KEY" && $FORCE -eq 0 ]]; then
  die "la CA raíz ya existe en $ROOT_DIR (usa --force para regenerarla; invalida toda la PKI)"
fi
[[ $FORCE -eq 1 ]] && rm -rf "$ROOT_DIR"

log "Preparando $ROOT_DIR"
mkdir -p "$ROOT_DIR"/{certs,newcerts,private}
chmod 700 "$ROOT_DIR/private"
: > "$ROOT_DIR/index.txt"
"$OPENSSL" rand -hex 16 > "$ROOT_DIR/serial"

log "Generando clave de la raíz (se pedirá passphrase)"
"$OPENSSL" genpkey -out "$ROOT_KEY" ${PASSOUT[@]+"${PASSOUT[@]}"} -aes-256-cbc \
  -algorithm EC -pkeyopt ec_paramgen_curve:P-256
chmod 600 "$ROOT_KEY"

log "Autofirmando el certificado raíz"
"$OPENSSL" req -config "$CNF_DIR/openssl-root.cnf" -new -x509 -sha256 -days 3650 \
  -key "$ROOT_KEY" ${PASSIN[@]+"${PASSIN[@]}"} -extensions v3_ca \
  -subj "/C=$ORG_C/O=$ORG_O/CN=$ROOT_CN" -out "$ROOT_CRT"

ok "CA raíz: $ROOT_CRT"
"$OPENSSL" x509 -in "$ROOT_CRT" -noout -subject -dates -fingerprint -sha256
