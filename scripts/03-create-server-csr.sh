#!/usr/bin/env bash
# F3 — Crea la clave y la CSR del servidor (EC P-256, clave sin cifrar).
source "$(dirname "$0")/common.sh"

if [[ -f "$SRV_KEY" && $FORCE -eq 0 ]]; then
  die "ya existe la clave de $SERVER_CN (usa --force para regenerarla)"
fi

mkdir -p "$SRV_DIR"
chmod 700 "$SRV_DIR"

log "Generando clave de $SERVER_CN"
"$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$SRV_KEY"
chmod 600 "$SRV_KEY"

log "Creando CSR ($SERVER_SAN)"
"$OPENSSL" req -config "$CNF_DIR/openssl-intermediate.cnf" -new -sha256 -key "$SRV_KEY" \
  -subj "/C=$ORG_C/O=$ORG_O/CN=$SERVER_CN" -addext "subjectAltName=$SERVER_SAN" -out "$SRV_CSR"

ok "CSR: $SRV_CSR"
"$OPENSSL" req -in "$SRV_CSR" -noout -subject -verify
