#!/usr/bin/env bash
# F4 — La intermedia firma la CSR del servidor (397 días) y se genera el fullchain.
source "$(dirname "$0")/common.sh"

[[ -f "$INT_CRT" ]] || die "no existe la CA intermedia; ejecuta 02-create-intermediate-ca.sh"
[[ -f "$SRV_CSR" ]] || die "no existe la CSR; ejecuta 03-create-server-csr.sh"
if [[ -f "$SRV_CRT" && $FORCE -eq 0 ]]; then
  die "ya existe $SRV_CRT (usa --force para volver a emitirlo)"
fi

log "Firmando $SERVER_CN con la intermedia (se pedirá la passphrase de la intermedia)"
"$OPENSSL" ca -config "$CNF_DIR/openssl-intermediate.cnf" -batch -notext -md sha256 -days 397 \
  -extensions server_cert ${PASSIN[@]+"${PASSIN[@]}"} -in "$SRV_CSR" -out "$SRV_CRT"

cat "$SRV_CRT" "$INT_CRT" > "$SRV_FULLCHAIN"

"$OPENSSL" verify -CAfile "$ROOT_CRT" -untrusted "$INT_CRT" -purpose sslserver \
  -verify_hostname "$SERVER_CN" "$SRV_CRT"
ok "Certificado: $SRV_CRT"
ok "Fullchain:   $SRV_FULLCHAIN"
"$OPENSSL" x509 -in "$SRV_CRT" -noout -subject -issuer -dates -ext subjectAltName
