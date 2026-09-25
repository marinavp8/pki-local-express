#!/usr/bin/env bash
# F2 — Crea la CA intermedia firmada por la raíz (EC P-256, clave cifrada, 5 años, nameConstraints).
source "$(dirname "$0")/common.sh"

[[ -f "$ROOT_CRT" ]] || die "no existe la CA raíz; ejecuta 01-create-root-ca.sh"
if [[ -f "$INT_KEY" && $FORCE -eq 0 ]]; then
  die "la CA intermedia ya existe en $INT_DIR (usa --force para regenerarla)"
fi
[[ $FORCE -eq 1 ]] && rm -rf "$INT_DIR"

log "Preparando $INT_DIR"
mkdir -p "$INT_DIR"/{certs,csr,newcerts,private}
chmod 700 "$INT_DIR/private"
: > "$INT_DIR/index.txt"
"$OPENSSL" rand -hex 16 > "$INT_DIR/serial"

log "Generando clave de la intermedia (se pedirá passphrase)"
"$OPENSSL" genpkey -out "$INT_KEY" ${PASSOUT[@]+"${PASSOUT[@]}"} -aes-256-cbc \
  -algorithm EC -pkeyopt ec_paramgen_curve:P-256
chmod 600 "$INT_KEY"

log "Creando CSR de la intermedia"
"$OPENSSL" req -config "$CNF_DIR/openssl-intermediate.cnf" -new -sha256 \
  -key "$INT_KEY" ${PASSIN[@]+"${PASSIN[@]}"} \
  -subj "/C=$ORG_C/O=$ORG_O/CN=$INTERMEDIATE_CN" -out "$INT_CSR"

log "Firmando la intermedia con la raíz (se pedirá la passphrase de la raíz)"
"$OPENSSL" ca -config "$CNF_DIR/openssl-root.cnf" -batch -notext -md sha256 -days 1825 \
  -extensions v3_intermediate_ca ${PASSIN[@]+"${PASSIN[@]}"} \
  -in "$INT_CSR" -out "$INT_CRT"

cat "$INT_CRT" "$ROOT_CRT" > "$CHAIN_CRT"
"$OPENSSL" verify -CAfile "$ROOT_CRT" "$INT_CRT"
ok "CA intermedia: $INT_CRT (cadena: $CHAIN_CRT)"
