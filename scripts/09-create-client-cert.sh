#!/usr/bin/env bash
# F7 — Certificado de cliente (mTLS) firmado por la intermedia: clave EC P-256, CSR, cert y .p12.
# Uso: 09-create-client-cert.sh [--force] <nombre>...   (el nombre va en el CN)
NAMES=(); FLAGS=()
for arg in "$@"; do
  if [[ "$arg" == --* ]]; then FLAGS+=("$arg"); else NAMES+=("$arg"); fi
done
set -- ${FLAGS[@]+"${FLAGS[@]}"}
source "$(dirname "$0")/common.sh"

[[ ${#NAMES[@]} -gt 0 ]] || die "uso: $0 [--force] <nombre>..."
[[ -f "$INT_CRT" ]] || die "no existe la CA intermedia; ejecuta 02-create-intermediate-ca.sh"
mkdir -p "$CLI_DIR"
chmod 700 "$CLI_DIR"

for name in "${NAMES[@]}"; do
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || die "nombre no válido: $name"
  key="$CLI_DIR/$name.key" csr="$CLI_DIR/$name.csr" crt="$CLI_DIR/$name.crt" p12="$CLI_DIR/$name.p12"
  if [[ -f "$crt" && $FORCE -eq 0 ]]; then
    die "ya existe $crt (usa --force para volver a emitirlo)"
  fi

  log "[$name] clave y CSR"
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$key"
  chmod 600 "$key"
  "$OPENSSL" req -config "$CNF_DIR/openssl-intermediate.cnf" -new -sha256 -key "$key" \
    -subj "/C=$ORG_C/O=$ORG_O/CN=$name" -out "$csr"

  log "[$name] firmando con la intermedia (se pedirá la passphrase de la intermedia)"
  "$OPENSSL" ca -config "$CNF_DIR/openssl-intermediate.cnf" -batch -notext -md sha256 -days 397 \
    -extensions client_cert ${PASSIN[@]+"${PASSIN[@]}"} -in "$csr" -out "$crt"
  "$OPENSSL" verify -CAfile "$ROOT_CRT" -untrusted "$INT_CRT" -purpose sslclient "$crt"

  # La contraseña del .p12 se genera aquí y se guarda en el llavero de inicio de sesión, nunca en disco.
  P12_PASS="$("$OPENSSL" rand -base64 24)"
  security add-generic-password -U -a "$USER" -s "pki-local-p12-$name" -w "$P12_PASS"
  P12_PASS="$P12_PASS" "$OPENSSL" pkcs12 -export -inkey "$key" -in "$crt" -certfile "$INT_CRT" \
    -name "$name" -passout env:P12_PASS -out "$p12"
  chmod 600 "$p12"
  unset P12_PASS

  ok "[$name] $crt"
  "$OPENSSL" x509 -in "$crt" -noout -subject -issuer -dates -ext extendedKeyUsage
done
