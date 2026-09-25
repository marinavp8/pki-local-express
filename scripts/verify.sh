#!/usr/bin/env bash
# Pruebas T1/T2 de la spec contra el servidor en marcha. Con --browser añade T3 (agent-browser).
BROWSER=0
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--browser" ]]; then BROWSER=1; else ARGS+=("$arg"); fi
done
set -- ${ARGS[@]+"${ARGS[@]}"}
source "$(dirname "$0")/common.sh"

PORT="${PORT:-17433}"
URL="https://$SERVER_CN:$PORT"
# Identidad de cliente para mTLS: ficheros para OpenSSL/LibreSSL y nombre en el llavero para SecureTransport.
CLIENT="${CLIENT:-jvh1}"
CLI_CRT="$CLI_DIR/$CLIENT.crt"
CLI_KEY="$CLI_DIR/$CLIENT.key"
MTLS=(-cert "$CLI_CRT" -key "$CLI_KEY" -cert_chain "$INT_CRT")
CURL_MTLS=(--cert "$CLI_CRT" --key "$CLI_KEY")
PASS=0
FAIL=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; PASS=$((PASS + 1))
  else printf '\033[1;31mFAIL\033[0m %s\n' "$name"; FAIL=$((FAIL + 1)); fi
}

t_chain()       { "$OPENSSL" verify -CAfile "$ROOT_CRT" -untrusted "$INT_CRT" -purpose sslserver -verify_hostname "$SERVER_CN" "$SRV_CRT"; }
t_s_client()    {
  "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -servername "$SERVER_CN" -verify_hostname "$SERVER_CN" \
    -CAfile "$ROOT_CRT" "${MTLS[@]}" -showcerts </dev/null 2>/dev/null \
    | tee /dev/stderr | grep -q 'Verify return code: 0 (ok)'
}
t_chain_len()   {
  [[ "$("$OPENSSL" s_client -connect "127.0.0.1:$PORT" -servername "$SERVER_CN" "${MTLS[@]}" -showcerts </dev/null 2>/dev/null \
        | grep -c 'BEGIN CERTIFICATE')" -eq 2 ]]
}
t_tls13()       { "$OPENSSL" s_client -connect "127.0.0.1:$PORT" -servername "$SERVER_CN" "${MTLS[@]}" -tls1_3 </dev/null 2>/dev/null | grep -q 'TLSv1.3'; }
t_curl_cacert() { curl -fsS "${CURL_MTLS[@]}" --cacert "$ROOT_CRT" "$URL/api/health" | grep -q '"status":"ok"'; }
# SecureTransport: confía con el trust store del sistema y toma la identidad del llavero por su nombre.
t_curl_system() { CURL_SSL_BACKEND=secure-transport curl -fsS --cert "$CLIENT" "$URL/api/health" | grep -q '"status":"ok"'; }
t_curl_tls()    { curl -fsS "${CURL_MTLS[@]}" --cacert "$ROOT_CRT" "$URL/api/tls" | grep -q "$INTERMEDIATE_CN"; }
t_negative()    { ! curl -fsS "${CURL_MTLS[@]}" --cacert "$ROOT_CRT" --resolve "otro.localhost:$PORT:127.0.0.1" "https://otro.localhost:$PORT/"; }
t_client_chain() { "$OPENSSL" verify -CAfile "$ROOT_CRT" -untrusted "$INT_CRT" -purpose sslclient "$CLI_CRT"; }
t_whoami()      { curl -fsS "${CURL_MTLS[@]}" --cacert "$ROOT_CRT" "$URL/api/whoami" | grep -q "\"CN\":\"$CLIENT\""; }
t_no_client()   { ! curl -fsS --cacert "$ROOT_CRT" "$URL/api/health"; }
t_srv_as_client() {
  ! curl -fsS --cert "$SRV_CRT" --key "$SRV_KEY" --cacert "$ROOT_CRT" "$URL/api/health"
}

log "Probando $URL (cliente $CLIENT)"
check "T0  cadena válida (openssl verify)"                    t_chain
check "T1  s_client verifica con la raíz"                     t_s_client
check "T1  el servidor envía 2 certificados (srv + int)"      t_chain_len
check "T1  negocia TLSv1.3"                                   t_tls13
check "T2  curl --cacert /api/health"                         t_curl_cacert
check "T2  curl /api/tls emitido por la intermedia"           t_curl_tls
check "T2  curl con el trust store del sistema"               t_curl_system
check "T2- nombre no coincidente es rechazado"                t_negative
check "T4  cert de cliente válido para clientAuth"            t_client_chain
check "T4  /api/whoami identifica a $CLIENT"                  t_whoami
check "T4- sin certificado de cliente es rechazado"           t_no_client
check "T4- el cert de servidor no sirve como cliente"         t_srv_as_client

if [[ $BROWSER -eq 1 ]]; then
  command -v agent-browser >/dev/null || die "agent-browser no está instalado"
  SHOT="$PROJECT_DIR/doc/evidencias/navegador-$(date +%Y%m%d-%H%M%S).png"
  t_browser() {
    agent-browser open "$URL/" \
      && agent-browser get title | grep -qi 'Servidor de pruebas TLS' \
      && agent-browser screenshot "$SHOT" \
      && agent-browser open "$URL/api/tls" \
      && agent-browser get text body | grep -q "$INTERMEDIATE_CN"
  }
  check "T3  navegador carga sin aviso de certificado"          t_browser
  agent-browser close >/dev/null 2>&1 || true
  [[ -f "$SHOT" ]] && log "Captura: $SHOT"
fi

echo
log "Resultado: $PASS OK, $FAIL fallos"
[[ $FAIL -eq 0 ]]
