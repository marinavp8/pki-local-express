# Variables y utilidades compartidas. Se carga con `source` desde cada script.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CNF_DIR="$PROJECT_DIR/pki"
# PKI_DIR permite generar la PKI en otra carpeta (p. ej. para pruebas) sin tocar la real.
export PKI_DIR="${PKI_DIR:-$PROJECT_DIR/pki}"

export SERVER_CN="${SERVER_CN:-www.serverpruebas.localhost}"
export SERVER_SAN="${SERVER_SAN:-DNS:$SERVER_CN}"

ORG_C="ES"
ORG_O="Pruebas Local"
ROOT_CN="Pruebas Local Root CA"
INTERMEDIATE_CN="Pruebas Local Intermediate CA"

ROOT_DIR="$PKI_DIR/root"
INT_DIR="$PKI_DIR/intermediate"
SRV_DIR="$PKI_DIR/server"

ROOT_KEY="$ROOT_DIR/private/root.key"
ROOT_CRT="$ROOT_DIR/certs/root.crt"
INT_KEY="$INT_DIR/private/intermediate.key"
INT_CSR="$INT_DIR/csr/intermediate.csr"
INT_CRT="$INT_DIR/certs/intermediate.crt"
CHAIN_CRT="$INT_DIR/certs/ca-chain.crt"
SRV_KEY="$SRV_DIR/$SERVER_CN.key"
SRV_CSR="$SRV_DIR/$SERVER_CN.csr"
SRV_CRT="$SRV_DIR/$SERVER_CN.crt"
SRV_FULLCHAIN="$SRV_DIR/$SERVER_CN.fullchain.crt"
CLI_DIR="$PKI_DIR/clients"

SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m OK\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *) die "argumento desconocido: $arg" ;;
  esac
done

# Se exige OpenSSL 3 (el /usr/bin/openssl de macOS es LibreSSL).
find_openssl() {
  local c
  for c in "${OPENSSL:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    [[ -n "$c" ]] || continue
    if command -v "$c" >/dev/null 2>&1 && "$c" version 2>/dev/null | grep -q '^OpenSSL 3'; then
      echo "$c"; return 0
    fi
  done
  die "no se encuentra OpenSSL 3 (brew install openssl@3 o exporta OPENSSL=/ruta/openssl)"
}
OPENSSL="$(find_openssl)"

# La passphrase de las CA se pide por consola. PKI_PASSPHRASE solo existe para pruebas automáticas.
if [[ -n "${PKI_PASSPHRASE:-}" ]]; then
  PASSOUT=(-pass env:PKI_PASSPHRASE)  # opción de genpkey
  PASSIN=(-passin env:PKI_PASSPHRASE)
else
  PASSOUT=()
  PASSIN=()
fi

sha1_fingerprint() {
  "$OPENSSL" x509 -in "$1" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':'
}
