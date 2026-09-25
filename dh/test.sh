#!/usr/bin/env bash
# Prueba del cifrado DH entre Alice y Bob. Crea las claves si faltan y deja los ficheros en dh/prueba/.
source "$(dirname "$0")/../scripts/common.sh"

DH_DIR="$PROJECT_DIR/dh"
KEYS="$DH_DIR/keys"
WORK="$DH_DIR/prueba"
DH=(node "$DH_DIR/dh.mjs")
PASS=0
FAIL=0

check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; PASS=$((PASS + 1))
  else printf '\033[1;31mFAIL\033[0m %s\n' "$name"; FAIL=$((FAIL + 1)); fi
}

for who in alice bob eve; do
  [[ -f "$KEYS/$who.key" ]] || "${DH[@]}" keygen "$who" "$KEYS"
done

rm -rf "$WORK"
mkdir -p "$WORK"
printf 'Hola Bob, soy Alice. %s\n' "$(date)" > "$WORK/mensaje.txt"
head -c 1048576 /dev/urandom > "$WORK/binario.bin"

# El secreto se compara por su hash: nunca se imprime.
secret() { "$OPENSSL" pkeyutl -derive -inkey "$KEYS/$1.key" -peerkey "$KEYS/$2.pub" | shasum -a 256; }
t_same_secret()  { [[ "$(secret alice bob)" == "$(secret bob alice)" ]]; }
t_eve_secret()   { [[ "$(secret alice bob)" != "$(secret eve alice)" ]]; }

t_roundtrip() {
  local f="$1"
  "${DH[@]}" encrypt "$KEYS/alice.key" "$KEYS/bob.pub" "$WORK/$f" "$WORK/$f.dhf" \
    && "${DH[@]}" decrypt "$KEYS/bob.key" "$KEYS/alice.pub" "$WORK/$f.dhf" "$WORK/$f.descifrado" \
    && cmp "$WORK/$f" "$WORK/$f.descifrado"
}
t_reply() {
  printf 'Recibido, Alice.\n' > "$WORK/respuesta.txt"
  "${DH[@]}" encrypt "$KEYS/bob.key" "$KEYS/alice.pub" "$WORK/respuesta.txt" "$WORK/respuesta.txt.dhf" \
    && "${DH[@]}" decrypt "$KEYS/alice.key" "$KEYS/bob.pub" "$WORK/respuesta.txt.dhf" "$WORK/respuesta.descifrada.txt" \
    && cmp "$WORK/respuesta.txt" "$WORK/respuesta.descifrada.txt"
}
t_not_plain()    { [[ -s "$WORK/mensaje.txt.dhf" ]] && ! grep -q 'Hola Bob' "$WORK/mensaje.txt.dhf"; }
t_random_salt()  {
  "${DH[@]}" encrypt "$KEYS/alice.key" "$KEYS/bob.pub" "$WORK/mensaje.txt" "$WORK/otra-vez.dhf" \
    && ! cmp -s "$WORK/mensaje.txt.dhf" "$WORK/otra-vez.dhf"
}
t_eve_fails()    { [[ -s "$WORK/mensaje.txt.dhf" ]] && ! "${DH[@]}" decrypt "$KEYS/eve.key" "$KEYS/alice.pub" "$WORK/mensaje.txt.dhf" "$WORK/eve.txt"; }
t_wrong_peer()   { [[ -s "$WORK/mensaje.txt.dhf" ]] && ! "${DH[@]}" decrypt "$KEYS/bob.key" "$KEYS/eve.pub" "$WORK/mensaje.txt.dhf" "$WORK/eve.txt"; }
t_tampered()     {
  [[ -s "$WORK/mensaje.txt.dhf" ]] || return 1
  cp "$WORK/mensaje.txt.dhf" "$WORK/alterado.dhf"
  printf '\xff' | dd of="$WORK/alterado.dhf" bs=1 seek=60 conv=notrunc 2>/dev/null
  ! "${DH[@]}" decrypt "$KEYS/bob.key" "$KEYS/alice.pub" "$WORK/alterado.dhf" "$WORK/alterado.txt"
}
t_key_perms()    { [[ "$(stat -f '%Lp' "$KEYS/alice.key")" == 600 && "$(stat -f '%Lp' "$KEYS/bob.key")" == 600 ]]; }

log "Prueba DH (X25519 + HKDF-SHA256 + AES-256-GCM) en $WORK"
check "D0  claves privadas con permisos 600"                    t_key_perms
check "D1  OpenSSL: alice·bob.pub == bob·alice.pub"             t_same_secret
check "D1- OpenSSL: el secreto de Eve es distinto"              t_eve_secret
check "D2  Alice → Bob: texto se descifra igual"                t_roundtrip mensaje.txt
check "D2  Alice → Bob: binario de 1 MiB se descifra igual"     t_roundtrip binario.bin
check "D3  Bob → Alice: respuesta se descifra igual"            t_reply
check "D4  el cifrado no contiene el texto en claro"            t_not_plain
check "D4  cifrar dos veces da ficheros distintos (sal)"        t_random_salt
check "D5- Eve no puede descifrar"                              t_eve_fails
check "D5- Bob con la pública equivocada no descifra"           t_wrong_peer
check "D5- un byte alterado se detecta (tag GCM)"               t_tampered

echo
log "Resultado: $PASS OK, $FAIL fallos"
[[ $FAIL -eq 0 ]]
