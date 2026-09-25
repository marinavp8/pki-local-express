# pki-local-express

PKI local con OpenSSL (CA raíz + intermedia), servidor HTTPS Express que exige certificado de cliente
(mTLS) y cifrado de ficheros con Diffie-Hellman (X25519). Pensado para pruebas en macOS.

La especificación completa está en [`doc/SPEC.md`](doc/SPEC.md).

## Qué incluye

| Parte | Qué hace |
|---|---|
| `scripts/01..04` | CA raíz → CA intermedia → certificado de servidor para `www.serverpruebas.localhost` (EC P-256). |
| `scripts/05..06` | Instala / desinstala la CA raíz en el System keychain del Mac. |
| `scripts/07..08` | Redirección opcional `127.0.0.1:443 → 17433` con `pf` (el servidor no corre como root). |
| `scripts/09..11` | Certificados de cliente (`clientAuth`) y su importación en el llavero de inicio de sesión. |
| `server/` | API Express por HTTPS en `127.0.0.1:17433` con mTLS obligatorio. |
| `dh/` | Cifrado de ficheros entre dos claves X25519 (HKDF-SHA256 + AES-256-GCM). |

La intermedia lleva `nameConstraints` limitados a `localhost` / `.localhost` / loopback, así que aunque la
raíz esté confiada en el sistema no puede emitir certificados válidos para dominios reales.

## Requisitos

- macOS
- OpenSSL 3 (`brew install openssl@3`; el `/usr/bin/openssl` de macOS es LibreSSL y se rechaza)
- Node 24, `jq`
- `agent-browser` (solo para la prueba de navegador)

## Puesta en marcha

```bash
npm --prefix server install

npm run pki:root                     # pide passphrase nueva de la raíz
npm run pki:intermediate             # pide passphrase nueva de la intermedia y la de la raíz
npm run pki:server-csr
npm run pki:server-cert              # pide la passphrase de la intermedia
npm run ca:install                   # sudo

npm run client:create -- jvh1 jvh2   # pide la passphrase de la intermedia
npm run client:install -- jvh1 jvh2  # llavero de inicio de sesión

npm start                            # en otra terminal
npm run verify                       # pruebas T0–T4 (CLIENT=jvh2 npm run verify para el otro cliente)
```

Opcional, para usar `https://www.serverpruebas.localhost/` sin puerto:

```bash
npm run port443:on    # sudo; se pierde al reiniciar
npm run port443:off
```

## Llamar al servidor

Sin certificado de cliente el handshake se rechaza (alerta TLS 116, `certificate required`).

```bash
# Con los ficheros del cliente
curl --cert pki/clients/jvh1.crt --key pki/clients/jvh1.key \
  https://www.serverpruebas.localhost:17433/api/whoami

# Con la identidad del llavero (el curl de macOS usa LibreSSL por defecto)
CURL_SSL_BACKEND=secure-transport curl --cert jvh1 \
  https://www.serverpruebas.localhost:17433/api/whoami
```

| Ruta | Respuesta |
|---|---|
| `GET /` | HTML con el CN del cliente autenticado |
| `GET /api/health` | `{"status":"ok"}` |
| `GET /api/whoami` | Certificado del cliente (subject, issuer, serie, huella) |
| `GET /api/tls` | Protocolo, cifrado, SNI, certificado del servidor y del cliente |

En Chrome o Safari aparece un diálogo para elegir el certificado (jvh1 o jvh2) y, la primera vez, macOS pide
permiso para usar la clave.

## Cifrado de ficheros con DH (`dh/`)

```bash
node dh/dh.mjs keygen alice dh/keys
node dh/dh.mjs keygen bob dh/keys

node dh/dh.mjs encrypt dh/keys/alice.key dh/keys/bob.pub   fichero      fichero.dhf  # Alice → Bob
node dh/dh.mjs decrypt dh/keys/bob.key   dh/keys/alice.pub fichero.dhf  fichero      # Bob descifra

npm run dh:test   # prueba completa en dh/prueba/
```

- Alice (su privada + pública de Bob) y Bob (su privada + pública de Alice) obtienen el mismo secreto X25519.
- Cada fichero usa una sal aleatoria en HKDF, así que la clave AES cambia en cada cifrado.
- Formato: `DHF1` (4) | sal (32) | iv (12) | texto cifrado | tag GCM (16). La cabecera se autentica como AAD.
- Limitaciones: cualquiera de los dos puede descifrar lo que cifró, no hay *forward secrecy* y el fichero se
  procesa entero en memoria.

## Seguridad

- Las claves privadas, CSR, `.p12` y todo `pki/` (salvo los `.cnf`) están en `.gitignore`.
- Las claves de CA van cifradas con AES-256 y passphrase; la contraseña de cada `.p12` se genera al crearlo y
  solo se guarda en el llavero.
- Con la raíz confiada en el sistema, quien tenga su clave puede suplantar webs `*.localhost` en este Mac:
  desinstalarla al terminar.

```bash
npm run client:uninstall -- jvh1 jvh2
npm run ca:uninstall
```
