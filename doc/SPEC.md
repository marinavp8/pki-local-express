# Spec — PKI local con OpenSSL + servidor HTTPS Express

> Origen: `IDEAS.md`. Estado: v1 implementada (2026-09-24).

## 1. Objetivo

Montar una autoridad de certificación (CA) propia con OpenSSL, emitir un certificado de servidor para
`www.serverpruebas.localhost`, servir un API Express por HTTPS en el puerto **17433** y conseguir que el
Mac (navegador y `curl`) confíe en él sin avisos, instalando la CA raíz en el llavero del sistema.

**Fuera de alcance:** CRL/OCSP operativos, renovación automática,
despliegue fuera de la máquina local.

## 2. Decisiones

| Tema | Decisión | Motivo |
|---|---|---|
| Jerarquía | CA raíz → CA intermedia → servidor | Realista: la raíz solo firma la intermedia. |
| Algoritmo | ECDSA **P-256** + SHA-256 en todos los niveles | Moderno, soportado por macOS, Chrome, curl y Node. |
| Validez | Raíz 10 años · intermedia 5 años · servidor **397 días** | macOS rechaza certificados TLS de larga duración. |
| Claves de CA | Cifradas con AES-256 y passphrase pedida por consola (no se guarda en disco ni en `.env`) | Las claves de CA son el activo crítico. |
| Clave servidor | Sin cifrar, `chmod 600` | Node la carga al arrancar sin interacción. |
| Trust store | **System keychain** (`/Library/Keychains/System.keychain`, requiere `sudo`) | Decisión del usuario: confianza para todos los usuarios del Mac. |
| Restricción de nombres | La intermedia lleva `nameConstraints` limitados a `localhost` / `.localhost` / loopback | Como la raíz se confía a nivel de sistema, limita el daño si se filtra la intermedia. |
| Runtime | Node 24 LTS, Express 5, módulo `node:https` | Versión actual por defecto. |
| Automatización | Scripts bash numerados + `npm run` | Reproducible e idempotente. |

## 3. Estructura del proyecto

```
.
├── doc/SPEC.md
├── IDEAS.md
├── pki/
│   ├── openssl-root.cnf
│   ├── openssl-intermediate.cnf
│   ├── root/          # certs/ private/ newcerts/ index.txt serial
│   ├── intermediate/  # certs/ private/ csr/ newcerts/ index.txt serial
│   └── server/        # www.serverpruebas.localhost.{key,csr,crt,fullchain.crt}
├── scripts/
│   ├── 01-create-root-ca.sh
│   ├── 02-create-intermediate-ca.sh
│   ├── 03-create-server-csr.sh
│   ├── 04-sign-server-cert.sh
│   ├── 05-install-ca-macos.sh
│   ├── 06-uninstall-ca-macos.sh
│   └── verify.sh
├── server/
│   ├── package.json
│   └── index.js
└── .gitignore         # pki/**/private/, *.key, *.csr, index.txt*, serial*
```

`private/` con permisos `700`; claves con `600`.

## 4. Funciones

### F1 — Crear la CA raíz (`01-create-root-ca.sh`)

- Clave: `openssl genpkey -aes-256-cbc -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
- Certificado autofirmado, 3650 días.
- Subject: `/C=ES/O=Pruebas Local/CN=Pruebas Local Root CA`.
- Extensiones (`v3_ca`):
  - `basicConstraints = critical, CA:true`
  - `keyUsage = critical, keyCertSign, cRLSign`
  - `subjectKeyIdentifier = hash`
- Idempotente: si ya existe la clave, aborta sin sobrescribir (salvo `--force`).

### F2 — Crear la CA intermedia (`02-create-intermediate-ca.sh`)

- Clave EC P-256 cifrada; CSR firmada por la raíz con `openssl ca` (base de datos `index.txt`/`serial`), 1825 días.
- Subject: `/C=ES/O=Pruebas Local/CN=Pruebas Local Intermediate CA`.
- Extensiones (`v3_intermediate_ca`):
  - `basicConstraints = critical, CA:true, pathlen:0`
  - `keyUsage = critical, keyCertSign, cRLSign`
  - `nameConstraints = critical, permitted;DNS:localhost, permitted;IP:127.0.0.0/255.0.0.0, permitted;IP:::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff`
  - `authorityKeyIdentifier = keyid:always`
- Genera `intermediate/certs/ca-chain.crt` (intermedia + raíz).

### F3 — Request del certificado de servidor (`03-create-server-csr.sh`)

- Clave EC P-256 sin cifrar.
- CSR con subject `/C=ES/O=Pruebas Local/CN=www.serverpruebas.localhost`.
- SAN obligatorio (los navegadores ignoran el CN):
  `DNS:www.serverpruebas.localhost`

### F4 — Obtener el certificado de servidor (`04-sign-server-cert.sh`)

- La **intermedia** firma la CSR, 397 días.
- Extensiones (`server_cert`):
  - `basicConstraints = critical, CA:false`
  - `keyUsage = critical, digitalSignature`
  - `extendedKeyUsage = serverAuth`
  - `subjectAltName` fijado por la CA desde `SERVER_SAN` (`copy_extensions = none`: no se confía en lo que pida la CSR)
  - `authorityKeyIdentifier = keyid,issuer`
- Salidas: `server/…crt` y `…fullchain.crt` (servidor + intermedia, **sin** la raíz).
- Verificación inmediata: `openssl verify -CAfile root.crt -untrusted intermediate.crt server.crt` → `OK`.

### F5 — API Express HTTPS (`server/index.js`)

- `https.createServer({ key, cert: fullchain, minVersion: 'TLSv1.2' }, app)`.
- Escucha en `127.0.0.1:17433` (configurable por `PORT`/`HOST`).
- Rutas de certificado configurables por variables de entorno con valores por defecto a `pki/server/`.
- Endpoints:

| Método | Ruta | Respuesta |
|---|---|---|
| GET | `/` | HTML simple: "Servidor de pruebas TLS" + hostname. |
| GET | `/api/health` | `200 {"status":"ok"}` |
| GET | `/api/tls` | `200` JSON con `protocol`, `cipher`, `servername` (SNI), `subject`, `issuer`, `subjectaltname`, `valid_from`, `valid_to`, `fingerprint256` del certificado servido. |

- **mTLS obligatorio**: `requestCert: true`, `rejectUnauthorized: true`, `ca: intermediate/certs/ca-chain.crt`
  (`TLS_CLIENT_CA`). Sin certificado de cliente de nuestra CA con `clientAuth` el handshake falla
  (alerta TLS 116 `certificate required`). `/` muestra el CN del cliente y `GET /api/whoami` devuelve su certificado.
- Arranque: `npm start` en `server/`. Error claro si faltan los ficheros de certificado.

### F6 — Instalar la CA en el Mac (`05-install-ca-macos.sh`)

- Solo se instala la **raíz** como ancla de confianza:
  `sudo security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain pki/root/certs/root.crt`
- macOS puede pedir además autenticación gráfica para cambiar la configuración de confianza.
- Comprobación: `security verify-cert -c pki/server/…crt -p ssl -s www.serverpruebas.localhost` → éxito.
- Desinstalación (`06-uninstall-ca-macos.sh`): `security remove-trusted-cert -d` + `security delete-certificate -c "Pruebas Local Root CA" /Library/Keychains/System.keychain`.

### F7 — Certificados de cliente (`09-create-client-cert.sh <nombre>...`)

- Emitidos: `jvh1`, `jvh2`. Clave EC P-256 sin cifrar (`600`), subject `/C=ES/O=Pruebas Local/CN=<nombre>`,
  firmados por la intermedia, 397 días, extensiones `client_cert`:
  `basicConstraints = critical, CA:false`, `keyUsage = critical, digitalSignature`, `extendedKeyUsage = clientAuth`.
- Salidas en `pki/clients/`: `.key`, `.csr`, `.crt` y `.p12` (clave + cert + intermedia).
- La contraseña del `.p12` se genera con `openssl rand` y solo vive en el llavero de inicio de sesión
  (servicio `pki-local-p12-<nombre>`).

### F8 — Identidades en el llavero (`10-install-client-macos.sh` / `11-uninstall-client-macos.sh`)

- `security import` del `.p12` en el llavero de **inicio de sesión** (`-T /usr/bin/curl`: curl usa la clave sin diálogo;
  Chrome/Safari piden permiso la primera vez). Idempotente.
- macOS no lista la identidad como "válida" (`find-identity -v`) por los `nameConstraints` de la intermedia;
  no afecta, quien valida el certificado es el servidor.
- `curl` de macOS usa LibreSSL por defecto; para tomar la identidad del llavero:
  `CURL_SSL_BACKEND=secure-transport curl --cert jvh1 https://www.serverpruebas.localhost:17433/api/whoami`.

## 5. Resolución de nombres

`*.localhost` resuelve a loopback de forma nativa en Chrome/Chromium y en curl ≥ 7.78, así que no hace
falta tocar `/etc/hosts`. Si alguna herramienta no lo resuelve, se añade
`127.0.0.1 www.serverpruebas.localhost` a `/etc/hosts` (documentado, no automático).

## 6. Pruebas

### T1 — Cadena con OpenSSL
```bash
openssl s_client -connect 127.0.0.1:17433 -servername www.serverpruebas.localhost \
  -CAfile pki/root/certs/root.crt </dev/null
```
Esperado: `Verify return code: 0 (ok)`, cadena de 2 certificados servida, TLSv1.3.

### T2 — curl
```bash
curl --cacert pki/root/certs/root.crt https://www.serverpruebas.localhost:17433/api/health   # determinista
curl https://www.serverpruebas.localhost:17433/api/health                                   # usando el trust store
curl -s https://www.serverpruebas.localhost:17433/api/tls | jq
```
Esperado: `{"status":"ok"}` sin `-k`. El `curl` de macOS (`/usr/bin/curl`) usa SecureTransport y consulta el
llavero, así que el segundo comando solo pasa después de F6.

Con mTLS todas las llamadas llevan `--cert pki/clients/jvh1.crt --key pki/clients/jvh1.key` (o `-cert/-key` en `s_client`).

Negativo: `curl --cacert root.crt --resolve otro.localhost:17433:127.0.0.1 https://otro.localhost:17433/`
debe fallar por nombre no coincidente.

### T3 — Navegador con agent-browser
1. Abrir `https://www.serverpruebas.localhost:17433/`.
2. Comprobar que carga sin interstitial de seguridad (sin `NET::ERR_CERT_*`).
3. Captura de pantalla en `doc/evidencias/`.
4. Abrir `/api/tls` y verificar `issuer` = Pruebas Local Intermediate CA.

### T4 — mTLS
- `openssl verify -purpose sslclient` del certificado de cliente → `OK`.
- `/api/whoami` devuelve el CN del cliente (`CLIENT=jvh2 npm run verify` para probar el otro).
- Sin certificado de cliente → rechazado; el certificado de servidor (`serverAuth`) no sirve como cliente.

T3 (navegador) requiere elegir el certificado en el diálogo de Chrome/Safari.

### Criterios de aceptación
- [x] `openssl verify` de la cadena devuelve `OK`.
- [x] T1, T2 (con `--cacert`) y T3 pasan.
- [x] La raíz aparece como confiable en Acceso a Llaveros → Sistema.
- [x] Ninguna clave privada queda fuera de `pki/**/private` o `pki/server` ni entra en git.
- [x] Los scripts se pueden re-ejecutar sin romper la PKI existente.
- [x] La desinstalación deja el llavero como estaba.

## 7. Seguridad

- La raíz confiada en el System keychain permite a quien tenga su clave suplantar cualquier web en
  este Mac: passphrase fuerte y desinstalar al acabar las pruebas.
- `nameConstraints` en la intermedia limita lo que puede emitir; la clave raíz sigue siendo crítica.
- No se reutilizan claves ni certificados en otros entornos.

## 8. Uso

Requisitos: OpenSSL 3 (Homebrew; el `/usr/bin/openssl` de macOS es LibreSSL y se rechaza), Node 24, `jq`, `agent-browser`.

```bash
npm --prefix server install
npm run pki:root            # pide passphrase nueva de la raíz
npm run pki:intermediate    # pide passphrase nueva de la intermedia y la de la raíz
npm run pki:server-csr
npm run pki:server-cert     # pide la passphrase de la intermedia
npm run ca:install          # sudo
npm start                   # en otra terminal
npm run verify              # T0–T2
npm run verify:browser      # T0–T3 con captura en doc/evidencias/
npm run client:create -- jvh1 jvh2   # pide la passphrase de la intermedia
npm run client:install -- jvh1 jvh2  # llavero de inicio de sesión
npm run port443:on          # opcional, sudo: https://www.serverpruebas.localhost/ (pf 443 → 17433)
npm run port443:off         # quita la redirección
npm run client:uninstall -- jvh1 jvh2
npm run ca:uninstall        # al terminar
```

Variables: `PKI_DIR` (PKI alternativa, p. ej. para pruebas), `SERVER_CN`, `SERVER_SAN`, `PORT`, `HOST`,
`TLS_KEY`, `TLS_CERT`, `TLS_CLIENT_CA`, `CLIENT` (verify.sh), `OPENSSL`. `PKI_PASSPHRASE` evita los prompts y es **solo para pruebas automáticas**.

Passphrase de las CA: está en el llavero de inicio de sesión (servicio `pki-local-ca-24sep`). Para firmar sin prompts:
`PKI_PASSPHRASE="$(security find-generic-password -a "$USER" -s pki-local-ca-24sep -w)" npm run pki:server-cert -- --force`.

Renovar el certificado de servidor: `scripts/04-sign-server-cert.sh --force` (o `03 --force` + `04 --force` para rotar la clave).

## 9. Dudas abiertas (se aplica el valor por defecto mientras no se decida)

1. SAN adicionales (`serverpruebas.localhost`, `localhost`, `127.0.0.1`) → por ahora solo `www`.
2. Cliente Node con `node --use-system-ca` → no incluido.
3. CRL de la intermedia y prueba de revocación → fuera de alcance.
4. Versionado en git → `.gitignore` preparado; sin repo.
