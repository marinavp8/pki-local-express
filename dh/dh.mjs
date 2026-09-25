#!/usr/bin/env node
// Cifrado de ficheros con Diffie-Hellman (X25519) + HKDF-SHA256 + AES-256-GCM.
//
//   node dh.mjs keygen  <nombre> [dir]                        → <dir>/<nombre>.key (privada) y .pub
//   node dh.mjs encrypt <mi.key> <otro.pub> <entrada> <salida>
//   node dh.mjs decrypt <mi.key> <otro.pub> <entrada> <salida>
//
// DH estático-estático: Alice (su privada + pública de Bob) y Bob (su privada + pública de Alice)
// obtienen el mismo secreto. Cada fichero lleva una sal aleatoria, así que la clave AES es distinta
// en cada cifrado aunque el secreto DH sea siempre el mismo para la pareja.
//
// Formato: "DHF1" (4) | sal (32) | iv (12) | texto cifrado | tag GCM (16). La cabecera va como AAD.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const MAGIC = Buffer.from('DHF1');
const SALT_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const HEADER_LEN = MAGIC.length + SALT_LEN + IV_LEN;

function die(msg) {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
}

function loadKey(file, kind) {
  const pem = fs.readFileSync(file);
  const key = kind === 'private' ? crypto.createPrivateKey(pem) : crypto.createPublicKey(pem);
  if (key.asymmetricKeyType !== 'x25519') die(`${file} no es una clave X25519`);
  return key;
}

// El secreto DH se pasa por HKDF junto con las dos públicas (ordenadas), para atar la clave a la pareja.
function deriveKey(myKeyFile, peerPubFile, salt) {
  const privateKey = loadKey(myKeyFile, 'private');
  const publicKey = loadKey(peerPubFile, 'public');
  const shared = crypto.diffieHellman({ privateKey, publicKey });
  const spki = (k) => k.export({ format: 'der', type: 'spki' });
  const pubs = [spki(crypto.createPublicKey(privateKey)), spki(publicKey)].sort(Buffer.compare);
  const info = Buffer.concat([Buffer.from('24-sep dh-file v1'), ...pubs]);
  return Buffer.from(crypto.hkdfSync('sha256', shared, salt, info, 32));
}

function keygen(name, dir = 'keys') {
  if (!/^[A-Za-z0-9._-]+$/.test(name ?? '')) die('uso: keygen <nombre> [dir]');
  const keyFile = path.join(dir, `${name}.key`);
  const pubFile = path.join(dir, `${name}.pub`);
  if (fs.existsSync(keyFile)) die(`ya existe ${keyFile}`);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  fs.writeFileSync(keyFile, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  fs.writeFileSync(pubFile, publicKey.export({ format: 'pem', type: 'spki' }));
  console.log(`OK ${keyFile} (privada) y ${pubFile} (pública)`);
}

function encrypt(myKey, peerPub, input, output) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const header = Buffer.concat([MAGIC, salt, iv]);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(myKey, peerPub, salt), iv);
  cipher.setAAD(header);
  const body = Buffer.concat([cipher.update(fs.readFileSync(input)), cipher.final()]);
  fs.writeFileSync(output, Buffer.concat([header, body, cipher.getAuthTag()]));
  console.log(`OK ${input} → ${output}`);
}

function decrypt(myKey, peerPub, input, output) {
  const data = fs.readFileSync(input);
  if (data.length < HEADER_LEN + TAG_LEN || !data.subarray(0, MAGIC.length).equals(MAGIC)) {
    die(`${input} no es un fichero DHF1`);
  }
  const header = data.subarray(0, HEADER_LEN);
  const salt = header.subarray(MAGIC.length, MAGIC.length + SALT_LEN);
  const iv = header.subarray(MAGIC.length + SALT_LEN);
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(myKey, peerPub, salt), iv);
  decipher.setAAD(header);
  decipher.setAuthTag(data.subarray(data.length - TAG_LEN));
  let plain;
  try {
    plain = Buffer.concat([decipher.update(data.subarray(HEADER_LEN, data.length - TAG_LEN)), decipher.final()]);
  } catch {
    die(`no se pudo descifrar ${input}: claves incorrectas o fichero alterado`);
  }
  fs.writeFileSync(output, plain);
  console.log(`OK ${input} → ${output}`);
}

const [cmd, ...args] = process.argv.slice(2);
const usage = 'uso: dh.mjs keygen <nombre> [dir] | encrypt|decrypt <mi.key> <otro.pub> <entrada> <salida>';
switch (cmd) {
  case 'keygen':
    keygen(...args);
    break;
  case 'encrypt':
  case 'decrypt':
    if (args.length !== 4) die(usage);
    (cmd === 'encrypt' ? encrypt : decrypt)(...args);
    break;
  default:
    die(usage);
}
