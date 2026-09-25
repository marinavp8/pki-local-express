import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const here = path.dirname(fileURLToPath(import.meta.url));
const pkiDir = process.env.PKI_DIR ?? path.resolve(here, '../pki');

const HOST = process.env.HOST ?? '127.0.0.1';
const PORT = Number(process.env.PORT ?? 17433);
const SERVER_CN = process.env.SERVER_CN ?? 'www.serverpruebas.localhost';
const KEY_FILE = process.env.TLS_KEY ?? path.join(pkiDir, 'server', `${SERVER_CN}.key`);
const CERT_FILE = process.env.TLS_CERT ?? path.join(pkiDir, 'server', `${SERVER_CN}.fullchain.crt`);
// CAs con las que se validan los certificados de cliente (intermedia + raíz).
const CLIENT_CA_FILE = process.env.TLS_CLIENT_CA ?? path.join(pkiDir, 'intermediate', 'certs', 'ca-chain.crt');

for (const file of [KEY_FILE, CERT_FILE, CLIENT_CA_FILE]) {
  if (!fs.existsSync(file)) {
    console.error(`Falta ${file}. Genera la PKI con scripts/01..04 antes de arrancar.`);
    process.exit(1);
  }
}

const app = express();
app.disable('x-powered-by');

// Datos del certificado que presentó el cliente (el handshake ya lo validó contra la CA).
function clientCert(req) {
  const cert = req.socket.getPeerCertificate();
  return {
    subject: cert.subject,
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    valid_to: cert.valid_to,
    fingerprint256: cert.fingerprint256,
  };
}

app.get('/', (req, res) => {
  const { subject } = clientCert(req);
  res.type('html').send(`<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Servidor de pruebas TLS</title></head>
<body>
  <h1>Servidor de pruebas TLS</h1>
  <p>${SERVER_CN}:${PORT} servido por HTTPS con un certificado de la CA local.</p>
  <p>Cliente autenticado: <strong>${escapeHtml(subject.CN)}</strong></p>
  <ul>
    <li><a href="/api/whoami">/api/whoami</a></li>
    <li><a href="/api/health">/api/health</a></li>
    <li><a href="/api/tls">/api/tls</a></li>
  </ul>
</body>
</html>`);
});

app.get('/api/whoami', (req, res) => {
  res.json(clientCert(req));
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/tls', (req, res) => {
  const socket = req.socket;
  const cert = socket.getCertificate();
  res.json({
    protocol: socket.getProtocol(),
    cipher: socket.getCipher().name,
    servername: socket.servername || null,
    subject: cert.subject,
    issuer: cert.issuer,
    subjectaltname: cert.subjectaltname,
    valid_from: cert.valid_from,
    valid_to: cert.valid_to,
    fingerprint256: cert.fingerprint256,
    client: clientCert(req),
  });
});

function escapeHtml(text = '') {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

const server = https.createServer(
  {
    key: fs.readFileSync(KEY_FILE),
    cert: fs.readFileSync(CERT_FILE),
    minVersion: 'TLSv1.2',
    // mTLS: sin un certificado de cliente emitido por nuestra CA el handshake se rechaza.
    ca: fs.readFileSync(CLIENT_CA_FILE),
    requestCert: true,
    rejectUnauthorized: true,
  },
  app,
);

server.on('tlsClientError', (err, socket) => {
  console.warn(`TLS rechazado desde ${socket.remoteAddress}: ${err.code ?? err.message}`);
});

server.on('error', (err) => {
  console.error(`No se pudo arrancar en ${HOST}:${PORT}: ${err.message}`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log(`Escuchando en https://${SERVER_CN}:${PORT} (${HOST})`);
});
