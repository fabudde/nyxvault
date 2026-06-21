#!/usr/bin/env node
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// NyxVault — Upload CLI
//
// Encrypts a file CLIENT-SIDE (Argon2id + XSalsa20-Poly1305 via TweetNaCl) and
// uploads only the ciphertext. The server NEVER sees your passphrase or content.
//
// Configuration (environment variables):
//   NYXVAULT_API_KEY     (required)  API key for your NyxVault instance
//   NYXVAULT_URL         (optional)  Base URL, default https://nyxvault.org
//   NYXVAULT_PASSPHRASE  (optional)  Encryption passphrase (or pass as arg 4)
//   NYXVAULT_BURN        (optional)  "1" → burn-after-reading (or pass "burn" as arg 5)
//
// Usage:
//   node nyx-upload.js <file> [expires_in] [passphrase] [burn]
//     <file>        Path to the file to upload
//     [expires_in]  1h | 24h | 7d | 30d | 90m  (optional, default: never)
//     [passphrase]  Encryption passphrase (optional if NYXVAULT_PASSPHRASE set)
//     [burn]        literal "burn" to enable burn-after-reading
//
// Example:
//   NYXVAULT_API_KEY=xxx node nyx-upload.js secret.pdf 24h 'my passphrase' burn
// ─────────────────────────────────────────────────────────────────────────────

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const API_KEY = process.env.NYXVAULT_API_KEY || '';
const BASE_URL = process.env.NYXVAULT_URL || 'https://nyxvault.org';
const PASSPHRASE = process.argv[4] || process.env.NYXVAULT_PASSPHRASE || '';

const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC = Buffer.from('NYX2');  // chunked format magic

async function deriveKey(passphrase, salt) {
  const key = await argon2id({
    password: passphrase,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16 MB
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

// Chunked encryption: NYX2(4) + salt(16) + num_chunks(4 BE) + [nonce(24) + ciphertext]...
async function encryptDataChunked(data, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const numChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));

  const buffers = [];
  const header = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC.copy(header, 0);
  Buffer.from(salt).copy(header, 4);
  header.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  buffers.push(header);

  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunk = data.slice(start, end);
    const nonce = nacl.randomBytes(NONCE_BYTES);
    const enc = nacl.secretbox(new Uint8Array(chunk), nonce, key);
    buffers.push(Buffer.from(nonce));
    buffers.push(Buffer.from(enc));
    process.stdout.write(`\r  Encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(buffers);
}

// Encrypt a short string (filename / content-type) — single-block legacy format
async function encryptString(str, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const key = await deriveKey(passphrase, salt);
  const enc = nacl.secretbox(new TextEncoder().encode(str), nonce, key);
  return Buffer.concat([Buffer.from(salt), Buffer.from(nonce), Buffer.from(enc)]).toString('base64');
}

function postForm(urlStr, form, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const transport = parsed.protocol === 'http:' ? http : https;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path: parsed.pathname,
      method: 'POST',
      headers: { ...form.getHeaders(), ...headers }
    };
    const req = transport.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error(`Non-JSON response (${res.statusCode}): ${body.slice(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    form.pipe(req);
  });
}

async function upload(filePath, expiresIn, burn) {
  if (!API_KEY) {
    console.error('❌ NYXVAULT_API_KEY is not set. Export it before uploading.');
    process.exit(1);
  }
  if (!PASSPHRASE) {
    console.error('❌ No passphrase. Set NYXVAULT_PASSPHRASE or pass it as argument 4.');
    console.error('   Choose a strong, unique passphrase — it is the ONLY thing protecting your file.');
    process.exit(1);
  }

  const fileName = path.basename(filePath);
  const fileData = fs.readFileSync(filePath);

  console.log(`🔐 Encrypting ${fileName} (${fileData.length} bytes)...`);
  const encryptedData = await encryptDataChunked(fileData, PASSPHRASE);

  console.log(`📤 Uploading encrypted blob (${encryptedData.length} bytes)...`);
  const encryptedNameB64 = await encryptString(fileName, PASSPHRASE);
  const encryptedTypeB64 = await encryptString('application/octet-stream', PASSPHRASE);

  const form = new FormData();
  form.append('file', encryptedData, { filename: 'encrypted.bin', contentType: 'application/octet-stream' });
  form.append('uploader', 'cli');
  form.append('filename_enc', encryptedNameB64);
  form.append('content_type_enc', encryptedTypeB64);
  if (expiresIn) form.append('expires_in', expiresIn);
  if (burn) {
    form.append('burn_after_read', '1');
    console.log('🔥 Burn-after-reading enabled — file self-destructs after first decrypt.');
  }

  const result = await postForm(`${BASE_URL}/api/upload`, form, { 'X-Api-Key': API_KEY });

  if (result.download_token) {
    console.log(`\n✅ Upload successful!`);
    console.log(`📎 Download link: ${BASE_URL}/dl/${result.download_token}`);
    if (result.expires_at) console.log(`⏳ Expires at: ${result.expires_at}`);
    if (result.burn_after_read) console.log(`🔥 Self-destructs after first read.`);
    return `${BASE_URL}/dl/${result.download_token}`;
  }
  console.error('❌ Upload failed:', result);
  process.exit(1);
}

const filePath = process.argv[2];
const expiresIn = process.argv[3] && /^\d+\s*[mhd]$/i.test(process.argv[3]) ? process.argv[3] : null;
const burn = process.env.NYXVAULT_BURN === '1' || process.argv[5] === 'burn';

if (!filePath) {
  console.log('NyxVault Upload CLI');
  console.log('Usage: node nyx-upload.js <file> [expires_in: 1h|24h|7d|30d] [passphrase] [burn]');
  console.log('Env:   NYXVAULT_API_KEY (required), NYXVAULT_URL, NYXVAULT_PASSPHRASE, NYXVAULT_BURN');
  process.exit(1);
}
upload(filePath, expiresIn, burn).catch(e => { console.error('❌', e.message); process.exit(1); });
