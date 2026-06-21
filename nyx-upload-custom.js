#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');

const API_KEY = process.env.NYXVAULT_API_KEY || '252f5a810e5e58b17b97e00a4ac38daa43e5cf48b321ab3687d7b714e5d23752';
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC = Buffer.from('NYX2');

async function deriveKey(passphrase, salt) {
  const key = await argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16MB (was 64MB)
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

// Chunked encryption
async function encryptDataChunked(data, passphrase) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const numChunks = Math.ceil(data.length / CHUNK_SIZE);

  const chunkBuffers = [];

  // Header
  const header = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC.copy(header, 0);
  salt.copy(header, 4);
  header.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  chunkBuffers.push(header);

  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunk = data.slice(start, end);
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const encrypted = nacl.secretbox(new Uint8Array(chunk), nonce, key);
    chunkBuffers.push(Buffer.from(nonce));
    chunkBuffers.push(Buffer.from(encrypted));
    process.stdout.write(`\r  Encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');

  return Buffer.concat(chunkBuffers);
}

// Legacy string encryption for metadata
async function encryptStringLegacy(str, passphrase) {
  const salt = crypto.randomBytes(SALT_BYTES);
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const key = await deriveKey(passphrase, salt);
  const encrypted = nacl.secretbox(new TextEncoder().encode(str), nonce, key);
  return Buffer.concat([salt, nonce, Buffer.from(encrypted)]).toString('base64');
}

async function upload(filePath, passphrase, expiry) {
  const fileData = fs.readFileSync(filePath);
  const filename = path.basename(filePath);
  console.log(`🔐 Encrypting ${filename} (${fileData.length} bytes)...`);
  
  const encrypted = await encryptDataChunked(fileData, passphrase);
  console.log(`✅ Encrypted (${encrypted.length} bytes)`);
  
  // Build multipart form data
  const boundary = '----NyxVaultUpload' + crypto.randomBytes(8).toString('hex');
  const parts = [];
  
  // File part
  parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`);
  parts.push(encrypted);
  parts.push('\r\n');
  
  // Encrypt metadata with legacy format
  const fnB64 = await encryptStringLegacy(filename, passphrase);
  const ctB64 = await encryptStringLegacy('application/octet-stream', passphrase);

  parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="filename_enc"\r\n\r\n${fnB64}\r\n`);
  parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="content_type_enc"\r\n\r\n${ctB64}\r\n`);
  
  if (expiry) {
    parts.push(`--${boundary}\r\nContent-Disposition: form-data; name="expiry"\r\n\r\n${expiry}\r\n`);
  }
  
  parts.push(`--${boundary}--\r\n`);
  
  const body = Buffer.concat(parts.map(p => typeof p === 'string' ? Buffer.from(p) : p));
  
  console.log(`📤 Uploading (${(body.length / 1024 / 1024).toFixed(1)} MB)...`);

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'nyxvault.org',
      path: '/api/upload',
      method: 'POST',
      headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': body.length,
        'X-Api-Key': API_KEY
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json);
        } catch(e) {
          reject(new Error(`Parse error: ${data}`));
        }
      });
    });
    
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function main() {
  const filePath = process.argv[2];
  const passphrase = process.argv[3];
  const expiry = process.argv[4] || 'never';
  
  if (!filePath || !passphrase) {
    console.log('Usage: node nyx-upload-custom.js <file> <passphrase> [expiry: 1h|24h|7d|30d|never]');
    process.exit(1);
  }
  
  console.log(`📤 Uploading to NyxVault (expiry: ${expiry})...`);
  const result = await upload(filePath, passphrase, expiry);
  
  if (result.token || result.download_token) {
    const t = result.token || result.download_token;
    console.log(`\n🔗 Download link: https://nyxvault.org/dl/${t}`);
    console.log(`🔑 Passphrase: ${passphrase}`);
  } else {
    console.log('Response:', JSON.stringify(result, null, 2));
  }
}

main().catch(e => console.error('❌', e.message));
