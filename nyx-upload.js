#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const https = require('https');
const { URL } = require('url');

const API_KEY = process.env.NYXVAULT_API_KEY || '';
const BASE_URL = process.env.NYXVAULT_URL || 'https://nyxvault.org';
const DEFAULT_PASSPHRASE = process.env.NYXVAULT_PASSPHRASE || 'changeme';
const PASSPHRASE = process.argv[4] || DEFAULT_PASSPHRASE;
const SALT_BYTES = 16;
const NONCE_BYTES = 24;

async function deriveKey(passphrase, salt) {
  const key = await argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

async function encryptData(data, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const encrypted = nacl.secretbox(data, nonce, key);
  const result = new Uint8Array(salt.length + nonce.length + encrypted.length);
  result.set(salt, 0);
  result.set(nonce, salt.length);
  result.set(encrypted, salt.length + nonce.length);
  return result;
}

async function encryptString(str, passphrase) {
  return encryptData(new TextEncoder().encode(str), passphrase);
}

function postForm(url, form, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname,
      method: 'POST',
      headers: { ...form.getHeaders(), ...headers }
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } 
        catch(e) { reject(new Error(`Non-JSON response: ${body.substring(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    form.pipe(req);
  });
}

async function upload(filePath, expiresIn) {
  const fileName = path.basename(filePath);
  const fileData = fs.readFileSync(filePath);
  
  console.log(`🔐 Encrypting ${fileName} (${fileData.length} bytes)...`);
  
  const encryptedData = await encryptData(new Uint8Array(fileData), PASSPHRASE);
  const encryptedName = await encryptString(fileName, PASSPHRASE);
  const encryptedNameB64 = Buffer.from(encryptedName).toString('base64');
  const encryptedType = await encryptString('application/octet-stream', PASSPHRASE);
  const encryptedTypeB64 = Buffer.from(encryptedType).toString('base64');
  
  console.log(`📤 Uploading encrypted blob (${encryptedData.length} bytes)...`);
  
  const form = new FormData();
  form.append('file', Buffer.from(encryptedData), { filename: 'encrypted.bin', contentType: 'application/octet-stream' });
  form.append('uploader', 'nyx');
  form.append('filename_enc', encryptedNameB64);
  form.append('content_type_enc', encryptedTypeB64);
  if (expiresIn) form.append('expires_in', expiresIn);
  
  const result = await postForm(`${BASE_URL}/api/upload`, form, { 'X-Api-Key': API_KEY });
  
  if (result.download_token) {
    console.log(`\n✅ Upload erfolgreich!`);
    console.log(`📎 Download link: ${BASE_URL}/dl/${result.download_token}`);
    return `${BASE_URL}/dl/${result.download_token}`;
  } else {
    console.error('❌ Upload failed:', result);
    return null;
  }
}

const filePath = process.argv[2];
const expiresIn = process.argv[3];
// argv[4] = custom passphrase (optional)
if (!filePath) {
  console.log('Usage: node nyx-upload.js <file> [expires_in: 1h|24h|7d|30d]');
  process.exit(1);
}
upload(filePath, expiresIn).catch(console.error);
