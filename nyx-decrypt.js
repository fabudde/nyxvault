#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');

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

async function decryptData(encryptedBuf, passphrase) {
  const data = new Uint8Array(encryptedBuf);
  const salt = data.slice(0, SALT_BYTES);
  const nonce = data.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = data.slice(SALT_BYTES + NONCE_BYTES);
  
  const key = await deriveKey(passphrase, salt);
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  
  if (!decrypted) throw new Error('Decryption failed! Wrong passphrase?');
  return decrypted;
}

async function main() {
  const inputFile = process.argv[2];
  const outputFile = process.argv[3];
  // argv[4] = custom passphrase (optional)
  
  if (!inputFile) {
    console.log('Usage: node nyx-decrypt.js <encrypted-file> [output-file]');
    process.exit(1);
  }
  
  const encData = fs.readFileSync(inputFile);
  console.log(`🔐 Decrypting ${inputFile} (${encData.length} bytes)...`);
  
  const decrypted = await decryptData(encData, PASSPHRASE);
  const outPath = outputFile || inputFile.replace('.bin', '-decrypted');
  
  fs.writeFileSync(outPath, decrypted);
  console.log(`✅ Decrypted! Saved to: ${outPath} (${decrypted.length} bytes)`);
}

main().catch(e => console.error('❌', e.message));
