#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');

const PASSPHRASE = process.argv[3] || 'KosmischerLobster!2026';
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024;
const SECRETBOX_OVERHEAD = 16;
const MAGIC = Buffer.from('NYX2');

async function deriveKey(passphrase, salt, memorySize = 16384) {
  const key = await argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: memorySize,
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

function isChunkedFormat(data) {
  return data.length >= 4 && data.slice(0, 4).equals(MAGIC);
}

async function decryptDataChunked(data, passphrase) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const numChunks = data.readUInt32BE(offset); offset += 4;

  console.log(`  Chunked format (NYX2): ${numChunks} chunks`);
  // NYX2 files are always encrypted with 16MB Argon2
  const key = await deriveKey(passphrase, salt, 16384);

  const chunks = [];
  let totalDecrypted = 0;

  for (let i = 0; i < numChunks; i++) {
    const nonce = new Uint8Array(data.slice(offset, offset + NONCE_BYTES)); offset += NONCE_BYTES;
    let ciphertextLen = (i < numChunks - 1) ? CHUNK_SIZE + SECRETBOX_OVERHEAD : data.length - offset;
    const ciphertext = new Uint8Array(data.slice(offset, offset + ciphertextLen)); offset += ciphertextLen;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) throw new Error('Decryption failed! Wrong passphrase?');
    chunks.push(Buffer.from(decrypted));
    totalDecrypted += decrypted.length;
    process.stdout.write(`\r  Decrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(chunks, totalDecrypted);
}

async function decryptDataLegacy(data, passphrase) {
  console.log('  Legacy format (single block)');
  const salt = new Uint8Array(data.slice(0, SALT_BYTES));
  const nonce = new Uint8Array(data.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES));
  const ciphertext = new Uint8Array(data.slice(SALT_BYTES + NONCE_BYTES));

  // Try 16MB first (new), then 64MB (old) for backward compatibility
  for (const mem of [16384, 65536]) {
    console.log(`  Trying Argon2id with ${mem / 1024}MB...`);
    const key = await deriveKey(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) {
      console.log(`  ✓ Success with ${mem / 1024}MB Argon2id`);
      return Buffer.from(decrypted);
    }
  }
  throw new Error('Decryption failed! Wrong passphrase?');
}

async function main() {
  const inputFile = process.argv[2];
  const outputFile = process.argv[4] || null;

  if (!inputFile) {
    console.log('Usage: node nyx-decrypt.js <encrypted-file> [passphrase] [output-file]');
    process.exit(1);
  }

  const encData = fs.readFileSync(inputFile);
  console.log(`🔐 Decrypting ${inputFile} (${encData.length} bytes)...`);

  let decrypted;
  if (isChunkedFormat(encData)) {
    decrypted = await decryptDataChunked(encData, PASSPHRASE);
  } else {
    decrypted = await decryptDataLegacy(encData, PASSPHRASE);
  }

  const outPath = outputFile || inputFile.replace('.bin', '-decrypted');
  fs.writeFileSync(outPath, decrypted);
  console.log(`✅ Decrypted! Saved to: ${outPath} (${decrypted.length} bytes)`);
}

main().catch(e => console.error('❌', e.message));
