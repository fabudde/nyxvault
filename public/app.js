/* NyxVault — Client-Side E2E Encryption 🔐🦞 */
/* v2: Chunked encryption, reduced Argon2, progressive download */
'use strict';

// ── Crypto Helpers (self-hosted libs: nacl + argon2) ─────
const SALT_BYTES = 16;
const NONCE_BYTES = 24; // XSalsa20-Poly1305 = secretbox
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC = new Uint8Array([0x4E, 0x59, 0x58, 0x32]); // "NYX2"
const SECRETBOX_OVERHEAD = 16; // Poly1305 tag

// Argon2id key derivation (using hash-wasm) — 16 MB (was 64 MB)
async function deriveKey(passphrase, salt) {
  const key = await hashwasm.argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16MB — still secure (OWASP min: 15MB)
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

function generateSalt() {
  return nacl.randomBytes(SALT_BYTES);
}

function generateNonce() {
  return nacl.randomBytes(NONCE_BYTES);
}

// Check if blob starts with NYX2 magic
function isChunkedFormat(data) {
  return data.length >= 4 &&
    data[0] === 0x4E && data[1] === 0x59 && data[2] === 0x58 && data[3] === 0x32;
}

// ── Chunked Encrypt (NYX2 format) ─────
// Format: NYX2(4) + salt(16) + num_chunks(4 BE) + [nonce(24) + ciphertext]...
async function encryptDataChunked(data, passphrase, onProgress) {
  const salt = generateSalt();
  const key = await deriveKey(passphrase, salt);
  const numChunks = Math.ceil(data.length / CHUNK_SIZE);

  // Calculate total size
  let totalSize = 4 + SALT_BYTES + 4; // magic + salt + num_chunks
  for (let i = 0; i < numChunks; i++) {
    const chunkLen = Math.min(CHUNK_SIZE, data.length - i * CHUNK_SIZE);
    totalSize += NONCE_BYTES + chunkLen + SECRETBOX_OVERHEAD;
  }

  const result = new Uint8Array(totalSize);
  let offset = 0;

  // Write magic
  result.set(MAGIC, offset); offset += 4;
  // Write salt
  result.set(salt, offset); offset += SALT_BYTES;
  // Write num_chunks (big-endian uint32)
  result[offset] = (numChunks >>> 24) & 0xFF;
  result[offset+1] = (numChunks >>> 16) & 0xFF;
  result[offset+2] = (numChunks >>> 8) & 0xFF;
  result[offset+3] = numChunks & 0xFF;
  offset += 4;

  // Encrypt each chunk
  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunk = data.slice(start, end);
    const nonce = generateNonce();
    const encrypted = nacl.secretbox(chunk, nonce, key);
    result.set(nonce, offset); offset += NONCE_BYTES;
    result.set(encrypted, offset); offset += encrypted.length;
    if (onProgress) onProgress(i + 1, numChunks);
  }

  return { blob: result, salt };
}

// ── Chunked Decrypt (NYX2 format) ─────
async function decryptDataChunked(data, passphrase, onProgress) {
  let offset = 4; // skip magic
  const salt = data.slice(offset, offset + SALT_BYTES); offset += SALT_BYTES;
  const numChunks = (data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3];
  offset += 4;

  const key = await deriveKey(passphrase, salt);
  const chunks = [];
  let totalDecrypted = 0;

  for (let i = 0; i < numChunks; i++) {
    const nonce = data.slice(offset, offset + NONCE_BYTES); offset += NONCE_BYTES;
    // Figure out ciphertext length: it's chunk_size + overhead, except last chunk
    // We need to calculate: for all but last chunk, ciphertext = CHUNK_SIZE + SECRETBOX_OVERHEAD
    // For last chunk, it's whatever remains
    let ciphertextLen;
    if (i < numChunks - 1) {
      ciphertextLen = CHUNK_SIZE + SECRETBOX_OVERHEAD;
    } else {
      ciphertextLen = data.length - offset;
    }
    const ciphertext = data.slice(offset, offset + ciphertextLen); offset += ciphertextLen;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) throw new Error('Decryption failed – wrong passphrase?');
    chunks.push(decrypted);
    totalDecrypted += decrypted.length;
    if (onProgress) onProgress(i + 1, numChunks);
  }

  // Combine chunks
  const result = new Uint8Array(totalDecrypted);
  let pos = 0;
  for (const chunk of chunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
}

// ── Encrypt (auto-selects chunked for large files, legacy for small strings) ─────
async function encryptData(data, passphrase, onProgress) {
  // Always use chunked format for files
  return encryptDataChunked(data, passphrase, onProgress);
}

// Helper: derive key with specific memory size
async function deriveKeyWithMem(passphrase, salt, memorySize) {
  const key = await hashwasm.argon2id({
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

// ── Decrypt (auto-detects format) ─────
async function decryptData(encryptedBlob, passphrase, onProgress) {
  if (isChunkedFormat(encryptedBlob)) {
    return decryptDataChunked(encryptedBlob, passphrase, onProgress);
  }
  // Legacy format — try 16MB first, then 64MB for old files
  const salt = encryptedBlob.slice(0, SALT_BYTES);
  const nonce = encryptedBlob.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = encryptedBlob.slice(SALT_BYTES + NONCE_BYTES);
  for (const mem of [16384, 65536]) {
    const key = await deriveKeyWithMem(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) return decrypted;
  }
  throw new Error('Decryption failed – wrong passphrase?');
}

// Encrypt a string (uses legacy format for small metadata — simpler)
async function encryptString(str, passphrase) {
  const data = nacl.util.decodeUTF8(str);
  const salt = generateSalt();
  const key = await deriveKey(passphrase, salt);
  const nonce = generateNonce();
  const encrypted = nacl.secretbox(data, nonce, key);
  const result = new Uint8Array(salt.length + nonce.length + encrypted.length);
  result.set(salt, 0);
  result.set(nonce, salt.length);
  result.set(encrypted, salt.length + nonce.length);
  return nacl.util.encodeBase64(result);
}

// Decrypt a base64 string (legacy format, with Argon2 fallback)
async function decryptString(b64, passphrase) {
  const data = nacl.util.decodeBase64(b64);
  const salt = data.slice(0, SALT_BYTES);
  const nonce = data.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = data.slice(SALT_BYTES + NONCE_BYTES);
  // Try 16MB first, then 64MB for old encrypted strings
  for (const mem of [16384, 65536]) {
    const key = await deriveKeyWithMem(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) return nacl.util.encodeUTF8(decrypted);
  }
  throw new Error('Decryption failed – wrong passphrase?');
}

// ── Progressive fetch with progress ─────
async function fetchWithProgress(url, onProgress) {
  const response = await fetch(url);
  if (!response.ok) throw new Error('Download failed');
  const contentLength = +response.headers.get('Content-Length');
  if (!response.body || !contentLength) {
    // Fallback: no streaming support
    return new Uint8Array(await response.arrayBuffer());
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (onProgress) onProgress(received, contentLength);
  }
  const result = new Uint8Array(received);
  let pos = 0;
  for (const chunk of chunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
}

// ── State ─────────────────────────────────────────────────
let sessionToken = sessionStorage.getItem('nyxvault_session');
let vaultPassphrase = sessionStorage.getItem('nyxvault_passphrase');
let selectedFile = null;

// ── DOM refs ──────────────────────────────────────────────
const loginOverlay = document.getElementById('loginOverlay');
const loginForm = document.getElementById('loginForm');
const loginPassword = document.getElementById('loginPassword');
const loginPassphrase = document.getElementById('loginPassphrase');
const loginError = document.getElementById('loginError');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const appContent = document.getElementById('appContent');

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const uploadOptions = document.getElementById('uploadOptions');
const selectedFileName = document.getElementById('selectedFileName');
const selectedFileSize = document.getElementById('selectedFileSize');
const expirySelect = document.getElementById('expirySelect');
const uploadBtn = document.getElementById('uploadBtn');
const cancelBtn = document.getElementById('cancelBtn');

const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');

const fileListBody = document.getElementById('fileListBody');
const fileCount = document.getElementById('fileCount');
const emptyState = document.getElementById('emptyState');
const fileTable = document.getElementById('fileTable');

const toastContainer = document.getElementById('toastContainer');

// ── Toast ─────────────────────────────────────────────────
function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Format helpers ────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
  const d = new Date(dateStr + 'Z');
  return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit', year: '2-digit' }) +
    ' ' + d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
}

// ── Auth ──────────────────────────────────────────────────
function showLogin() {
  loginOverlay.style.display = 'flex';
  appContent.style.display = 'none';
}

function showApp() {
  loginOverlay.style.display = 'none';
  appContent.style.display = 'block';
  loadFiles();
}

async function login() {
  const password = loginPassword.value.trim();
  const passphrase = loginPassphrase.value.trim();

  if (!password || !passphrase) {
    loginError.textContent = 'Both fields required';
    loginError.style.display = 'block';
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = 'Authenticating...';
  loginError.style.display = 'none';

  try {
    const res = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');

    sessionToken = data.token;
    vaultPassphrase = passphrase;
    sessionStorage.setItem('nyxvault_session', sessionToken);
    sessionStorage.setItem('nyxvault_passphrase', passphrase);

    toast('Logged in! 🔐', 'success');
    showApp();
  } catch (err) {
    loginError.textContent = err.message;
    loginError.style.display = 'block';
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Unlock Vault';
  }
}

function logout() {
  fetch('/auth/logout', {
    method: 'POST',
    headers: { 'X-Session-Token': sessionToken }
  }).catch(() => {});
  sessionToken = null;
  vaultPassphrase = null;
  sessionStorage.removeItem('nyxvault_session');
  sessionStorage.removeItem('nyxvault_passphrase');
  loginPassword.value = '';
  loginPassphrase.value = '';
  showLogin();
}

// ── API helper ────────────────────────────────────────────
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (sessionToken) headers['X-Session-Token'] = sessionToken;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    logout();
    throw new Error('Session expired');
  }
  return res;
}

// ── File List ─────────────────────────────────────────────
async function loadFiles() {
  try {
    const res = await api('/api/files');
    const data = await res.json();
    renderFiles(data.files);
  } catch (err) {
    if (err.message !== 'Session expired') {
      toast('Failed to load files', 'error');
    }
  }
}

async function renderFiles(files) {
  fileListBody.innerHTML = '';
  fileCount.textContent = `${files.length} file${files.length !== 1 ? 's' : ''}`;

  if (files.length === 0) {
    emptyState.style.display = 'block';
    fileTable.style.display = 'none';
    return;
  }

  emptyState.style.display = 'none';
  fileTable.style.display = 'table';

  for (const f of files) {
    let displayName = f.original_name || 'encrypted file';
    // Try to decrypt filename if we have a passphrase
    if (vaultPassphrase && f.filename_enc) {
      try {
        displayName = await decryptString(f.filename_enc, vaultPassphrase);
      } catch {
        displayName = f.original_name || '🔒 encrypted';
      }
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="filename" title="${escapeHtml(displayName)}">📄 ${escapeHtml(displayName)}</td>
      <td class="meta">${formatBytes(f.size_bytes)}</td>
      <td class="meta">${formatDate(f.upload_date)}</td>
      <td class="meta">${f.uploader}</td>
      <td class="actions">
        <button class="btn-icon copy" onclick="copyLink('${f.download_token}')" title="Copy shareable link">📋 Link</button>
        <button class="btn-icon" onclick="downloadFile(${f.id})" title="Download & decrypt">⬇️</button>
        <button class="btn-icon delete" onclick="deleteFile(${f.id})" title="Delete">🗑️</button>
      </td>
    `;
    fileListBody.appendChild(tr);
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ── Upload ────────────────────────────────────────────────
function handleFileDrop(e) {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  const files = e.dataTransfer?.files || e.target?.files;
  if (files && files.length > 0) {
    selectFile(files[0]);
  }
}

function selectFile(file) {
  selectedFile = file;
  selectedFileName.textContent = file.name;
  selectedFileSize.textContent = formatBytes(file.size);
  uploadOptions.classList.add('show');
}

function cancelUpload() {
  selectedFile = null;
  uploadOptions.classList.remove('show');
  fileInput.value = '';
}

async function uploadFile() {
  if (!selectedFile || !vaultPassphrase) return;

  uploadBtn.disabled = true;
  uploadBtn.textContent = 'Encrypting...';
  progressContainer.classList.add('show');
  progressFill.style.width = '10%';
  progressText.textContent = 'Encrypting file...';

  try {
    // Read file
    const arrayBuffer = await selectedFile.arrayBuffer();
    const fileData = new Uint8Array(arrayBuffer);

    progressFill.style.width = '20%';
    progressText.textContent = 'Deriving key & encrypting...';

    // Encrypt file content (chunked with progress)
    const { blob: encryptedData } = await encryptData(fileData, vaultPassphrase, (done, total) => {
      const pct = 20 + (done / total) * 30;
      progressFill.style.width = pct + '%';
      progressText.textContent = `Encrypting chunk ${done}/${total}...`;
    });

    progressFill.style.width = '50%';
    progressText.textContent = 'Encrypting metadata...';

    // Encrypt filename and content type
    const filenameEnc = await encryptString(selectedFile.name, vaultPassphrase);
    const contentTypeEnc = await encryptString(selectedFile.type || 'application/octet-stream', vaultPassphrase);

    // Calculate expiry
    let expiresAt = null;
    const expiryVal = expirySelect.value;
    if (expiryVal !== 'never') {
      const hours = parseInt(expiryVal);
      expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
    }

    progressFill.style.width = '60%';
    progressText.textContent = 'Uploading...';

    // Build form data
    const formData = new FormData();
    formData.append('file', new Blob([encryptedData]), 'encrypted');
    formData.append('filename_enc', filenameEnc);
    formData.append('content_type_enc', contentTypeEnc);
    formData.append('original_name', selectedFile.name);
    if (expiresAt) formData.append('expires_at', expiresAt);

    // Upload with progress
    const xhr = new XMLHttpRequest();
    const uploadPromise = new Promise((resolve, reject) => {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const pct = 60 + (e.loaded / e.total) * 35;
          progressFill.style.width = pct + '%';
          progressText.textContent = `Uploading... ${Math.round(e.loaded / e.total * 100)}%`;
        }
      });
      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(JSON.parse(xhr.responseText));
        } else {
          reject(new Error(JSON.parse(xhr.responseText).error || 'Upload failed'));
        }
      });
      xhr.addEventListener('error', () => reject(new Error('Network error')));
    });

    xhr.open('POST', '/api/upload');
    xhr.setRequestHeader('X-Session-Token', sessionToken);
    xhr.send(formData);

    const result = await uploadPromise;

    progressFill.style.width = '100%';
    progressText.textContent = 'Done!';

    toast(`Uploaded ${selectedFile.name} 🔐`, 'success');

    // Reset
    cancelUpload();
    loadFiles();

  } catch (err) {
    toast(`Upload failed: ${err.message}`, 'error');
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = '🔐 Encrypt & Upload';
    setTimeout(() => {
      progressContainer.classList.remove('show');
      progressFill.style.width = '0%';
    }, 2000);
  }
}

// ── Download (authenticated) ──────────────────────────────
async function downloadFile(id) {
  if (!vaultPassphrase) {
    toast('No passphrase set', 'error');
    return;
  }

  toast('Downloading...', 'info');

  try {
    const encryptedData = await fetchWithProgress(`/api/download/${id}`, (received, total) => {
      const pct = Math.round(received / total * 100);
      toast(`Downloading... ${pct}%`, 'info');
    });

    toast('Decrypting...', 'info');
    const decrypted = await decryptData(encryptedData, vaultPassphrase, (done, total) => {
      if (total > 1) toast(`Decrypting chunk ${done}/${total}...`, 'info');
    });

    // Get filename from file list
    const filesRes = await api('/api/files');
    const filesData = await filesRes.json();
    const file = filesData.files.find(f => f.id === id);

    let filename = 'decrypted_file';
    if (file && file.filename_enc && vaultPassphrase) {
      try {
        filename = await decryptString(file.filename_enc, vaultPassphrase);
      } catch { filename = file.original_name || 'decrypted_file'; }
    }

    // Trigger download
    const blob = new Blob([decrypted]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast(`Decrypted: ${filename}`, 'success');
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  }
}

// ── Delete ────────────────────────────────────────────────
async function deleteFile(id) {
  if (!confirm('Delete this file permanently?')) return;

  try {
    const res = await api(`/api/files/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Delete failed');
    toast('File deleted', 'success');
    loadFiles();
  } catch (err) {
    toast(`Delete failed: ${err.message}`, 'error');
  }
}

// ── Copy Link ─────────────────────────────────────────────
function copyLink(token) {
  const url = `${window.location.origin}/dl/${token}`;
  navigator.clipboard.writeText(url).then(() => {
    toast('Link copied! 📋', 'success');
  }).catch(() => {
    // Fallback
    const input = document.createElement('input');
    input.value = url;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    toast('Link copied! 📋', 'success');
  });
}

// ── Event Listeners ───────────────────────────────────────
loginForm.addEventListener('submit', (e) => { e.preventDefault(); login(); });
logoutBtn.addEventListener('click', logout);

dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', handleFileDrop);
dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFileDrop);

uploadBtn.addEventListener('click', uploadFile);
cancelBtn.addEventListener('click', cancelUpload);

// ── Init ──────────────────────────────────────────────────
if (sessionToken && vaultPassphrase) {
  // Validate session
  api('/api/files').then(res => {
    if (res.ok) showApp();
    else showLogin();
  }).catch(() => showLogin());
} else {
  showLogin();
}
