/* NyxVault — Client-Side E2E Encryption 🔐🦞 */
'use strict';

// ── Crypto Helpers (self-hosted libs: nacl + argon2) ─────
const SALT_BYTES = 16;
const NONCE_BYTES = 24; // XChaCha20-Poly1305 = secretbox

// Argon2id key derivation (using hash-wasm)
async function deriveKey(passphrase, salt) {
  const key = await hashwasm.argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536, // 64MB
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

// Encrypt data with passphrase
async function encryptData(data, passphrase) {
  const salt = generateSalt();
  const key = await deriveKey(passphrase, salt);
  const nonce = generateNonce();
  const encrypted = nacl.secretbox(data, nonce, key);
  // Prepend salt + nonce to ciphertext
  const result = new Uint8Array(salt.length + nonce.length + encrypted.length);
  result.set(salt, 0);
  result.set(nonce, salt.length);
  result.set(encrypted, salt.length + nonce.length);
  return { blob: result, salt, nonce };
}

// Decrypt data with passphrase
async function decryptData(encryptedBlob, passphrase) {
  const salt = encryptedBlob.slice(0, SALT_BYTES);
  const nonce = encryptedBlob.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = encryptedBlob.slice(SALT_BYTES + NONCE_BYTES);
  const key = await deriveKey(passphrase, salt);
  const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
  if (!decrypted) throw new Error('Decryption failed – wrong passphrase?');
  return decrypted;
}

// Encrypt a string
async function encryptString(str, passphrase) {
  const data = nacl.util.decodeUTF8(str);
  const { blob } = await encryptData(data, passphrase);
  return nacl.util.encodeBase64(blob);
}

// Decrypt a base64 string
async function decryptString(b64, passphrase) {
  const data = nacl.util.decodeBase64(b64);
  const decrypted = await decryptData(data, passphrase);
  return nacl.util.encodeUTF8(decrypted);
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

    progressFill.style.width = '30%';
    progressText.textContent = 'Deriving key...';

    // Encrypt file content
    const { blob: encryptedData } = await encryptData(fileData, vaultPassphrase);

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
    const res = await api(`/api/download/${id}`);
    if (!res.ok) throw new Error('Download failed');

    const encryptedData = new Uint8Array(await res.arrayBuffer());

    toast('Decrypting...', 'info');
    const decrypted = await decryptData(encryptedData, vaultPassphrase);

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
