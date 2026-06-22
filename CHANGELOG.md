# Changelog

All notable changes to NyxVault are documented here.

## [2.0.0] — 2026-06-22

### 🔐 Security — NYX3 Encryption Format

Major cryptographic integrity upgrade. **New files are encrypted with the NYX3 format; existing NYX2 files remain fully readable (backward compatible).**

#### Fixed
- **Chunk reordering/truncation vulnerability** — Each chunk's plaintext now includes a 5-byte prefix (`chunk_index` as 4-byte big-endian + `is_last` flag). After decryption, the prefix is verified: wrong order → `Integrity error: chunk order mismatch`; missing final marker → `Integrity error: missing final chunk marker`; premature final marker → `Integrity error: premature final chunk marker`. An attacker with blob access can no longer silently reorder, duplicate, or truncate chunks.
- **Unauthenticated header** — A 32-byte HMAC-SHA256 of the header (magic + salt + num_chunks) is stored between the salt and the chunk count. The HMAC key is derived via domain separation (`HMAC-SHA256(derived_key, "nyxvault-header-auth")`), so tampering with `num_chunks` is detected before any chunk decryption begins.
- **Incorrect cipher label on landing page** — The landing page and index previously stated "XChaCha20-Poly1305"; the actual cipher used by TweetNaCl's `secretbox` is **XSalsa20-Poly1305**. Corrected everywhere.

#### Format

```
NYX3 on-disk layout:
  "NYX3"            4 bytes   magic
  salt              16 bytes  Argon2id salt
  header_hmac       32 bytes  HMAC-SHA256(hmac_subkey, magic ‖ salt ‖ num_chunks)
  num_chunks        4 bytes   uint32 big-endian
  repeated num_chunks times:
    nonce           24 bytes
    ciphertext      encrypted(chunk_index‖is_last‖data) + 16 bytes Poly1305 tag

  hmac_subkey = HMAC-SHA256(derived_key, "nyxvault-header-auth")
  chunk plaintext prefix: index(4 BE) + is_last(1 byte: 0x00 or 0x01)
```

#### Changed
- `app.js` (browser encrypt) — writes NYX3 format with chunk prefix + header HMAC
- `dl-page.js` (browser decrypt) — detects NYX3 vs NYX2, verifies HMAC + chunk integrity
- `nyx-upload.js` (CLI encrypt) — writes NYX3 format
- `nyx-decrypt.js` (CLI decrypt) — detects NYX3 vs NYX2, uses `crypto.timingSafeEqual` for HMAC comparison
- `package.json` — version bumped to 2.0.0
- `server.js` — health endpoint reports version 2.0.0

#### Backward Compatibility
- NYX2 files are auto-detected by magic bytes and decrypted using the original code path (no integrity checks, since those didn't exist in NYX2).
- Legacy single-block format (used for `filename_enc` / `content_type_enc` metadata strings) is unchanged.
- Argon2id parameters are unchanged (16 MB, 3 iterations, 32-byte key).

---

## [1.2.2] — 2026-06-22

- New premium landing page; removed "Open Vault" links (instance is private).

## [1.2.1] — 2026-06-22

- Admin download: try vault passphrase first, prompt on failure for custom ones.

## [1.2.0] — 2026-06-22

- Fix admin download button; require passphrase on upload.
- Fast admin dashboard: paginated file list (25/page) with non-blocking filename decryption.

## [1.1.3] — 2026-06-21

- Fix 404 on `/` and `/admin` when install path contains a dot-dir.

## [1.1.2] — 2026-06-21

- Audit v3 fixes (Tyto 🦉): schema migration, CSP hardening, burn single-use + secure delete.
- Make VirusTotal scan strictly opt-in (privacy).

## [1.0.0] — 2026-06-21

- Initial production release.
- E2E encrypted file sharing with Argon2id + XSalsa20-Poly1305.
- Burn after reading, expiring links, QR code sharing.
- VirusTotal opt-in hash scan, in-browser preview (image/video/audio/PDF/text).
- CLI tools (`nyx-upload.js`, `nyx-decrypt.js`).
- Cosmic lobster theme 🦞.
