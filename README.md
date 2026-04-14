# 🦞🔐 NyxVault

**Self-hosted, end-to-end encrypted file sharing. Zero knowledge. Your server, your data.**

![License](https://img.shields.io/badge/license-MIT-purple)
![Node](https://img.shields.io/badge/node-%3E%3D18-green)

<p align="center">
  <img src="https://nyxvault.org/lib/preview.png" alt="NyxVault" width="400">
</p>

## ✨ Features

- **🔐 End-to-End Encryption** — Files are encrypted in your browser before upload. The server never sees your data.
- **🔑 Argon2id + XChaCha20-Poly1305** — Same crypto used by ProtonMail and Signal.
- **📎 Shareable Download Links** — Each file gets a unique link with its own access token.
- **⏰ Expiring Files** — Set files to auto-delete after 1 hour, 24 hours, 7 days, or 30 days.
- **🖥️ Web UI + API** — Beautiful dark UI for humans, REST API for bots/scripts.
- **🪶 Lightweight** — Node.js + SQLite. No Docker required, no third-party dependencies.
- **📱 Responsive** — Works on desktop, tablet, and mobile.

## 🚀 Quick Start

```bash
git clone https://github.com/fabudde/nyxvault.git
cd nyxvault
bash setup.sh
node server.js
```

Open `http://localhost:3870` and you're done.

## 📦 Manual Setup

```bash
# Clone
git clone https://github.com/fabudde/nyxvault.git
cd nyxvault

# Install dependencies
npm install

# Configure
cp .env.example .env
# Edit .env with your own secrets:
#   API_KEY      — for API access (scripts, bots)
#   WEB_PASSWORD — for browser login
#   SESSION_SECRET — random string for sessions

# Create directories
mkdir -p data storage

# Start
node server.js
```

## 🐳 Docker

```bash
docker run -d \
  --name nyxvault \
  -p 3870:3870 \
  -v nyxvault-data:/app/data \
  -v nyxvault-storage:/app/storage \
  -e API_KEY=your-api-key \
  -e WEB_PASSWORD=your-password \
  -e SESSION_SECRET=your-secret \
  fabudde/nyxvault
```

Or with docker-compose:

```yaml
version: '3.8'
services:
  nyxvault:
    image: fabudde/nyxvault
    ports:
      - "127.0.0.1:3870:3870"
    volumes:
      - ./data:/app/data
      - ./storage:/app/storage
    environment:
      - API_KEY=your-api-key
      - WEB_PASSWORD=your-password
      - SESSION_SECRET=your-secret
      - MAX_FILE_SIZE_MB=100
    restart: unless-stopped
```

## 🔧 Reverse Proxy (Caddy)

```
vault.yourdomain.com {
    reverse_proxy 127.0.0.1:3870
}
```

## 📡 API

### Upload (with API key)

```bash
curl -X POST https://vault.yourdomain.com/api/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@/path/to/file.pdf" \
  -F "expires_hours=24"
```

### Download

```bash
# Get metadata
curl https://vault.yourdomain.com/api/dl/{token}/meta

# Get encrypted blob
curl https://vault.yourdomain.com/api/dl/{token}/blob -o encrypted.bin
```

### List files

```bash
curl https://vault.yourdomain.com/api/files \
  -H "X-API-Key: your-api-key"
```

## 🔐 How Encryption Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Browser    │     │    Server    │     │  Recipient  │
│              │     │              │     │             │
│ 1. Generate  │     │              │     │             │
│    file key  │     │              │     │             │
│              │     │              │     │             │
│ 2. Derive    │     │              │     │             │
│    master key│     │              │     │             │
│    (Argon2id)│     │              │     │             │
│              │     │              │     │             │
│ 3. Encrypt   │     │              │     │             │
│    file      │────▶│ 4. Store     │     │             │
│   (XChaCha20)│     │    encrypted │     │             │
│              │     │    blob only │     │             │
│              │     │              │     │             │
│              │     │ 5. Generate  │────▶│ 6. Enter    │
│              │     │    share link│     │    passphrase│
│              │     │              │     │             │
│              │     │              │◀────│ 7. Download │
│              │     │              │     │    blob     │
│              │     │              │     │             │
│              │     │              │     │ 8. Decrypt  │
│              │     │              │     │   (Argon2id │
│              │     │              │     │  + XChaCha) │
└─────────────┘     └──────────────┘     └─────────────┘

The server NEVER sees plaintext. Only encrypted blobs.
```

## 🛡️ Security

- **XChaCha20-Poly1305** — Authenticated encryption (AEAD)
- **Argon2id** — Memory-hard key derivation (64MB, 3 iterations)
- **Per-file salt + nonce** — No key reuse, ever
- **Filename encryption** — Even filenames are encrypted
- **Rate limiting** — Brute-force protection on downloads and uploads
- **No server-side decryption** — Zero knowledge architecture

### Audited By

- 🦉 **Tyto** — Security Advisor (9.5/10 rating)

## ⚙️ Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3870` | Server port |
| `API_KEY` | — | API authentication key |
| `WEB_PASSWORD` | — | Web UI login password |
| `SESSION_SECRET` | — | Express session secret |
| `MAX_FILE_SIZE_MB` | `100` | Maximum upload size in MB |

## 📝 License

MIT — do whatever you want with it.

## 👥 Credits

Built by **[Nyx](https://heynyx.dev)** 🦞 and **[Fabian](https://fabianbudde.com)** 🐻

Security review by **Tyto** 🦉

---

*Your files, your server, your keys. No cloud, no tracking, no bullshit.* 🔐
