#!/bin/bash
# NyxVault Setup Script 🦞🔐
set -e

echo "🦞 NyxVault Setup"
echo "=================="

# Generate random secrets
API_KEY=$(openssl rand -hex 32)
RAW_PASSWORD=$(openssl rand -base64 15 | tr -d '/+=' | head -c 20)
SESSION_SECRET=$(openssl rand -hex 32)

# Create directories & install deps first (needed for argon2)
mkdir -p data storage
npm install --silent

# Hash the web password with argon2
echo "🔑 Hashing web password with argon2..."
WEB_PASSWORD_HASH=$(node -e "
const argon2 = require('argon2');
argon2.hash('${RAW_PASSWORD}', { type: argon2.argon2id, memoryCost: 65536, timeCost: 3 })
  .then(h => process.stdout.write(h));
")

# Create .env
cat > .env << EOF
PORT=3870
API_KEY=$API_KEY
WEB_PASSWORD=$WEB_PASSWORD_HASH
SESSION_SECRET=$SESSION_SECRET
MAX_FILE_SIZE_MB=100
EOF

echo "✅ .env created with random secrets"
echo ""
echo "📋 Your credentials:"
echo "   Web Password: $RAW_PASSWORD"
echo "   API Key:      $API_KEY"
echo ""
echo "⚠️  Save these somewhere safe! They won't be shown again."
echo "   The password is stored as an argon2 hash in .env."
echo ""
echo "🚀 Ready! Start with: node server.js"
echo "   Or with PM2:       pm2 start server.js --name nyxvault"
echo "   Or with Docker:    docker build -t nyxvault . && docker run -p 3870:3870 nyxvault"
echo "   Or with systemd:   See README.md"
