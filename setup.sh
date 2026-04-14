#!/bin/bash
# NyxVault Setup Script 🦞🔐
set -e

echo "🦞 NyxVault Setup"
echo "=================="

# Generate random secrets
API_KEY=$(openssl rand -hex 32)
WEB_PASSWORD=$(openssl rand -base64 15 | tr -d '/+=' | head -c 20)
SESSION_SECRET=$(openssl rand -hex 32)

# Create .env
cat > .env << EOF
PORT=3870
API_KEY=$API_KEY
WEB_PASSWORD=$WEB_PASSWORD
SESSION_SECRET=$SESSION_SECRET
MAX_FILE_SIZE_MB=100
EOF

echo "✅ .env created with random secrets"
echo ""
echo "📋 Your credentials:"
echo "   Web Password: $WEB_PASSWORD"
echo "   API Key:      $API_KEY"
echo ""
echo "⚠️  Save these somewhere safe! They won't be shown again."
echo ""

# Create directories
mkdir -p data storage

# Install dependencies
npm install

echo ""
echo "🚀 Ready! Start with: node server.js"
echo "   Or with PM2:       pm2 start server.js --name nyxvault"
echo "   Or with systemd:   See README.md"
