#!/bin/bash
# deploy.sh — Run on a fresh Ubuntu/Debian VPS
# Usage: chmod +x deploy.sh && sudo ./deploy.sh

set -e

echo "🛡️  Deploying Threat Exposure Test Server..."

# Install Node.js 20 if not present
if ! command -v node &>/dev/null; then
  echo "→ Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

# Install dependencies
echo "→ Installing dependencies..."
cd "$(dirname "$0")"
npm ci --production

# Open port 80 if ufw is active
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
  echo "→ Opening port 80 in firewall..."
  ufw allow 80/tcp
fi

# Create systemd service
echo "→ Creating systemd service..."
cat > /etc/systemd/system/threat-test.service <<EOF
[Unit]
Description=Threat Exposure Test Server
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=$(pwd)
ExecStart=$(which node) server.js
Environment=PORT=80
Environment=NODE_ENV=production
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable threat-test
systemctl restart threat-test

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
echo ""
echo "✅ Server is live!"
echo "   → http://${PUBLIC_IP}"
echo ""
echo "   systemctl status threat-test   # check status"
echo "   journalctl -u threat-test -f   # view logs"
