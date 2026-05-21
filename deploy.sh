#!/bin/bash
# deploy.sh — Run on a fresh Ubuntu/Debian VPS
# Usage: chmod +x deploy.sh && sudo ./deploy.sh [OPTIONS]
#
# Options:
#   --no-service       Skip systemd service creation/enable
#   --no-firewall      Skip firewall rule for port 80
#   --no-node-install  Skip Node.js installation

set -e

NO_SERVICE=false
NO_FIREWALL=false
NO_NODE_INSTALL=false

for arg in "$@"; do
  case "$arg" in
    --no-service)       NO_SERVICE=true ;;
    --no-firewall)      NO_FIREWALL=true ;;
    --no-node-install)  NO_NODE_INSTALL=true ;;
    --help|-h)
      echo "Usage: sudo ./deploy.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --no-service       Skip systemd service creation/enable"
      echo "  --no-firewall      Skip firewall rule for port 80"
      echo "  --no-node-install  Skip Node.js installation"
      exit 0
      ;;
  esac
done

echo "🛡️  Deploying Threat Exposure Test Server..."

# Install Node.js 20 if not present
if [ "$NO_NODE_INSTALL" = false ]; then
  if ! command -v node &>/dev/null; then
    echo "→ Installing Node.js 20..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
  fi
fi

# Install dependencies
echo "→ Installing dependencies..."
cd "$(dirname "$0")"
npm ci --production

# Open port 80 if ufw is active
if [ "$NO_FIREWALL" = false ]; then
  if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    echo "→ Opening port 80 in firewall..."
    ufw allow 80/tcp
  fi
fi

# Create systemd service
if [ "$NO_SERVICE" = false ]; then
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
fi

PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
echo ""
echo "✅ Server is live!"
echo "   → http://${PUBLIC_IP}"

if [ "$NO_SERVICE" = false ]; then
  echo ""
  echo "   systemctl status threat-test   # check status"
  echo "   journalctl -u threat-test -f   # view logs"
fi
