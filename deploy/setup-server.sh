#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/profile-admin"
DATA_DIR="$APP_DIR/server-data"

echo "=== Profile Admin — Server Setup ==="

# 1. Install Docker if missing
if ! command -v docker &>/dev/null; then
  echo "[1/5] Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  echo "[1/5] Docker already installed"
fi

# 2. Install Docker Compose plugin if missing
if ! docker compose version &>/dev/null; then
  echo "[2/5] Installing Docker Compose plugin..."
  apt-get update -qq && apt-get install -y -qq docker-compose-plugin
else
  echo "[2/5] Docker Compose already installed"
fi

# 3. Create directories
echo "[3/5] Setting up directories..."
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

# Copy database if uploaded
if [ -f "$APP_DIR/profiles.sqlite3" ]; then
  echo "  -> Copying uploaded database to server-data/"
  cp "$APP_DIR/profiles.sqlite3" "$DATA_DIR/profiles.sqlite3"
  rm "$APP_DIR/profiles.sqlite3"
fi

chown -R 1000:1000 "$DATA_DIR"

# 4. Create .env.server from example if not exists
if [ ! -f "$APP_DIR/.env.server" ]; then
  echo "[4/5] Creating .env.server from example..."
  cp "$APP_DIR/.env.server.example" "$APP_DIR/.env.server"
  chmod 600 "$APP_DIR/.env.server"
  echo ""
  echo "  ╔══════════════════════════════════════════════════╗"
  echo "  ║  IMPORTANT: Edit .env.server with your tokens!  ║"
  echo "  ║  nano $APP_DIR/.env.server           ║"
  echo "  ╚══════════════════════════════════════════════════╝"
  echo ""
  NEED_ENV=1
else
  echo "[4/5] .env.server already exists, keeping it"
  NEED_ENV=0
fi

# 5. Build and start
echo "[5/5] Building and starting services..."
cd "$APP_DIR"

if [ "$NEED_ENV" = "1" ]; then
  echo ""
  echo "Fill .env.server first, then run:"
  echo "  cd $APP_DIR && docker compose build && docker compose up -d"
  echo ""
else
  docker compose build
  docker compose up -d
  echo ""
  echo "=== Services started! ==="
  docker compose ps
  echo ""
  echo "Panel: http://$(hostname -I | awk '{print $1}'):8765/"
fi

echo "Done."
