# Private VPS deployment

The panel is published only inside a Tailscale network. Docker exposes port 8765 on the VPS loopback interface, not on its public IP.

## 1. Prepare Ubuntu

Install Docker Engine with the official Docker repository, then install Tailscale and sign the VPS into the same tailnet as the personal PC.

Create the application directory and copy `admin_panel/`, `Dockerfile`, `compose.yaml`, `.dockerignore`, and `.env.server.example` into it. Do not copy `.env.local`, `.octo.env.local`, `outputs/`, or any local token files. To keep the current accounts, copy `admin_panel/data/profiles.sqlite3` separately to `server-data/profiles.sqlite3`.

In the application directory:

```bash
cp .env.server.example .env.server
mkdir -p server-data
chmod 700 server-data
sudo chown -R 1000:1000 server-data
chmod 600 .env.server
```

Fill `.env.server` directly on the VPS. Do not commit or send this file in chat.

Profile notes contain `email:code` by design. Restrict Vision workspace access and include its notes in your credential rotation and backup policy.

## 2. Start services

```bash
docker compose build
docker compose up -d
docker compose ps
```

The web container is reachable only at `127.0.0.1:8765` on the VPS. The worker handles the persistent SQLite job queue. The bot uses long polling and needs no inbound port.

## 3. Publish to the tailnet

Run on the VPS:

```bash
sudo tailscale serve --bg http://127.0.0.1:8765
tailscale serve status
```

Open the HTTPS URL printed by `tailscale serve status` from the personal PC while Tailscale is connected. Sign in with `ADMIN_USER` and `ADMIN_PASSWORD`.

Do not use `tailscale funnel`: Funnel intentionally makes a service public on the internet.

Restrict access further in the Tailscale admin console with an access-control rule that permits only the personal PC or user account to reach this VPS.

## 4. Firewall

Allow SSH according to the VPS provider's requirements. Do not open TCP 8765 publicly. Verify from another network that `http://PUBLIC_VPS_IP:8765` is unreachable.

## 5. Data and backups

The SQLite database is stored in `server-data/profiles.sqlite3`. Back up the entire `server-data` directory while services are stopped, or use SQLite's online backup command.

Useful commands:

```bash
docker compose logs --tail=100 web worker bot
docker compose restart web worker bot
docker compose down
```
