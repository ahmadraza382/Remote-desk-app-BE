# RemoteDesk Signaling Server

FastAPI + **MariaDB** (MySQL-compatible). It performs **device registration**, **access control**,
**pairing**, **SDP/ICE relay**, and **connection-history logging**. No media flows through it —
once WebRTC connects, this server is out of the data path.

## What it stores (MariaDB)

- `devices` — registry: `device_uuid` (PK), unique 12-digit `code` (public), secret `auth_token`,
  `mac_address`, `device_name`, `os_info`, `registered_at`, `last_seen`, `status` (active|blocked).
- `connection_history` — one row per pairing: controller/host codes + names, `connected_at`,
  `ended_at`, `status` (connected|ended|failed|declined).

Tables are created automatically on startup from `schema.sql`.

## HTTP / WebSocket API

- `POST /register` — body `{ device_uuid, mac, name, os }`. Idempotent by `device_uuid`; returns
  `{ code, auth_token }` (existing code if already registered).
- `GET /history/{code}` — recent connections involving that code (most recent first).
- `GET /turn-credentials` — ephemeral coturn ICE servers (see TURN below). Requires the
  `X-Device-Code` + `X-Device-Token` headers of a registered, active device.
- `GET /` — health → `{"status":"ok"}`.
- `WS /ws` — identify-first handshake:
  - client → `{ "type":"identify", "role":"host"|"controller", "code", "token", "targetCode"? }`
  - server → `{ "type":"authorized" }` or `{ "type":"unauthorized", "reason" }`
  - server → `{ "type":"peer-ready" }` / `{ "type":"peer-left" }`
  - relayed peer ↔ peer (verbatim): `{ "description": <SDP> }` or `{ "candidate": <ICE> }`

**Access control:** the device is authenticated by its `code` + secret `token`; a controller's
`targetCode` must map to a registered, active device. Unregistered/blocked devices or a wrong
token are rejected. A code only authenticates from its bound device.

**Host approval:** even for a registered controller, the Host user must approve each session.
After both peers authorize, the server sends the Host `connect-request`; only on the Host's
`accept` does it send `peer-ready` and relay SDP/ICE. A `reject` or a 30s timeout sends the
controller `declined` and logs the attempt as `declined`. No media flows before approval.

**Blocking devices (admin only).** A `blocked` device cannot register a session or connect.
Either set status directly in SQL:

```sql
UPDATE devices SET status = 'blocked' WHERE code = '123456789012';   -- block
UPDATE devices SET status = 'active'  WHERE code = '123456789012';   -- unblock
```

…or use the guarded HTTP endpoints (enabled only when `ADMIN_TOKEN` is set in `.env`):

```bash
curl -X POST http://localhost:8000/admin/block   -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "content-type: application/json" -d '{"code":"123456789012"}'
curl -X POST http://localhost:8000/admin/unblock -H "X-Admin-Token: $ADMIN_TOKEN" \
     -H "content-type: application/json" -d '{"code":"123456789012"}'
```

These are admin-only (never exposed to clients); blocking also drops the device's live connection.

## TURN (self-hosted coturn)

`GET /turn-credentials` returns time-limited ICE servers using coturn's TURN REST API
(`use-auth-secret`) — **no hardcoded TURN passwords**. The `username` is an expiry timestamp
and the `credential` is `base64(HMAC-SHA1(TURN_SECRET, username))`; the raw secret is never sent.

Set in `.env`:

```
TURN_HOST=turn.example.com   # your coturn host
TURN_SECRET=<matches coturn's static-auth-secret>
```

- When `TURN_HOST` + `TURN_SECRET` are set → returns `stun:`, `turn:`, and `turns:` URLs for
  that host with ephemeral creds.
- When unset and `APP_ENV=dev` → falls back to Google STUN (so local dev works).
- When unset and `APP_ENV=prod` → `503` (coturn must be configured in production).

The VPS-side coturn install (with a matching `static-auth-secret`) is performed separately.

## Configuration

`DATABASE_URL` is read from `signaling/.env` automatically on startup (via python-dotenv).
There is **no default** — if `.env` is missing the variable, the server fails fast with a
clear message. Copy `.env.example` → `.env` and fill in your local MariaDB password.
`.env` is git-ignored (never commit the real password); `.env.example` is the committed template.

```
# signaling/.env
DATABASE_URL=mysql://root:<password>@localhost:3306/remotedesk
# also accepted: mariadb://user:pass@host:3306/remotedesk
```

## Run (development)

```bash
# 1. MariaDB (install it, then create the database once)
#    Windows: install MariaDB, open HeidiSQL / mysql CLI
mysql -u root -p -e "CREATE DATABASE remotedesk CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 2. Config — copy the template and set your password
cp .env.example .env       # Windows: copy .env.example .env
#   then edit signaling/.env and set the real password

# 3. Server
python -m venv .venv
# Windows:  .venv\Scripts\activate   |   macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt
py -m uvicorn main:app --port 8000     # reads DATABASE_URL from .env; no manual env var needed
```

The `devices` and `connection_history` tables are created automatically on startup from
`schema.sql`.

Dev uses `ws://` (plain). `wss://` (TLS) is production only. For cross-network testing, expose
the server with a tunnel (e.g. `ngrok http 8000`) and set the app's signaling URL to the tunnel
host.
