"""RemoteDesk signaling server (FastAPI + PostgreSQL).

Responsibilities: device registration, ACCESS CONTROL (only registered + active devices,
authenticated by their secret token, may pair; a code authenticates only from its bound
device), pairing, relaying SDP/ICE between paired peers, and connection-history logging.
No media flows through here — once WebRTC connects, this server is out of the data path.

Handshake (identify-first, instead of codes in the URL):
  1. Client opens WS /ws and sends {type:'identify', role, code, token, targetCode?}.
  2. Server verifies the device (exists, active, token matches); for a controller it also
     verifies targetCode maps to a registered, active device.
  3. On failure → {type:'unauthorized', reason} + close. On success → {type:'authorized'}.
  4. When a controller and its target host are both connected + authorized, they are paired:
     {type:'peer-ready'} to both, a history row is logged, and subsequent messages relay.

Run (dev):  uvicorn main:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

import db

# Load signaling/.env so DATABASE_URL (and any other config) is available without
# manual environment variables. Runs before the DB pool is created in lifespan startup.
load_dotenv(Path(__file__).with_name(".env"))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("remotedesk.signaling")

HISTORY_LIMIT = 20
# How long the Host has to accept an incoming request before it is auto-declined.
ACCEPT_TIMEOUT_SECONDS = 30
# Admin block/unblock is only enabled when this secret is configured (in .env).
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

APP_ENV = os.environ.get("APP_ENV", "dev")
# coturn (self-hosted STUN + TURN). When set, the app uses ephemeral TURN REST API creds.
TURN_HOST = os.environ.get("TURN_HOST")
TURN_SECRET = os.environ.get("TURN_SECRET")  # matches coturn's static-auth-secret
TURN_TTL_SECONDS = 86400
# Dev fallback when coturn is not configured (so local testing still works).
GOOGLE_STUN = {"urls": ["stun:stun.l.google.com:19302"]}

# code -> connected client. The in-memory pairing map; gated by the DB access checks.
connected: dict[str, "Client"] = {}


@dataclass
class Client:
    ws: WebSocket
    role: str
    code: str
    name: str | None
    target: str | None = None
    # Tentatively matched peer awaiting Host approval (before media starts).
    pending_peer: "Client | None" = None
    approval_task: "asyncio.Task[None] | None" = None
    # Confirmed peer (after Accept); SDP/ICE relays only between confirmed partners.
    partner: "Client | None" = None
    history_id: int | None = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await db.init_db()
    logger.info("database ready")
    try:
        yield
    finally:
        await db.close_db()


app = FastAPI(title="RemoteDesk Signaling", lifespan=lifespan)


class RegisterBody(BaseModel):
    device_uuid: str
    mac: str | None = None
    name: str | None = None
    os: str | None = None


class AdminBody(BaseModel):
    code: str


@app.get("/")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register")
async def register(body: RegisterBody) -> dict[str, str]:
    try:
        code, token = await db.register_device(
            body.device_uuid, body.mac or "", body.name or "", body.os or ""
        )
    except db.DeviceBlocked:
        # Blocked devices get no session credentials.
        raise HTTPException(status_code=403, detail="device is blocked")
    return {"code": code, "auth_token": token}


def _require_admin(token: str | None) -> None:
    """Guard the admin endpoints with the ADMIN_TOKEN secret (disabled if unset)."""
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="admin endpoints are disabled (set ADMIN_TOKEN)")
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="invalid admin token")


@app.post("/admin/block")
async def admin_block(body: AdminBody, x_admin_token: str | None = Header(default=None)) -> dict[str, str]:
    _require_admin(x_admin_token)
    await db.set_device_status(body.code, "blocked")
    # Drop any live connection for the now-blocked device.
    live = connected.get(body.code)
    if live is not None:
        await _cleanup(live)
        try:
            await live.ws.close()
        except Exception as err:
            logger.warning("closing blocked device ws failed: %s", err)
    return {"code": body.code, "status": "blocked"}


@app.post("/admin/unblock")
async def admin_unblock(body: AdminBody, x_admin_token: str | None = Header(default=None)) -> dict[str, str]:
    _require_admin(x_admin_token)
    await db.set_device_status(body.code, "active")
    return {"code": body.code, "status": "active"}


def make_turn_credentials(host: str, secret: str, ttl: int = TURN_TTL_SECONDS) -> dict[str, object]:
    """Ephemeral coturn creds (TURN REST API / use-auth-secret). The raw secret is never
    returned — only the time-limited username (expiry) and its HMAC-SHA1 credential."""
    username = str(int(time.time()) + ttl)
    digest = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    credential = base64.b64encode(digest).decode()
    return {
        "urls": [
            f"stun:{host}:3478",
            f"turn:{host}:3478",
            f"turns:{host}:5349",
        ],
        "username": username,
        "credential": credential,
    }


@app.get("/turn-credentials")
async def turn_credentials(
    x_device_code: str | None = Header(default=None),
    x_device_token: str | None = Header(default=None),
) -> dict[str, list[dict[str, object]]]:
    # Only a registered, active device may fetch creds (prevents open TURN-relay abuse).
    if not x_device_code or not x_device_token:
        raise HTTPException(status_code=401, detail="missing device credentials")
    device = await db.get_device_by_code(x_device_code)
    if device is None or device.status != "active" or device.auth_token != x_device_token:
        raise HTTPException(status_code=401, detail="unauthorized")

    if TURN_HOST and TURN_SECRET:
        return {"iceServers": [make_turn_credentials(TURN_HOST, TURN_SECRET)]}
    if APP_ENV != "prod":
        # Dev without coturn configured — fall back to Google STUN so local testing works.
        return {"iceServers": [GOOGLE_STUN]}
    raise HTTPException(status_code=503, detail="TURN is not configured")


@app.get("/history/{code}")
async def history(code: str) -> list[dict[str, object]]:
    rows = await db.recent_connections(code, HISTORY_LIMIT)
    out: list[dict[str, object]] = []
    for r in rows:
        if r.controller_code == code:
            out.append(
                {
                    "code": r.host_code,
                    "name": r.host_name,
                    "time": r.connected_at.isoformat(),
                    "status": r.status,
                    "direction": "outgoing",
                }
            )
        else:
            out.append(
                {
                    "code": r.controller_code,
                    "name": r.controller_name,
                    "time": r.connected_at.isoformat(),
                    "status": r.status,
                    "direction": "incoming",
                }
            )
    return out


async def _reject(ws: WebSocket, reason: str) -> None:
    try:
        await ws.send_text(json.dumps({"type": "unauthorized", "reason": reason}))
        await ws.close()
    except Exception as err:  # the socket may already be gone
        logger.warning("reject send failed: %s", err)


async def _pair(controller: Client, host: Client) -> None:
    controller.partner = host
    host.partner = controller
    ready = json.dumps({"type": "peer-ready"})
    await controller.ws.send_text(ready)
    await host.ws.send_text(ready)
    logger.info("paired controller=%s host=%s", controller.code, host.code)
    # History logging must never break the live session.
    try:
        history_id = await db.log_connection(
            controller.code, host.code, controller.name, host.name
        )
        controller.history_id = history_id
        host.history_id = history_id
    except Exception as err:
        logger.error("history log failed: %s", err)


async def _request_connect(controller: Client, host: Client) -> None:
    """Ask the Host to approve an incoming connection before any media starts."""
    controller.pending_peer = host
    host.pending_peer = controller
    await host.ws.send_text(
        json.dumps({"type": "connect-request", "code": controller.code, "name": controller.name})
    )
    logger.info("connect-request controller=%s host=%s", controller.code, host.code)
    host.approval_task = asyncio.create_task(_approval_timeout(host))


async def _approval_timeout(host: Client) -> None:
    try:
        await asyncio.sleep(ACCEPT_TIMEOUT_SECONDS)
    except asyncio.CancelledError:
        return  # accepted/rejected in time — expected cancellation
    if host.pending_peer is not None:
        await _decline(host, "timed out")


async def _accept(host: Client) -> None:
    controller = host.pending_peer
    if controller is None:
        return
    if host.approval_task is not None:
        host.approval_task.cancel()
        host.approval_task = None
    controller.pending_peer = None
    host.pending_peer = None
    await _pair(controller, host)


async def _decline(host: Client, reason: str) -> None:
    controller = host.pending_peer
    if host.approval_task is not None:
        host.approval_task.cancel()
        host.approval_task = None
    host.pending_peer = None
    if controller is not None:
        controller.pending_peer = None
        try:
            await controller.ws.send_text(json.dumps({"type": "declined", "reason": reason}))
        except Exception as err:
            logger.warning("declined notify failed: %s", err)
        try:
            await db.log_declined(controller.code, host.code, controller.name, host.name)
        except Exception as err:
            logger.error("declined history log failed: %s", err)
    logger.info("declined controller=%s host=%s reason=%s", controller.code if controller else "?", host.code, reason)


async def _try_pair(client: Client) -> None:
    if client.partner is not None or client.pending_peer is not None:
        return
    if client.role == "controller":
        host = connected.get(client.target or "")
        if host is not None and host.role == "host" and host.partner is None and host.pending_peer is None:
            await _request_connect(client, host)
    else:  # host: a controller may already be waiting for this code
        for other in list(connected.values()):
            if (
                other.role == "controller"
                and other.target == client.code
                and other.partner is None
                and other.pending_peer is None
            ):
                await _request_connect(other, client)
                break


async def _cleanup(client: Client) -> None:
    if connected.get(client.code) is client:
        connected.pop(client.code, None)
    if client.approval_task is not None:
        client.approval_task.cancel()
        client.approval_task = None

    # Tentative (pre-approval) peer: tell it the request ended.
    pending = client.pending_peer
    if pending is not None:
        pending.pending_peer = None
        if pending.approval_task is not None:
            pending.approval_task.cancel()
            pending.approval_task = None
        try:
            if pending.role == "controller":
                # The host we were asking for is gone.
                await pending.ws.send_text(
                    json.dumps({"type": "declined", "reason": "host disconnected"})
                )
            else:
                # The requester left before the host responded — dismiss its prompt.
                await pending.ws.send_text(json.dumps({"type": "peer-left"}))
        except Exception as err:
            logger.warning("pending notify failed: %s", err)

    # Confirmed partner: tell it the peer left and close out the history row.
    partner = client.partner
    if partner is not None:
        partner.partner = None
        try:
            await partner.ws.send_text(json.dumps({"type": "peer-left"}))
        except Exception as err:
            logger.warning("peer-left notify failed: %s", err)
    if client.history_id is not None:
        try:
            await db.end_connection(client.history_id)
        except Exception as err:
            logger.error("history end failed: %s", err)


@app.websocket("/ws")
async def signaling(ws: WebSocket) -> None:
    await ws.accept()
    client: Client | None = None
    try:
        # 1. identify-first
        raw = await ws.receive_text()
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            await _reject(ws, "malformed identify")
            return
        if msg.get("type") != "identify":
            await _reject(ws, "expected identify")
            return

        role = msg.get("role")
        code = msg.get("code")
        token = msg.get("token")
        target = msg.get("targetCode")
        if role not in ("host", "controller") or not code or not token:
            await _reject(ws, "invalid identify")
            return

        # 2. access control — authenticate the device by code + token, then status
        device = await db.get_device_by_code(code)
        if device is None or device.auth_token != token:
            await _reject(ws, "device not registered or not authorized")
            return
        if device.status != "active":
            await _reject(ws, "device is blocked")
            return
        if role == "controller":
            if not target:
                await _reject(ws, "missing target code")
                return
            target_device = await db.get_device_by_code(target)
            if target_device is None:
                await _reject(ws, "target device not registered")
                return
            if target_device.status != "active":
                await _reject(ws, "target device is blocked")
                return

        await db.touch_last_seen(code)

        # 3. authorized — register in the pairing map and attempt to pair
        client = Client(ws=ws, role=role, code=code, name=device.device_name, target=target)
        # If this device already has an active connection, replace it cleanly.
        previous = connected.get(code)
        if previous is not None:
            await _cleanup(previous)
        connected[code] = client
        await ws.send_text(json.dumps({"type": "authorized"}))
        await _try_pair(client)

        # 4. message loop — intercept the Host's approval, relay SDP/ICE to the partner
        while True:
            data = await ws.receive_text()
            try:
                parsed = json.loads(data)
                mtype = parsed.get("type") if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                mtype = None

            if mtype in ("accept", "reject"):
                # Only a Host with a pending request may approve/decline.
                if client.role == "host" and client.pending_peer is not None:
                    if mtype == "accept":
                        await _accept(client)
                    else:
                        await _decline(client, "rejected by host")
                continue

            # SDP/ICE — only relayed between confirmed partners (post-approval).
            if client.partner is not None:
                try:
                    await client.partner.ws.send_text(data)
                except Exception as err:
                    logger.warning("relay failed: %s", err)
    except WebSocketDisconnect:
        logger.info("disconnect code=%s", client.code if client else "?")
    except Exception as err:
        logger.error("ws error: %s", err)
    finally:
        if client is not None:
            await _cleanup(client)
