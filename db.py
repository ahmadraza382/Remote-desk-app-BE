"""PostgreSQL data-access layer (asyncpg).

A thin repository — all SQL lives here, never scattered through the request handlers.
Every query is async and the public functions raise on real errors so callers can
decide how to handle them (the WS/HTTP layer wraps them in try/except).
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import asyncpg

CODE_LENGTH = 12
CODE_ALLOC_RETRIES = 10
SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_pool: asyncpg.Pool | None = None


class DeviceBlocked(Exception):
    """Raised when a blocked device attempts to (re)register."""


@dataclass
class Device:
    device_uuid: str
    code: str
    auth_token: str
    device_name: str | None
    status: str


@dataclass
class HistoryRow:
    controller_code: str
    host_code: str
    controller_name: str | None
    host_name: str | None
    connected_at: datetime
    status: str | None


def _pool_or_raise() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("database pool not initialized")
    return _pool


def _database_url() -> str:
    """Read DATABASE_URL (loaded from signaling/.env). Fail fast if it is missing."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Create signaling/.env (copy signaling/.env.example) "
            "and set DATABASE_URL=postgresql://postgres:<password>@localhost:5432/remotedesk"
        )
    return url


async def init_db() -> None:
    """Create the connection pool and ensure the schema exists."""
    global _pool
    _pool = await asyncpg.create_pool(_database_url(), min_size=1, max_size=10)
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    async with _pool.acquire() as conn:
        await conn.execute(schema)


async def close_db() -> None:
    if _pool is not None:
        await _pool.close()


def _generate_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(CODE_LENGTH))


async def register_device(uuid: str, mac: str, name: str, os_info: str) -> tuple[str, str]:
    """Idempotent by device_uuid. Returns (code, auth_token)."""
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT code, auth_token, status FROM devices WHERE device_uuid = $1", uuid
        )
        if existing is not None:
            if existing["status"] != "active":
                raise DeviceBlocked()
            await conn.execute(
                """UPDATE devices
                   SET mac_address = $2, device_name = $3, os_info = $4, last_seen = now()
                   WHERE device_uuid = $1""",
                uuid,
                mac,
                name,
                os_info,
            )
            return existing["code"], existing["auth_token"]

        token = secrets.token_urlsafe(32)
        for _ in range(CODE_ALLOC_RETRIES):
            code = _generate_code()
            try:
                await conn.execute(
                    """INSERT INTO devices
                       (device_uuid, code, auth_token, mac_address, device_name, os_info, last_seen)
                       VALUES ($1, $2, $3, $4, $5, $6, now())""",
                    uuid,
                    code,
                    token,
                    mac,
                    name,
                    os_info,
                )
                return code, token
            except asyncpg.UniqueViolationError:
                continue  # extremely unlikely code collision; try another
        raise RuntimeError("could not allocate a unique device code")


async def get_device_by_code(code: str) -> Device | None:
    pool = _pool_or_raise()
    row = await pool.fetchrow(
        "SELECT device_uuid, code, auth_token, device_name, status FROM devices WHERE code = $1",
        code,
    )
    if row is None:
        return None
    return Device(
        device_uuid=str(row["device_uuid"]),
        code=row["code"],
        auth_token=row["auth_token"],
        device_name=row["device_name"],
        status=row["status"],
    )


async def touch_last_seen(code: str) -> None:
    pool = _pool_or_raise()
    await pool.execute("UPDATE devices SET last_seen = now() WHERE code = $1", code)


async def log_connection(
    controller_code: str, host_code: str, controller_name: str | None, host_name: str | None
) -> int:
    pool = _pool_or_raise()
    return await pool.fetchval(
        """INSERT INTO connection_history
           (controller_code, host_code, controller_name, host_name, status)
           VALUES ($1, $2, $3, $4, 'connected') RETURNING id""",
        controller_code,
        host_code,
        controller_name,
        host_name,
    )


async def end_connection(history_id: int) -> None:
    """Idempotent: only sets ended_at the first time."""
    pool = _pool_or_raise()
    await pool.execute(
        """UPDATE connection_history
           SET ended_at = now(), status = 'ended'
           WHERE id = $1 AND ended_at IS NULL""",
        history_id,
    )


async def log_failed(controller_code: str, host_code: str) -> None:
    pool = _pool_or_raise()
    await pool.execute(
        """INSERT INTO connection_history (controller_code, host_code, status)
           VALUES ($1, $2, 'failed')""",
        controller_code,
        host_code,
    )


async def log_declined(
    controller_code: str, host_code: str, controller_name: str | None, host_name: str | None
) -> None:
    pool = _pool_or_raise()
    await pool.execute(
        """INSERT INTO connection_history
           (controller_code, host_code, controller_name, host_name, status, ended_at)
           VALUES ($1, $2, $3, $4, 'declined', now())""",
        controller_code,
        host_code,
        controller_name,
        host_name,
    )


async def set_device_status(code: str, status: str) -> None:
    """Admin: block ('blocked') or unblock ('active') a device by code."""
    pool = _pool_or_raise()
    await pool.execute("UPDATE devices SET status = $2 WHERE code = $1", code, status)


async def recent_connections(code: str, limit: int) -> list[HistoryRow]:
    pool = _pool_or_raise()
    rows = await pool.fetch(
        """SELECT controller_code, host_code, controller_name, host_name, connected_at, status
           FROM connection_history
           WHERE controller_code = $1 OR host_code = $1
           ORDER BY connected_at DESC
           LIMIT $2""",
        code,
        limit,
    )
    return [
        HistoryRow(
            controller_code=r["controller_code"],
            host_code=r["host_code"],
            controller_name=r["controller_name"],
            host_name=r["host_name"],
            connected_at=r["connected_at"],
            status=r["status"],
        )
        for r in rows
    ]
