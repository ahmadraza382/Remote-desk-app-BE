"""MariaDB / MySQL data-access layer (aiomysql).

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
from urllib.parse import unquote, urlparse

import aiomysql
import pymysql.err

CODE_LENGTH = 12
CODE_ALLOC_RETRIES = 10
SCHEMA_PATH = Path(__file__).with_name("schema.sql")
# MySQL / MariaDB duplicate-key error (UNIQUE / PRIMARY).
_MYSQL_DUPLICATE_ENTRY = 1062

_pool: aiomysql.Pool | None = None


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


def _pool_or_raise() -> aiomysql.Pool:
    if _pool is None:
        raise RuntimeError("database pool not initialized")
    return _pool


def _database_url() -> str:
    """Read DATABASE_URL (loaded from signaling/.env). Fail fast if it is missing."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Create signaling/.env (copy signaling/.env.example) "
            "and set DATABASE_URL=mysql://user:<password>@localhost:3306/remotedesk"
        )
    return url


def _parse_database_url(url: str) -> dict:
    """Parse mysql:// or mariadb:// URLs into aiomysql.create_pool kwargs."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("mysql", "mariadb"):
        raise RuntimeError(
            f"DATABASE_URL must use mysql:// or mariadb:// (got scheme={scheme!r}). "
            "Example: mysql://root:password@localhost:3306/remotedesk"
        )
    if not parsed.path or parsed.path == "/":
        raise RuntimeError(
            "DATABASE_URL is missing the database name "
            "(e.g. mysql://root:password@localhost:3306/remotedesk)"
        )
    db = parsed.path.lstrip("/").split("?")[0]
    if not db:
        raise RuntimeError("DATABASE_URL is missing the database name")
    return {
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 3306,
        "user": unquote(parsed.username) if parsed.username else "root",
        "password": unquote(parsed.password) if parsed.password else "",
        "db": db,
    }


async def init_db() -> None:
    """Create the connection pool and ensure the schema exists."""
    global _pool
    cfg = _parse_database_url(_database_url())
    _pool = await aiomysql.create_pool(
        host=cfg["host"],
        port=cfg["port"],
        user=cfg["user"],
        password=cfg["password"],
        db=cfg["db"],
        minsize=1,
        maxsize=10,
        autocommit=True,
        charset="utf8mb4",
        cursorclass=aiomysql.DictCursor,
    )
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    statements = [
        s.strip()
        for s in schema.split(";")
        if s.strip() and not all(line.strip().startswith("--") or not line.strip() for line in s.splitlines())
    ]
    async with _pool.acquire() as conn:
        async with conn.cursor() as cur:
            for statement in statements:
                # Strip leading comment-only lines so executors get pure SQL.
                lines = [
                    line
                    for line in statement.splitlines()
                    if line.strip() and not line.strip().startswith("--")
                ]
                sql = "\n".join(lines).strip()
                if sql:
                    await cur.execute(sql)


async def close_db() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        await _pool.wait_closed()
        _pool = None


def _generate_code() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(CODE_LENGTH))


async def register_device(uuid: str, mac: str, name: str, os_info: str) -> tuple[str, str]:
    """Idempotent by device_uuid. Returns (code, auth_token)."""
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT code, auth_token, status FROM devices WHERE device_uuid = %s",
                (uuid,),
            )
            existing = await cur.fetchone()
            if existing is not None:
                if existing["status"] != "active":
                    raise DeviceBlocked()
                await cur.execute(
                    """UPDATE devices
                       SET mac_address = %s, device_name = %s, os_info = %s,
                           last_seen = UTC_TIMESTAMP(6)
                       WHERE device_uuid = %s""",
                    (mac, name, os_info, uuid),
                )
                return existing["code"], existing["auth_token"]

            token = secrets.token_urlsafe(32)
            for _ in range(CODE_ALLOC_RETRIES):
                code = _generate_code()
                try:
                    await cur.execute(
                        """INSERT INTO devices
                           (device_uuid, code, auth_token, mac_address, device_name, os_info, last_seen)
                           VALUES (%s, %s, %s, %s, %s, %s, UTC_TIMESTAMP(6))""",
                        (uuid, code, token, mac, name, os_info),
                    )
                    return code, token
                except pymysql.err.IntegrityError as e:
                    # 1062 = duplicate entry (code collision — extremely rare)
                    if e.args and e.args[0] == _MYSQL_DUPLICATE_ENTRY:
                        continue
                    raise
            raise RuntimeError("could not allocate a unique device code")


async def get_device_by_code(code: str) -> Device | None:
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT device_uuid, code, auth_token, device_name, status FROM devices WHERE code = %s",
                (code,),
            )
            row = await cur.fetchone()
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
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE devices SET last_seen = UTC_TIMESTAMP(6) WHERE code = %s",
                (code,),
            )


async def log_connection(
    controller_code: str, host_code: str, controller_name: str | None, host_name: str | None
) -> int:
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """INSERT INTO connection_history
                   (controller_code, host_code, controller_name, host_name, status)
                   VALUES (%s, %s, %s, %s, 'connected')""",
                (controller_code, host_code, controller_name, host_name),
            )
            history_id = cur.lastrowid
            if history_id is None:
                raise RuntimeError("INSERT into connection_history did not return an id")
            return int(history_id)


async def end_connection(history_id: int) -> None:
    """Idempotent: only sets ended_at the first time."""
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """UPDATE connection_history
                   SET ended_at = UTC_TIMESTAMP(6), status = 'ended'
                   WHERE id = %s AND ended_at IS NULL""",
                (history_id,),
            )


async def log_failed(controller_code: str, host_code: str) -> None:
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """INSERT INTO connection_history (controller_code, host_code, status)
                   VALUES (%s, %s, 'failed')""",
                (controller_code, host_code),
            )


async def log_declined(
    controller_code: str, host_code: str, controller_name: str | None, host_name: str | None
) -> None:
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """INSERT INTO connection_history
                   (controller_code, host_code, controller_name, host_name, status, ended_at)
                   VALUES (%s, %s, %s, %s, 'declined', UTC_TIMESTAMP(6))""",
                (controller_code, host_code, controller_name, host_name),
            )


async def set_device_status(code: str, status: str) -> None:
    """Admin: block ('blocked') or unblock ('active') a device by code."""
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE devices SET status = %s WHERE code = %s",
                (status, code),
            )


async def recent_connections(code: str, limit: int) -> list[HistoryRow]:
    pool = _pool_or_raise()
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """SELECT controller_code, host_code, controller_name, host_name, connected_at, status
                   FROM connection_history
                   WHERE controller_code = %s OR host_code = %s
                   ORDER BY connected_at DESC
                   LIMIT %s""",
                (code, code, limit),
            )
            rows = await cur.fetchall()
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
