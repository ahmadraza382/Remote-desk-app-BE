-- RemoteDesk device registry + connection history (PostgreSQL).
-- Created on server startup if absent (idempotent).

CREATE TABLE IF NOT EXISTS devices (
    device_uuid   UUID PRIMARY KEY,           -- generated + persisted on the device
    code          CHAR(12) UNIQUE NOT NULL,   -- server-assigned, public, shareable
    auth_token    TEXT NOT NULL,              -- secret; proves the device owns the code
    mac_address   TEXT,
    device_name   TEXT,
    os_info       TEXT,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ,
    status        TEXT NOT NULL DEFAULT 'active'  -- active | blocked
);

CREATE TABLE IF NOT EXISTS connection_history (
    id               BIGSERIAL PRIMARY KEY,
    controller_code  CHAR(12) NOT NULL,        -- who initiated
    host_code        CHAR(12) NOT NULL,        -- who was connected to
    controller_name  TEXT,
    host_name        TEXT,
    connected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at         TIMESTAMPTZ,
    status           TEXT                       -- connected | ended | failed
);

-- Fast lookups for the recent-connections list (involving either side).
CREATE INDEX IF NOT EXISTS idx_history_controller ON connection_history (controller_code, connected_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_host ON connection_history (host_code, connected_at DESC);
