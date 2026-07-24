-- RemoteDesk device registry + connection history (MariaDB / MySQL).
-- Created on server startup if absent (idempotent).

CREATE TABLE IF NOT EXISTS devices (
    device_uuid   CHAR(36) PRIMARY KEY,       -- generated + persisted on the device
    code          CHAR(12) NOT NULL,          -- server-assigned, public, shareable
    auth_token    TEXT NOT NULL,              -- secret; proves the device owns the code
    mac_address   TEXT,
    device_name   TEXT,
    os_info       TEXT,
    registered_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen     DATETIME(6) NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'active',  -- active | blocked
    UNIQUE KEY uq_devices_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS connection_history (
    id               BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    controller_code  CHAR(12) NOT NULL,       -- who initiated
    host_code        CHAR(12) NOT NULL,       -- who was connected to
    controller_name  TEXT,
    host_name        TEXT,
    connected_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    ended_at         DATETIME(6) NULL,
    status           VARCHAR(32) NULL         -- connected | ended | failed | declined
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fast lookups for the recent-connections list (involving either side).
-- CREATE INDEX IF NOT EXISTS requires MariaDB 10.5.2+ (or MySQL 8.0+ with equivalent).
CREATE INDEX IF NOT EXISTS idx_history_controller ON connection_history (controller_code, connected_at);
CREATE INDEX IF NOT EXISTS idx_history_host ON connection_history (host_code, connected_at);
