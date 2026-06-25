import sqlite3
import time
from pathlib import Path
from typing import Any

from .security import decrypt_secret, encrypt_secret, hash_password, mask_secret, new_session_token, verify_password


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "nms.db"
MAX_FAILED_LOGINS = 5
BAN_SECONDS = 15 * 60
SESSION_SECONDS = 8 * 60 * 60
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin@nms"


DEVICE_TYPES = [
    {"value": "router", "label": "Roteador"},
    {"value": "switch", "label": "Switch"},
    {"value": "bras_bng", "label": "BRAS/BNG"},
    {"value": "olt", "label": "OLT"},
    {"value": "firewall", "label": "Firewall"},
    {"value": "other", "label": "Outro"},
]


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT 'other',
                ssh_username TEXT NOT NULL DEFAULT '',
                ssh_password_encrypted TEXT NOT NULL DEFAULT '',
                ssh_port INTEGER NOT NULL DEFAULT 22,
                snmp_community_encrypted TEXT NOT NULL DEFAULT '',
                snmp_port INTEGER NOT NULL DEFAULT 161,
                model TEXT NOT NULL DEFAULT '',
                vrp_version TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS devices_updated_at
            AFTER UPDATE ON devices
            FOR EACH ROW
            BEGIN
                UPDATE devices SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS users_updated_at
            AFTER UPDATE ON users
            FOR EACH ROW
            BEGIN
                UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT PRIMARY KEY,
                failed_count INTEGER NOT NULL DEFAULT 0,
                banned_until REAL NOT NULL DEFAULT 0,
                last_failed_at REAL NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                interface_name TEXT NOT NULL DEFAULT '',
                commands_preview TEXT NOT NULL,
                executed INTEGER NOT NULL DEFAULT 0,
                source_ip TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(command_audit_logs)").fetchall()}
        if "source_ip" not in columns:
            conn.execute("ALTER TABLE command_audit_logs ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")


def _normalize_device_payload(payload: dict[str, Any]) -> dict[str, Any]:
    ssh_port = payload.get("ssh_port") or 22
    snmp_port = payload.get("snmp_port") or 161
    return {
        "name": (payload.get("name") or payload.get("host") or "").strip(),
        "host": (payload.get("host") or "").strip(),
        "description": (payload.get("description") or "").strip(),
        "device_type": payload.get("device_type") or "other",
        "ssh_username": (payload.get("ssh_username") or "").strip(),
        "ssh_password_encrypted": encrypt_secret(payload.get("ssh_password") or ""),
        "ssh_port": int(ssh_port),
        "snmp_community_encrypted": encrypt_secret(payload.get("snmp_community") or ""),
        "snmp_port": int(snmp_port),
        "model": (payload.get("model") or "").strip(),
        "vrp_version": (payload.get("vrp_version") or "").strip(),
        "notes": (payload.get("notes") or "").strip(),
    }


def _device_row_to_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "host": row["host"],
        "description": row["description"],
        "device_type": row["device_type"],
        "ssh_username": row["ssh_username"],
        "ssh_password_status": mask_secret(row["ssh_password_encrypted"]),
        "ssh_port": row["ssh_port"],
        "snmp_community_status": mask_secret(row["snmp_community_encrypted"]),
        "snmp_port": row["snmp_port"],
        "model": row["model"],
        "vrp_version": row["vrp_version"],
        "notes": row["notes"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_devices() -> list[dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM devices ORDER BY updated_at DESC, id DESC").fetchall()
    return [_device_row_to_public(row) for row in rows]


def get_device(device_id: int) -> dict[str, Any] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    return _device_row_to_public(row) if row else None


def get_device_private(device_id: int) -> dict[str, Any] | None:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        return None
    public = _device_row_to_public(row)
    public.update({
        "ssh_password": decrypt_secret(row["ssh_password_encrypted"]),
        "snmp_community": decrypt_secret(row["snmp_community_encrypted"]),
    })
    return public


def create_device(payload: dict[str, Any]) -> dict[str, Any]:
    init_db()
    data = _normalize_device_payload(payload)
    if not data["host"]:
        raise ValueError("host required")
    if not data["name"]:
        data["name"] = data["host"]

    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO devices (
                name, host, description, device_type, ssh_username,
                ssh_password_encrypted, ssh_port, snmp_community_encrypted,
                snmp_port, model, vrp_version, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["name"],
                data["host"],
                data["description"],
                data["device_type"],
                data["ssh_username"],
                data["ssh_password_encrypted"],
                data["ssh_port"],
                data["snmp_community_encrypted"],
                data["snmp_port"],
                data["model"],
                data["vrp_version"],
                data["notes"],
            ),
        )
        conn.commit()
        new_id = cur.lastrowid
    created = get_device(int(new_id))
    if created is None:
        raise RuntimeError("device creation failed")
    return created


def update_device(device_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    init_db()
    current = get_device(device_id)
    if not current:
        return None

    data = _normalize_device_payload(payload)
    if not data["host"]:
        raise ValueError("host required")
    if not data["name"]:
        data["name"] = data["host"]

    with get_connection() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        ssh_secret = data["ssh_password_encrypted"] or existing["ssh_password_encrypted"]
        snmp_secret = data["snmp_community_encrypted"] or existing["snmp_community_encrypted"]
        conn.execute(
            """
            UPDATE devices
            SET name = ?, host = ?, description = ?, device_type = ?,
                ssh_username = ?, ssh_password_encrypted = ?, ssh_port = ?,
                snmp_community_encrypted = ?, snmp_port = ?, model = ?,
                vrp_version = ?, notes = ?
            WHERE id = ?
            """,
            (
                data["name"],
                data["host"],
                data["description"],
                data["device_type"],
                data["ssh_username"],
                ssh_secret,
                data["ssh_port"],
                snmp_secret,
                data["snmp_port"],
                data["model"],
                data["vrp_version"],
                data["notes"],
                device_id,
            ),
        )
        conn.commit()
    return get_device(device_id)


def delete_device(device_id: int) -> bool:
    init_db()
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
    return cur.rowcount > 0


def users_exist() -> bool:
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()
    return bool(row and row["total"])


def create_initial_user(username: str, password: str) -> dict[str, Any]:
    init_db()
    if users_exist():
        raise ValueError("initial user already exists")
    username = username.strip().lower()
    if not username:
        raise ValueError("username required")
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), "admin"),
        )
        conn.commit()
        user_id = int(cur.lastrowid)
    return {"id": user_id, "username": username, "role": "admin"}


def ensure_default_admin() -> None:
    init_db()
    if users_exist():
        return
    create_initial_user(DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_PASSWORD)


def get_login_ban(ip: str) -> dict[str, Any]:
    init_db()
    now = time.time()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM login_attempts WHERE ip = ?", (ip,)).fetchone()
    if not row:
        return {"banned": False, "remaining_seconds": 0, "failed_count": 0}
    remaining = max(0, int(row["banned_until"] - now))
    return {
        "banned": remaining > 0,
        "remaining_seconds": remaining,
        "failed_count": row["failed_count"],
    }


def register_failed_login(ip: str) -> dict[str, Any]:
    init_db()
    now = time.time()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM login_attempts WHERE ip = ?", (ip,)).fetchone()
        failed_count = 1 if not row else int(row["failed_count"]) + 1
        banned_until = now + BAN_SECONDS if failed_count >= MAX_FAILED_LOGINS else 0
        conn.execute(
            """
            INSERT INTO login_attempts (ip, failed_count, banned_until, last_failed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                failed_count = excluded.failed_count,
                banned_until = excluded.banned_until,
                last_failed_at = excluded.last_failed_at
            """,
            (ip, failed_count, banned_until, now),
        )
        conn.commit()
    return get_login_ban(ip)


def reset_login_failures(ip: str) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
        conn.commit()


def authenticate_user(username: str, password: str, ip: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    init_db()
    ban = get_login_ban(ip)
    if ban["banned"]:
        return None, ban

    normalized = username.strip().lower()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (normalized,)).fetchone()

    if not row or not verify_password(password, row["password_hash"]):
        ban = register_failed_login(ip)
        return None, ban

    reset_login_failures(ip)
    return {"id": row["id"], "username": row["username"], "role": row["role"]}, {"banned": False, "remaining_seconds": 0}


def create_session(user_id: int) -> str:
    init_db()
    token = new_session_token()
    expires_at = time.time() + SESSION_SECONDS
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at),
        )
        conn.commit()
    return token


def get_session_user(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    init_db()
    now = time.time()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT users.id, users.username, users.role, sessions.expires_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] < now:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return None
    return {"id": row["id"], "username": row["username"], "role": row["role"]}


def delete_session(token: str | None) -> None:
    if not token:
        return
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def create_command_audit_log(
    *,
    user_id: int,
    device_id: int,
    action: str,
    interface_name: str,
    commands_preview: list[str],
    executed: bool = False,
    source_ip: str = "",
) -> None:
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO command_audit_logs (
                user_id, device_id, action, interface_name, commands_preview, executed, source_ip
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                device_id,
                action,
                interface_name,
                "\n".join(commands_preview),
                1 if executed else 0,
                source_ip,
            ),
        )
        conn.commit()


def list_command_audit_logs(
    limit: int = 30,
    device_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    init_db()
    safe_limit = max(1, min(int(limit), 100))
    where = []
    params: list[Any] = []
    if device_id:
        where.append("command_audit_logs.device_id = ?")
        params.append(device_id)
    if date_from:
        where.append("date(command_audit_logs.created_at) >= date(?)")
        params.append(date_from)
    if date_to:
        where.append("date(command_audit_logs.created_at) <= date(?)")
        params.append(date_to)
    where_sql = "WHERE " + " AND ".join(where) if where else ""
    with get_connection() as conn:
        rows = conn.execute(
            f"""
            SELECT
                command_audit_logs.id,
                command_audit_logs.action,
                command_audit_logs.interface_name,
                command_audit_logs.commands_preview,
                command_audit_logs.executed,
                command_audit_logs.source_ip,
                command_audit_logs.created_at,
                users.username,
                devices.name AS device_name,
                devices.host AS device_host
            FROM command_audit_logs
            JOIN users ON users.id = command_audit_logs.user_id
            JOIN devices ON devices.id = command_audit_logs.device_id
            {where_sql}
            ORDER BY command_audit_logs.id DESC
            LIMIT ?
            """,
            (*params, safe_limit),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "action": row["action"],
            "interface": row["interface_name"],
            "commands_preview": row["commands_preview"],
            "executed": bool(row["executed"]),
            "source_ip": row["source_ip"],
            "created_at": row["created_at"],
            "username": row["username"],
            "device_name": row["device_name"],
            "device_host": row["device_host"],
        }
        for row in rows
    ]


def _user_row_to_public(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_users() -> list[dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY username").fetchall()
    return [_user_row_to_public(row) for row in rows]


def create_user(payload: dict[str, Any]) -> dict[str, Any]:
    init_db()
    username = (payload.get("username") or "").strip().lower()
    password = payload.get("password") or ""
    role = payload.get("role") or "leitura"
    if role not in {"admin", "leitura"}:
        raise ValueError("invalid role")
    if not username or not password:
        raise ValueError("username and password required")
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _user_row_to_public(row)


def update_user(user_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    init_db()
    role = payload.get("role")
    password = payload.get("password") or ""
    if password and len(password) < 8:
        raise ValueError("password must have at least 8 characters")
    if role and role not in {"admin", "leitura"}:
        raise ValueError("invalid role")
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return None
        if role:
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if password:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), user_id))
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _user_row_to_public(row)


def delete_user(user_id: int) -> bool:
    init_db()
    with get_connection() as conn:
        total_admins = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'admin'").fetchone()["total"]
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return False
        if row["role"] == "admin" and total_admins <= 1:
            raise ValueError("cannot remove last admin")
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return cur.rowcount > 0
