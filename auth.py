import os
import sqlite3
import bcrypt
import re
import pyotp
from contextlib import contextmanager

import config # Make sure to use the config for DB path

# --- New, More Robust Database Connection Class ---
class DatabaseConnection:
    def __init__(self, commit=False):
        self.commit = commit
        self.conn = None
        self.cur = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(config.DB_PATH, timeout=10)
        self.cur = self.conn.cursor()
        return self.cur
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if self.commit and exc_type is None: # Only commit if no errors
                self.conn.commit()
            self.conn.close()

# --- The rest of the file is updated to use the new class ---

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
ALLOWED_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "protonmail.com"
}

def _ensure_users_schema():
    with DatabaseConnection(commit=True) as cur:
        try:
            cur.execute("PRAGMA table_info(users)")
            columns = [col[1] for col in cur.fetchall()]
            if 'mfa_secret' not in columns:
                cur.execute("ALTER TABLE users ADD COLUMN mfa_secret TEXT")
        except sqlite3.OperationalError:
            pass
_ensure_users_schema()

def is_valid_email(email: str) -> bool:
    if not EMAIL_REGEX.match(email): return False
    domain = email.split("@", 1)[1].lower()
    return domain in ALLOWED_DOMAINS

def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 8: return False, "Password must be at least 8 characters."
    if not re.search(r'[a-z]', password): return False, "Password must contain a lowercase letter."
    if not re.search(r'[0-9]', password): return False, "Password must contain a number."
    if not re.search(r'[^A-Za-z0-9]', password): return False, "Password must contain a special character."
    return True, "Password is valid."

def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        with DatabaseConnection(commit=True) as cur:
            cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, hashed))
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        return False, "Username or Email already exists"

def user_exists(email: str) -> bool:
    with DatabaseConnection() as cur:
        cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        return cur.fetchone() is not None

def verify_user(username: str, password: str) -> tuple[bool, str]:
    with DatabaseConnection() as cur:
        cur.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    if row and bcrypt.checkpw(password.encode('utf-8'), row[0]):
        return True, "Login successful"
    return False, "Invalid credentials"

def get_user_id(username: str) -> int | None:
    with DatabaseConnection() as cur:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        record = cur.fetchone()
    return record[0] if record else None

def is_admin(username: str) -> bool:
    return get_user_id(username) == 1

def update_password(email: str, new_password: str) -> None:
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    with DatabaseConnection(commit=True) as cur:
        cur.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, email))

def change_password(username: str, old_password: str, new_password: str) -> tuple[bool, str]:
    if old_password == new_password: return False, "New password cannot be the same as the old password."
    is_valid, _ = verify_user(username, old_password)
    if not is_valid: return False, "Incorrect current password."
    is_strong, msg = validate_password(new_password)
    if not is_strong: return False, msg
    new_hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    with DatabaseConnection(commit=True) as cur:
        cur.execute("UPDATE users SET password = ? WHERE username = ?", (new_hashed, username))
    log_event(username, "change_password")
    return True, "Password changed successfully."

def get_username_by_email(email: str) -> str | None:
    with DatabaseConnection() as cur:
        cur.execute("SELECT username FROM users WHERE email = ?", (email,))
        record = cur.fetchone()
    return record[0] if record else None

def delete_user_account(username: str, password: str, mfa_code: str) -> tuple[bool, str]:
    ok, _ = verify_user(username, password)
    if not ok: return False, "Invalid password."
    secret = get_user_mfa_secret(username)
    if not secret: return False, "MFA is not configured for this user."
    pad = (8 - len(secret) % 8) % 8
    totp = pyotp.TOTP(secret + "=" * pad)
    if not totp.verify(mfa_code): return False, "Invalid MFA code."
    try:
        user_id = get_user_id(username)
        if not user_id: return False, "User not found."
        with DatabaseConnection(commit=True) as cur:
            cur.execute("SELECT path FROM files WHERE user_id = ?", (user_id,))
            paths_to_delete = [row[0] for row in cur.fetchall()]
            cur.execute("DELETE FROM files WHERE user_id = ?", (user_id,))
            cur.execute("DELETE FROM audit_logs WHERE username = ?", (username,))
            cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        for path in paths_to_delete:
            if os.path.exists(path):
                os.remove(path)
        return True, "Account deleted successfully."
    except Exception as e:
        return False, f"An error occurred: {e}"

def generate_mfa_secret(username: str) -> str:
    secret = pyotp.random_base32()
    with DatabaseConnection(commit=True) as cur:
        cur.execute("UPDATE users SET mfa_secret = ? WHERE username = ?", (secret, username))
    return secret

def get_user_mfa_secret(username: str) -> str | None:
    with DatabaseConnection() as cur:
        cur.execute("SELECT mfa_secret FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    return row[0] if row and row[0] else None

def log_event(username: str, action: str, details: str = ""):
    with DatabaseConnection(commit=True) as cur:
        log_event_with_cursor(cur, username, action, details)

def log_event_with_cursor(cur: sqlite3.Cursor, username: str, action: str, details: str = ""):
    cur.execute("INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)", (username, action, details))

def get_audit_logs(username: str) -> list:
    with DatabaseConnection() as cur:
        cur.execute("SELECT action, details, timestamp FROM audit_logs WHERE username = ? ORDER BY timestamp DESC", (username,))
        return cur.fetchall()

def get_user_files(username: str) -> list:
    user_id = get_user_id(username)
    if not user_id: return []
    with DatabaseConnection() as cur:
        cur.execute("SELECT id, filename, path, salt, size_kb, date_added FROM files WHERE user_id = ?", (user_id,))
        return cur.fetchall()

def file_exists(username: str, filename: str) -> bool:
    files = get_user_files(username)
    return any(f[1] == filename for f in files)

def delete_file_record_by_name(username: str, filename: str) -> None:
    user_id = get_user_id(username)
    if not user_id: return
    with DatabaseConnection(commit=True) as cur:
        cur.execute("SELECT id, path FROM files WHERE user_id = ? AND filename = ?", (user_id, filename))
        record = cur.fetchone()
        if record:
            file_id, file_path = record
            if os.path.exists(file_path):
                os.remove(file_path)
            cur.execute("DELETE FROM files WHERE id = ?", (file_id,))