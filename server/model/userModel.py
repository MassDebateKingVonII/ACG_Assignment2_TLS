from server.config.db import get_db

def create_user(username: str, password_hash: str, cert_path: str) -> bool:
    """Insert a new user into the database."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, cert_path) VALUES (%s, %s, %s)",
                (username, password_hash, cert_path)
            )
        return True
    except Exception:
        return False
    finally:
        db.close()

def get_user_by_user_id(user_id: int) -> dict | None:
    """Fetch a user record by user id."""
    db = get_db()
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()
    finally:
        db.close()

def get_user_by_username(username: str) -> dict | None:
    """Fetch a user record by username."""
    db = get_db()
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()
    finally:
        db.close()
        
def check_user_by_username(username: str) -> bool:
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE username=%s LIMIT 1", (username,))
            return cur.fetchone() is not None
    finally:
        db.close()