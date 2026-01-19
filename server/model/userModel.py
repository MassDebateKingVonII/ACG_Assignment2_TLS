from server.config.db import get_db

def create_user(username: str, password_hash: str, public_key_pem: str) -> bool:
    """Insert a new user into the database."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, public_key) VALUES (%s, %s, %s)",
                (username, password_hash, public_key_pem)
            )
        return True
    except Exception:
        return False
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