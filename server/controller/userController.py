from server.model.userModel import create_user, get_user_by_username
from server.utils.auth import hash_password, verify_password

def register_user(username: str, password: str, public_key_pem: str) -> bool:
    """
    Hash the password and store user information in DB.
    Returns True if registration succeeds, False otherwise.
    """
    pw_hash = hash_password(password)
    return create_user(username, pw_hash, public_key_pem)


def login_user(username: str, password: str) -> dict | None:
    """
    Verify username and password.
    Returns user dict if valid, else None.
    """
    user = get_user_by_username(username)
    if not user:
        return None
    if verify_password(password, user["password_hash"]):
        return user
    return None
