from server.model.userModel import (
    create_user, 
    get_user_by_username, 
    check_user_by_username,
    get_user_by_user_id
)

from server.utils.auth import hash_password, verify_password

def register_user(username: str, password: str, cert_path: str) -> bool:
    """
    Hash the password and store user information in DB.
    Returns True if registration succeeds, False otherwise.
    """
    pw_hash = hash_password(password)
    return create_user(username, pw_hash, cert_path)


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


def check_user_exists(username: str):
    """
    Verify username is unique by checking the database if exists.
    Returns true if users exists, returns false if unique.
    """
    exists = check_user_by_username(username)
    return exists

def get_user_pubkey(id : int):
    """
    Gets the public key (certificate) of the user by id
    """
    user = get_user_by_user_id(id)
    cert_path = user["cert_path"]
    return cert_path