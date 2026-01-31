import base64, json, os
from server.config.db import get_db
from server.utils.envelopeEncryption import encrypt_file_at_rest, decrypt_file_at_rest

SAVE_DIR = os.path.join('server_path', 'save')
os.makedirs(SAVE_DIR, exist_ok=True)

def store_file(filename: str, plaintext_bytes: bytes, signature: bytes, user_id: int):
    
    if file_exists(filename):
        delete_file_record(filename)
        
    # Encrypt file at rest (returns AES dict with ciphertext, nonce, tag)
    enc_data = encrypt_file_at_rest(plaintext_bytes)

    # Save the encrypted file to disk (binary)
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(base64.b64decode(enc_data["file"]["ciphertext"]))

    # Base64 encode signature for storage
    signature_b64 = base64.b64encode(signature).decode()

    # Save only metadata and encrypted DEK to database
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO encrypted_files
                (filename, uploaded_by_id, file_nonce, file_tag, file_signature, enc_dek, kek_salt)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                filename,
                user_id,
                enc_data["file"]["nonce"],         # Store nonce
                enc_data["file"]["tag"],           # Stores the GMAC tag
                signature_b64,                     # File signature created by server file signing key
                json.dumps(enc_data["enc_dek"]),   # The encrypted DEK dictionary contain nonce, tag and ciphertext
                enc_data["kek_salt"]               # The salt used to derive the KEK via the MEK through PBKDF2HMAC
            ))
    finally:
        db.close()
     
def list_files():
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT f.filename, u.username AS uploaded_by, f.created_at
                FROM encrypted_files f
                INNER JOIN users u ON f.uploaded_by_id = u.id
                ORDER BY f.created_at DESC
            """)
            rows = cur.fetchall()
            return rows
    finally:
        db.close()


def load_file(filename: str) -> tuple[bytes, str] | None:
    db = get_db()
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT * FROM encrypted_files WHERE filename=%s", (filename,))
            row = cur.fetchone()
    finally:
        db.close()

    if not row:
        return None

    # Load ciphertext from disk
    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    if not os.path.exists(enc_path):
        return None

    with open(enc_path, "rb") as f:
        ciphertext_bytes = f.read()

    # Reconstruct AES dict
    enc_file_dict = {
        "ciphertext": base64.b64encode(ciphertext_bytes).decode(),
        "nonce": row["file_nonce"],
        "tag": row["file_tag"]
    }

    record = {
        "file": enc_file_dict,
        "enc_dek": json.loads(row["enc_dek"]),
        "kek_salt": row["kek_salt"]
    }

    plaintext_bytes = decrypt_file_at_rest(record)
    file_signature = row["file_signature"]
    return plaintext_bytes, file_signature

def file_exists(filename: str) -> bool:
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT 1 FROM encrypted_files WHERE filename=%s", (filename,))
            return cur.fetchone() is not None
    finally:
        db.close()
        
def delete_file_record(filename: str):
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM encrypted_files WHERE filename=%s", (filename,))
    finally:
        db.close()

    enc_path = os.path.join(SAVE_DIR, filename + ".enc")
    if os.path.exists(enc_path):
        os.remove(enc_path)

def get_all_records():
    db = get_db()
    try:
        with db.cursor(dictionary=True) as cur:
            cur.execute("SELECT id, enc_dek, kek_salt FROM encrypted_files")
            return cur.fetchall()
    finally:
        db.close()

def update_record_dek(record_id: int, enc_dek: dict):
    """
    enc_dek: AES dict (ciphertext, nonce, tag)
    """
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                "UPDATE encrypted_files SET enc_dek=%s WHERE id=%s",
                (json.dumps(enc_dek), record_id)
            )
    finally:
        db.close()