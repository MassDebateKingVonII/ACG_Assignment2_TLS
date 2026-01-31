import os, json, base64

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from utils.socket_utils import send_resp, recv_all
from client.utils.CSR_utils import (
    generate_csr,
    KEY_FILE_PATH,
)

from client.utils.certificateValidation import (
    TRUSTED_ROOT_PATH
)

from utils.PKI_utils import (
    verify_cert_signed_by_root
)

CLIENT_CERT_PATH = os.path.join("client_path", "certificates")

def derive_passphrase(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())
        
def authenticate_client_gui(conn, action, username, password):
    # wait for AUTH
    auth_signal = recv_all(conn, 4)
    if auth_signal != b"AUTH":
        return False, "Protocol error"

    payload = {
        "action": action,   # "login" or "register"
        "username": username,
        "password": password
    }

    data = json.dumps(payload).encode()
    send_resp(conn, data)

    resp_len = int.from_bytes(recv_all(conn, 8), "big")
    resp = recv_all(conn, resp_len)

    if resp == b"LOGGED_IN":
        # We only accept "logged in" if we can successfully load salt + derive key.
        try:
            salt_file = os.path.join(KEY_FILE_PATH, f"salt_{username}.bin")
            if not os.path.exists(salt_file):
                raise FileNotFoundError("Salt file missing. Cannot derive key passphrase.")

            with open(salt_file, "rb") as f:
                salt = f.read()

            if not salt or len(salt) < 16:
                raise ValueError("Salt file invalid or corrupted.")

            key_passphrase = derive_passphrase(password, salt)

            # Only set these AFTER successful derivation
            conn.username = username
            conn.key_passphrase = key_passphrase

            return True, "OK"

        except Exception as e:
            # Ensure client-side state is NOT marked as logged in
            if hasattr(conn, "username"):
                conn.username = None
            if hasattr(conn, "key_passphrase"):
                conn.key_passphrase = None

            # Best effort: tell server to logout this session so the server doesn't
            # keep an authenticated connection alive while the client can't proceed.
            try:
                conn.send(b"LOGO")
                resp_len = int.from_bytes(recv_all(conn, 8), "big")
                _ = recv_all(conn, resp_len)
            except:
                pass

            # Also safest: close the connection so any server-side auth context is gone
            try:
                conn.close()
            except:
                pass

            return False, f"Login blocked: cannot unlock keys ({str(e)})"

    if resp == b"REGISTERING":
        # CSR flow with encrypted private key
        salt = os.urandom(16)
        key_passphrase = derive_passphrase(password, salt)
        csr_pem, key_pem = generate_csr(username, key_passphrase)
        
        # Save Salt
        os.makedirs(KEY_FILE_PATH, exist_ok=True)
        salt_file = os.path.join(KEY_FILE_PATH, f"salt_{username}.bin")
        with open(salt_file, "wb") as f:
            f.write(salt)
            
        # Save encrypted private key
        key_file = os.path.join(KEY_FILE_PATH, f"{username}_key.pem")
        with open(key_file, "wb") as f:
            f.write(key_pem)

        # CSR payload
        csr_payload = {
            "action": "submit_csr",
            "username": username,
            "csr": base64.b64encode(csr_pem).decode()
        }

        csr_bytes = json.dumps(csr_payload).encode()
        send_resp(conn, csr_bytes)

        # Receive signed certificate
        cert_len = int.from_bytes(recv_all(conn, 8), "big")
        signed_cert = recv_all(conn, cert_len)

        with open(TRUSTED_ROOT_PATH, "rb") as f:
            root_pem = f.read()

        if verify_cert_signed_by_root(signed_cert, root_pem):
            cert_file = os.path.join(CLIENT_CERT_PATH, f"{username}_cert.pem")
            with open(cert_file, "wb") as f:
                f.write(signed_cert)
            return False, "Registered successfully. Please login."

        return False, "Certificate verification failed"

    if resp == b"LOGIN_FAILED":
        return False, "Login failed"

    if resp == b"REG_FAILED":
        # Try to read feedback payload
        try:
            fb_len_bytes = recv_all(conn, 8)
            if fb_len_bytes:
                fb_len = int.from_bytes(fb_len_bytes, "big")
                fb_data = recv_all(conn, fb_len)
                feedback = json.loads(fb_data.decode("utf-8"))

                warning = feedback.get("warning", "")
                suggestions = feedback.get("suggestions", [])
                error = feedback.get("error", "")

                msg = "Registration failed."
                
                if warning:
                    msg += f"\n\n{warning}"
                if suggestions:
                    msg += "\n" + "\n".join(f"- {s}" for s in suggestions)
                if error:
                    msg += f"\n\n{error}"

                return False, msg
        except Exception:
            pass

        return False, "Registration failed"

    return False, "Unknown server response"