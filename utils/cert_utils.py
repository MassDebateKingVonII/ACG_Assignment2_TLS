from cryptography.hazmat.primitives import serialization
from cryptography import x509

def load_private_key(path: str, passphrase=None):
    """
    Load a PEM-encoded private key from disk.

    :param path: Path to the key file
    :param passphrase: Passphrase for encrypted key, if any (can be str or bytes)
    :return: private key object
    """
    with open(path, "rb") as f:
        key_bytes = f.read()

    if passphrase:
        # If passphrase is string, encode it to bytes
        if isinstance(passphrase, str):
            password = passphrase.encode()
        else:
            # Already bytes
            password = passphrase
    else:
        password = None

    return serialization.load_pem_private_key(
        key_bytes,
        password=password
    )

def load_certificate(path: str):
    """
    Load a PEM-encoded certificate from disk.

    :param path: Path to the certificate file
    :return: certificate object
    """
    with open(path, "rb") as f:
        cert_bytes = f.read()

    return x509.load_pem_x509_certificate(cert_bytes)